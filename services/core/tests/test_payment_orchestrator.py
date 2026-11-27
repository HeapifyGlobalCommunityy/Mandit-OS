"""Unit and integration tests for Payment Orchestrator engine (Milestone 3).

Verifies card/UPI execution, idempotency, TOCTOU checkout validation, decision gating,
spend reservation commit/release, PSP timeouts, event emission, and error handling.
Per docs/modules/04-policy-and-payments.md §8 and docs/REFERENCE.md §9.4, §12.5.
"""

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from mandit.common import events
from mandit.common.models import Base
from mandit.payments.models import (
    IdempotencyKeyModel,
    PaymentModel,
    PspWebhookEventModel,
)
from mandit.payments.psp_client import (
    PspAuthorizeCardResponse,
    PspCaptureCardResponse,
    PspCreateScopedCredentialResponse,
    PspCreateUpiIntentResponse,
    PspPaymentStatusResponse,
    PspTimeoutError,
)
from mandit.payments.schemas import (
    PaymentRail,
    PaymentStatus,
)
from mandit.payments.service import (
    CheckoutChangedError,
    DecisionExpiredError,
    DecisionNotAllowError,
    DecisionNotFoundError,
    IdempotencyConflictError,
    PaymentAlreadyExistsError,
    PaymentError,
    PaymentOrchestratorImpl,
    SpendReservationError,
)
from mandit.policy.models import DecisionModel
from mandit.tokens.models import PaymentTokenModel
from mandit.tokens.schemas import (
    IssuedToken,
    PaymentToken,
    TokenErrorCode,
    TokenStatus,
)
from mandit.tokens.service import TokenIssueError

# --- Test Doubles ---


class MockDecision:
    def __init__(
        self,
        decision_id: str = "dec_test_001",
        proposal_id: str = "prop_test_001",
        outcome: str = "ALLOW",
        expires_at: datetime | None = None,
        transaction_id: str = "txn_test_001",
        mandate_id: str = "man_test_001",
    ) -> None:
        self.decision_id = decision_id
        self.proposal_id = proposal_id
        self.outcome = outcome
        self.expires_at = expires_at or (datetime.now(UTC) + timedelta(minutes=15))
        self.transaction_id = transaction_id
        self.mandate_id = mandate_id


class MockProposal:
    def __init__(
        self,
        proposal_id: str = "prop_test_001",
        agent_id: str = "agent_01",
        mandate_id: str = "man_test_001",
        checkout_id: str = "co_test_001",
        checkout_hash: str = "sha256:checkout_hash_abc",
        merchant_id: str = "mer_croma",
        payee_id: str = "acq_croma_001",
        amount_minor: int = 500000,
        currency: str = "INR",
        rail: str = "CARD",
        transaction_id: str = "txn_test_001",
    ) -> None:
        self.proposal_id = proposal_id
        self.agent_id = agent_id
        self.mandate_id = mandate_id
        self.checkout_id = checkout_id
        self.checkout_hash = checkout_hash
        self.merchant_id = merchant_id
        self.payee_id = payee_id
        self.amount_minor = amount_minor
        self.currency = currency
        self.rail = rail
        self.transaction_id = transaction_id


class MockCheckout:
    def __init__(
        self,
        checkout_id: str = "co_test_001",
        checkout_hash: str = "sha256:checkout_hash_abc",
        merchant_id: str = "mer_croma",
        payee_id: str = "acq_croma_001",
        amount_minor: int = 500000,
        currency: str = "INR",
    ) -> None:
        self.checkout_id = checkout_id
        self.checkout_hash = checkout_hash
        self.merchant_id = merchant_id
        self.payee_id = payee_id
        self.amount_minor = amount_minor
        self.currency = currency


class MockDecisionProvider:
    def __init__(self, decision: MockDecision | None = None) -> None:
        self.decision = decision or MockDecision()

    async def get(self, decision_id: str, session: Any = None) -> Any:
        return self.decision

    async def get_latest_for_proposal(self, proposal_id: str, session: Any = None) -> Any:
        if self.decision and self.decision.proposal_id == proposal_id:
            return self.decision
        return None


class MockMandateClient:
    def __init__(
        self,
        reservation_id: str = "res_test_001",
        usable: bool = True,
        fail_reserve: bool = False,
    ) -> None:
        self.reservation_id = reservation_id
        self.usable = usable
        self.fail_reserve = fail_reserve
        self.committed_reservations: list[str] = []
        self.released_reservations: list[str] = []

    async def reserve_spend(
        self,
        mandate_id: str,
        proposal_id: str,
        amount_minor: int,
        currency: str,
        session: Any = None,
    ) -> Any:
        if self.fail_reserve:
            raise Exception("Mandate spend reservation failed: OVER_TOTAL_CAP")
        return {
            "reservation_id": self.reservation_id,
            "mandate_id": mandate_id,
            "proposal_id": proposal_id,
            "amount_minor": amount_minor,
            "currency": currency,
            "status": "RESERVED",
        }

    async def commit_spend(self, reservation_id: str, session: Any = None) -> Any:
        self.committed_reservations.append(reservation_id)
        return {"reservation_id": reservation_id, "status": "COMMITTED"}

    async def release_spend(self, reservation_id: str, session: Any = None) -> Any:
        self.released_reservations.append(reservation_id)
        return {"reservation_id": reservation_id, "status": "RELEASED"}

    async def assert_usable(self, mandate_id: str, session: Any = None) -> Any:
        if not self.usable:
            return None
        return {"mandate_id": mandate_id, "status": "ACTIVE"}


class MockGroundingClient:
    def __init__(
        self,
        proposal: MockProposal | None = None,
        checkout: MockCheckout | None = None,
    ) -> None:
        self.proposal = proposal or MockProposal()
        self.checkout = checkout or MockCheckout()
        self.completed_checkouts: list[tuple[str, str]] = []

    async def get_proposal(self, proposal_id: str, session: Any = None) -> Any:
        if self.proposal and self.proposal.proposal_id == proposal_id:
            return self.proposal
        return None

    async def refetch_checkout(self, checkout_id: str, session: Any = None) -> Any:
        if self.checkout and self.checkout.checkout_id == checkout_id:
            return self.checkout
        return None

    async def complete_checkout(
        self, checkout_id: str, psp_payment_id: str, session: Any = None
    ) -> Any:
        self.completed_checkouts.append((checkout_id, psp_payment_id))
        return {"checkout_id": checkout_id, "status": "COMPLETED"}


class MockTokenService:
    def __init__(self, fail_issue: bool = False) -> None:
        self.fail_issue = fail_issue
        self.issued_tokens: list[str] = []
        self.redeemed_tokens: list[str] = []
        self.failed_tokens: list[str] = []

    async def issue(
        self, decision_id: str, reservation_id: str, session: Any = None
    ) -> IssuedToken:
        if self.fail_issue:
            raise TokenIssueError(
                TokenErrorCode.DECISION_NOT_ALLOW,
                "Token issuance refused",
                status_code=400,
            )
        now = datetime.now(UTC)
        token_id = f"ptok_{uuid.uuid4().hex[:8]}"
        self.issued_tokens.append(token_id)
        record = PaymentToken(
            token_id=token_id,
            proposal_id="prop_test_001",
            decision_id=decision_id,
            mandate_id="man_test_001",
            reservation_id=reservation_id,
            merchant_id="mer_croma",
            payee_id="acq_croma_001",
            amount_minor=500000,
            currency="INR",
            checkout_hash="sha256:checkout_hash_abc",
            rail="CARD",
            status=TokenStatus.ISSUED,
            idem_key=None,
            expires_at=now + timedelta(minutes=10),
            issued_at=now,
        )
        return IssuedToken(token_record=record, signed_token="mock.jwt.signed_token_secret")

    async def mark_redeemed(self, token_id: str, session: Any = None) -> None:
        self.redeemed_tokens.append(token_id)

    async def mark_failed(self, token_id: str, session: Any = None) -> None:
        self.failed_tokens.append(token_id)

    async def mark_unknown(self, token_id: str, session: Any = None) -> None:
        pass


class MockPspClient:
    def __init__(
        self,
        auth_status: str = "AUTHORIZED",
        decline_code: str | None = None,
        fail_capture: bool = False,
        timeout: bool = False,
    ) -> None:
        self.auth_status = auth_status
        self.decline_code = decline_code
        self.fail_capture = fail_capture
        self.timeout = timeout
        self.card_authorized = False
        self.card_captured = False
        self.upi_created = False

    async def create_scoped_credential(self, req: Any) -> PspCreateScopedCredentialResponse:
        if self.timeout:
            raise PspTimeoutError("Mock PSP request timed out")
        return PspCreateScopedCredentialResponse(
            credential_id="spc_test_001",
            status="ACTIVE",
            max_amount_minor=req.max_amount_minor,
            currency=req.currency,
            expires_at=req.expires_at,
        )

    async def authorize_card(self, req: Any) -> PspAuthorizeCardResponse:
        if self.timeout:
            raise PspTimeoutError("Mock PSP request timed out")
        self.card_authorized = True
        return PspAuthorizeCardResponse(
            psp_payment_id="psp_pay_001",
            status=self.auth_status,
            amount_minor=req.amount_minor,
            currency=req.currency,
            decline_code=self.decline_code,
        )

    async def capture_card(self, req: Any) -> PspCaptureCardResponse:
        if self.timeout:
            raise PspTimeoutError("Mock PSP request timed out")
        if self.fail_capture:
            return PspCaptureCardResponse(
                psp_payment_id=req.psp_payment_id,
                status="FAILED",
                amount_minor=req.amount_minor,
                currency="INR",
            )
        self.card_captured = True
        return PspCaptureCardResponse(
            psp_payment_id=req.psp_payment_id,
            status="CAPTURED",
            amount_minor=req.amount_minor,
            currency="INR",
        )

    async def create_upi_intent(self, req: Any) -> PspCreateUpiIntentResponse:
        if self.timeout:
            raise PspTimeoutError("Mock PSP request timed out")
        self.upi_created = True
        return PspCreateUpiIntentResponse(
            intent_id="upi_intent_001",
            psp_payment_id="psp_pay_upi_001",
            status="PENDING",
            amount_minor=req.amount_minor,
            currency=req.currency,
            payee_vpa=req.payee_vpa,
            expires_at=req.expires_at,
        )

    async def get_payment_status(self, psp_payment_id: str) -> PspPaymentStatusResponse:
        return PspPaymentStatusResponse(
            psp_payment_id=psp_payment_id,
            status="CAPTURED",
            amount_minor=500000,
            currency="INR",
            merchant_id="mer_croma",
        )

    async def get_public_jwks(self) -> Any:
        return {"keys": []}


class AsyncSessionWrapper:
    """Synchronous SQLAlchemy Session wrapper exposing awaitable methods for unit tests."""

    def __init__(self, sync_session: Any) -> None:
        self._sync = sync_session

    async def execute(self, statement: Any, *args: Any, **kwargs: Any) -> Any:
        return self._sync.execute(statement, *args, **kwargs)

    async def flush(self) -> None:
        self._sync.flush()

    def add(self, instance: Any) -> None:
        self._sync.add(instance)

    async def commit(self) -> None:
        self._sync.commit()

    async def rollback(self) -> None:
        self._sync.rollback()

    def close(self) -> None:
        self._sync.close()


@pytest.fixture
def db_session():
    """Create in-memory SQLite database and return an async-wrapped session."""
    engine = create_engine("sqlite:///:memory:", echo=False)
    # Ensure all tables are registered
    _ = (
        PaymentModel,
        IdempotencyKeyModel,
        PspWebhookEventModel,
        PaymentTokenModel,
        DecisionModel,
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    wrapper = AsyncSessionWrapper(session)
    events._default_emitter.clear()
    try:
        yield wrapper
    finally:
        wrapper.close()


@pytest.fixture
def orchestrator_setup():
    decision_provider = MockDecisionProvider()
    mandate_client = MockMandateClient()
    grounding_client = MockGroundingClient()
    token_service = MockTokenService()
    psp_client = MockPspClient()

    orchestrator = PaymentOrchestratorImpl(
        decision_provider=decision_provider,
        token_service=token_service,
        mandate_client=mandate_client,
        grounding_client=grounding_client,
        psp_client=psp_client,
    )
    return {
        "orchestrator": orchestrator,
        "decision_provider": decision_provider,
        "mandate_client": mandate_client,
        "grounding_client": grounding_client,
        "token_service": token_service,
        "psp_client": psp_client,
    }


# =============================================================================
# TEST CASES
# =============================================================================


@pytest.mark.anyio
async def test_card_execution_success(orchestrator_setup, db_session):
    """1. Successful Card execution commits spend, completes checkout, and returns CAPTURED."""
    orch: PaymentOrchestratorImpl = orchestrator_setup["orchestrator"]
    mandate_client: MockMandateClient = orchestrator_setup["mandate_client"]
    grounding_client: MockGroundingClient = orchestrator_setup["grounding_client"]
    token_service: MockTokenService = orchestrator_setup["token_service"]
    psp_client: MockPspClient = orchestrator_setup["psp_client"]

    resp = await orch.execute("prop_test_001", "idem_key_001", session=db_session)

    assert resp.status == PaymentStatus.CAPTURED
    assert resp.rail == PaymentRail.CARD
    assert resp.amount_minor == 500000
    assert resp.currency == "INR"
    assert resp.merchant_id == "mer_croma"
    assert resp.receipt is not None
    assert resp.receipt.transaction_id == "txn_test_001"
    assert resp.receipt.evidence_url == "/v1/evidence/txn_test_001"

    # Verify spend committed
    assert "res_test_001" in mandate_client.committed_reservations
    assert len(mandate_client.released_reservations) == 0

    # Verify checkout completed
    assert ("co_test_001", "psp_pay_001") in grounding_client.completed_checkouts

    # Verify token marked redeemed
    assert len(token_service.redeemed_tokens) == 1
    assert psp_client.card_captured is True


@pytest.mark.anyio
async def test_card_authorization_decline(orchestrator_setup, db_session):
    """2. Card authorization decline releases spend, marks token failed, and returns FAILED."""
    orch: PaymentOrchestratorImpl = orchestrator_setup["orchestrator"]
    mandate_client: MockMandateClient = orchestrator_setup["mandate_client"]
    token_service: MockTokenService = orchestrator_setup["token_service"]
    psp_client: MockPspClient = orchestrator_setup["psp_client"]

    psp_client.auth_status = "FAILED"
    psp_client.decline_code = "INSUFFICIENT_FUNDS"

    resp = await orch.execute("prop_test_001", "idem_key_002", session=db_session)

    assert resp.status == PaymentStatus.FAILED
    assert resp.receipt is None

    # Verify spend released
    assert "res_test_001" in mandate_client.released_reservations
    assert len(mandate_client.committed_reservations) == 0

    # Verify token marked failed
    assert len(token_service.failed_tokens) == 1


@pytest.mark.anyio
async def test_card_capture_failure(orchestrator_setup, db_session):
    """3. Card capture failure marks payment FAILED and releases spend."""
    orch: PaymentOrchestratorImpl = orchestrator_setup["orchestrator"]
    mandate_client: MockMandateClient = orchestrator_setup["mandate_client"]
    psp_client: MockPspClient = orchestrator_setup["psp_client"]

    psp_client.fail_capture = True

    resp = await orch.execute("prop_test_001", "idem_key_003", session=db_session)

    assert resp.status == PaymentStatus.FAILED
    assert "res_test_001" in mandate_client.released_reservations
    assert len(mandate_client.committed_reservations) == 0


@pytest.mark.anyio
async def test_upi_intent_creation_pending(orchestrator_setup, db_session):
    """4. Successful UPI intent creation leaves state PENDING with spend intact."""
    orch: PaymentOrchestratorImpl = orchestrator_setup["orchestrator"]
    grounding_client: MockGroundingClient = orchestrator_setup["grounding_client"]
    mandate_client: MockMandateClient = orchestrator_setup["mandate_client"]
    psp_client: MockPspClient = orchestrator_setup["psp_client"]

    grounding_client.proposal.rail = "UPI"

    resp = await orch.execute("prop_test_001", "idem_key_004", session=db_session)

    assert resp.status == PaymentStatus.PENDING
    assert resp.rail == PaymentRail.UPI
    assert psp_client.upi_created is True
    assert resp.receipt is None

    # Spend reservation remains intact (neither committed nor released)
    assert len(mandate_client.committed_reservations) == 0
    assert len(mandate_client.released_reservations) == 0


@pytest.mark.anyio
async def test_decision_validation_not_allow(orchestrator_setup, db_session):
    """5. Rejects non-ALLOW decision with DecisionNotAllowError."""
    orch: PaymentOrchestratorImpl = orchestrator_setup["orchestrator"]
    decision_provider: MockDecisionProvider = orchestrator_setup["decision_provider"]

    decision_provider.decision.outcome = "BLOCK"

    with pytest.raises(DecisionNotAllowError) as exc_info:
        await orch.execute("prop_test_001", "idem_key_005", session=db_session)

    assert exc_info.value.code == "DECISION_NOT_ALLOW"
    assert exc_info.value.status_code == 400


@pytest.mark.anyio
async def test_decision_validation_missing(orchestrator_setup, db_session):
    """6. Rejects missing decision with DecisionNotFoundError."""
    orch: PaymentOrchestratorImpl = orchestrator_setup["orchestrator"]
    decision_provider: MockDecisionProvider = orchestrator_setup["decision_provider"]

    decision_provider.decision = None

    with pytest.raises(DecisionNotFoundError) as exc_info:
        await orch.execute("prop_test_001", "idem_key_006", session=db_session)

    assert exc_info.value.code == "DECISION_NOT_FOUND"
    assert exc_info.value.status_code == 404


@pytest.mark.anyio
async def test_expired_decision_rejection(orchestrator_setup, db_session):
    """7. Rejects expired decision with DecisionExpiredError."""
    orch: PaymentOrchestratorImpl = orchestrator_setup["orchestrator"]
    decision_provider: MockDecisionProvider = orchestrator_setup["decision_provider"]

    decision_provider.decision.expires_at = datetime.now(UTC) - timedelta(seconds=10)

    with pytest.raises(DecisionExpiredError) as exc_info:
        await orch.execute("prop_test_001", "idem_key_007", session=db_session)

    assert exc_info.value.code == "DECISION_EXPIRED"
    assert exc_info.value.status_code == 410


@pytest.mark.anyio
async def test_checkout_validation_failure_toctou(orchestrator_setup, db_session):
    """8. Rejects checkout with changed hash (TOCTOU violation)."""
    orch: PaymentOrchestratorImpl = orchestrator_setup["orchestrator"]
    grounding_client: MockGroundingClient = orchestrator_setup["grounding_client"]

    # Re-fetched checkout has different hash
    grounding_client.checkout.checkout_hash = "sha256:tampered_hash_xyz"

    with pytest.raises(CheckoutChangedError) as exc_info:
        await orch.execute("prop_test_001", "idem_key_008", session=db_session)

    assert exc_info.value.code == "CHECKOUT_CHANGED"
    assert exc_info.value.status_code == 409


@pytest.mark.anyio
async def test_spend_reservation_failure(orchestrator_setup, db_session):
    """9. Rejects payment when mandate spend reservation fails."""
    orch: PaymentOrchestratorImpl = orchestrator_setup["orchestrator"]
    mandate_client: MockMandateClient = orchestrator_setup["mandate_client"]

    mandate_client.fail_reserve = True

    with pytest.raises(SpendReservationError) as exc_info:
        await orch.execute("prop_test_001", "idem_key_009", session=db_session)

    assert exc_info.value.code == "OVER_TOTAL_CAP"
    assert exc_info.value.status_code == 400


@pytest.mark.anyio
async def test_idempotent_repeated_request(orchestrator_setup, db_session):
    """10. Repeated request with identical key and proposal returns cached response."""
    orch: PaymentOrchestratorImpl = orchestrator_setup["orchestrator"]
    mandate_client: MockMandateClient = orchestrator_setup["mandate_client"]

    resp1 = await orch.execute("prop_test_001", "idem_key_010", session=db_session)
    assert resp1.status == PaymentStatus.CAPTURED
    assert len(mandate_client.committed_reservations) == 1

    # Second call with same key and proposal
    resp2 = await orch.execute("prop_test_001", "idem_key_010", session=db_session)
    assert resp2.payment_id == resp1.payment_id
    assert resp2.status == resp1.status

    # Ensure external calls / spend commit were not duplicated
    assert len(mandate_client.committed_reservations) == 1


@pytest.mark.anyio
async def test_same_idempotency_key_different_request(orchestrator_setup, db_session):
    """11. Same idempotency key with different request payload raises IdempotencyConflictError."""
    orch: PaymentOrchestratorImpl = orchestrator_setup["orchestrator"]

    # First call with prop_test_001
    await orch.execute("prop_test_001", "idem_key_011", session=db_session)

    # Second call with same key but different proposal
    with pytest.raises(IdempotencyConflictError) as exc_info:
        await orch.execute("prop_test_different", "idem_key_011", session=db_session)

    assert exc_info.value.code == "IDEMPOTENCY_KEY_MISMATCH"
    assert exc_info.value.status_code == 409


@pytest.mark.anyio
async def test_concurrent_duplicate_execution_prevention(orchestrator_setup, db_session):
    """12. Prevents duplicate payments for the same proposal under different keys."""
    orch: PaymentOrchestratorImpl = orchestrator_setup["orchestrator"]

    # Execute first payment
    await orch.execute("prop_test_001", "idem_key_012_a", session=db_session)

    # Second execution for same proposal with a different idempotency key
    with pytest.raises(PaymentAlreadyExistsError) as exc_info:
        await orch.execute("prop_test_001", "idem_key_012_b", session=db_session)

    assert exc_info.value.code == "PAYMENT_ALREADY_EXISTS"
    assert exc_info.value.status_code == 409


@pytest.mark.anyio
async def test_psp_timeout_unknown_handling(orchestrator_setup, db_session):
    """13. PSP timeout sets payment to UNKNOWN and does NOT release spend reservation."""
    orch: PaymentOrchestratorImpl = orchestrator_setup["orchestrator"]
    mandate_client: MockMandateClient = orchestrator_setup["mandate_client"]
    psp_client: MockPspClient = orchestrator_setup["psp_client"]

    psp_client.timeout = True

    resp = await orch.execute("prop_test_001", "idem_key_013", session=db_session)

    assert resp.status == PaymentStatus.UNKNOWN
    # Critical invariant: Spend reservation must NOT be released while
    # rail charge may have succeeded!
    assert len(mandate_client.released_reservations) == 0
    assert len(mandate_client.committed_reservations) == 0


@pytest.mark.anyio
async def test_no_automatic_duplicate_charge_after_timeout(orchestrator_setup, db_session):
    """14. A payment in UNKNOWN is never retried with a second charge."""
    orch: PaymentOrchestratorImpl = orchestrator_setup["orchestrator"]
    psp_client: MockPspClient = orchestrator_setup["psp_client"]

    psp_client.timeout = True
    resp1 = await orch.execute("prop_test_001", "idem_key_014", session=db_session)
    assert resp1.status == PaymentStatus.UNKNOWN

    # Clear timeout flag on PSP
    psp_client.timeout = False

    # Calling with same key returns the stored UNKNOWN response without attempting another charge
    resp2 = await orch.execute("prop_test_001", "idem_key_014", session=db_session)
    assert resp2.status == PaymentStatus.UNKNOWN
    assert resp2.payment_id == resp1.payment_id
    assert psp_client.card_captured is False


@pytest.mark.anyio
async def test_token_issuance_failure_reservation_cleanup(orchestrator_setup, db_session):
    """15. Failure during token issuance cleans up the spend reservation."""
    orch: PaymentOrchestratorImpl = orchestrator_setup["orchestrator"]
    mandate_client: MockMandateClient = orchestrator_setup["mandate_client"]
    token_service: MockTokenService = orchestrator_setup["token_service"]

    token_service.fail_issue = True

    with pytest.raises(PaymentError):
        await orch.execute("prop_test_001", "idem_key_015", session=db_session)

    # Reservation was cleaned up
    assert "res_test_001" in mandate_client.released_reservations


@pytest.mark.anyio
async def test_event_emission_and_transaction_behavior(orchestrator_setup, db_session):
    """16. Correctly emits PAYMENT_CREATED and PAYMENT_RESULT events."""
    orch: PaymentOrchestratorImpl = orchestrator_setup["orchestrator"]

    await orch.execute("prop_test_001", "idem_key_016", session=db_session)

    emitted = events._default_emitter.emitted_events
    types = [e["event_type"] for e in emitted]

    assert "PAYMENT_CREATED" in types
    assert "PAYMENT_RESULT" in types

    result_event = next(e for e in emitted if e["event_type"] == "PAYMENT_RESULT")
    assert result_event["payload"]["status"] == "CAPTURED"
    assert result_event["payload"]["psp_payment_id"] == "psp_pay_001"
    assert result_event["producer"] == "payments"


@pytest.mark.anyio
async def test_no_sensitive_token_leakage(orchestrator_setup, db_session):
    """17. Raw signed token is never stored in PaymentModel or returned in response."""
    orch: PaymentOrchestratorImpl = orchestrator_setup["orchestrator"]

    resp = await orch.execute("prop_test_001", "idem_key_017", session=db_session)

    # Verify response schema has no token JWS field
    dumped = resp.model_dump()
    assert "signed_token" not in dumped
    assert "mandit_token" not in dumped

    # Verify database model has no token JWS
    status_resp = await orch.get(resp.payment_id, session=db_session)
    assert status_resp is not None
    assert status_resp.payment_id == resp.payment_id
    assert status_resp.token_id.startswith("ptok_")
    assert "mock.jwt" not in status_resp.token_id


@pytest.mark.anyio
async def test_get_and_get_by_proposal(orchestrator_setup, db_session):
    """18. Tests get(payment_id) and get_by_proposal(proposal_id)."""
    orch: PaymentOrchestratorImpl = orchestrator_setup["orchestrator"]

    resp = await orch.execute("prop_test_001", "idem_key_018", session=db_session)

    by_id = await orch.get(resp.payment_id, session=db_session)
    assert by_id is not None
    assert by_id.payment_id == resp.payment_id
    assert by_id.proposal_id == "prop_test_001"
    assert by_id.status == PaymentStatus.CAPTURED

    by_prop = await orch.get_by_proposal("prop_test_001", session=db_session)
    assert by_prop is not None
    assert by_prop.payment_id == resp.payment_id
    assert by_prop.status == PaymentStatus.CAPTURED

    non_existent = await orch.get("pay_nonexistent", session=db_session)
    assert non_existent is None
