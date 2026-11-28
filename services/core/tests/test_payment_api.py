"""Comprehensive tests for Payment API routes, Signed Webhooks, and Reconciliation (Milestone 4).

Covers:
- POST /v1/payments/execute
- GET /v1/payments/{payment_id}
- POST /v1/payments/webhooks/mock-psp
- Webhook signature verification, tampering, unknown keys, replay prevention
- Out-of-band PSP status confirmation before state mutation
- Reconciliation of UNKNOWN and PENDING payments
- Spend commit/release and token lifecycle transitions
- End-to-end integration with InProcessPspClient
Per docs/modules/04-policy-and-payments.md §8 and docs/REFERENCE.md §9.4, §12.5.
"""

import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from mandit.common import events, jcs
from mandit.common.crypto import b64url_encode
from mandit.common.models import Base
from mandit.payments.api import (
    get_db_session,
    get_payment_orchestrator,
    router,
)
from mandit.payments.models import (
    IdempotencyKeyModel,
    PaymentModel,
    PspWebhookEventModel,
)
from mandit.payments.psp_client import (
    InProcessPspClient,
    PspAuthorizeCardResponse,
    PspCaptureCardResponse,
    PspCreateScopedCredentialResponse,
    PspCreateUpiIntentResponse,
    PspPaymentStatusResponse,
)
from mandit.payments.schemas import (
    PaymentRail,
    PaymentReceiptSchema,
    PaymentStatus,
    PaymentStatusResponse,
)
from mandit.payments.service import (
    DecisionNotFoundError,
    IdempotencyConflictError,
    PaymentOrchestratorImpl,
)
from mandit.payments.webhook_verifier import PspWebhookVerifier
from mandit.policy.models import DecisionModel
from mandit.tokens.models import PaymentTokenModel
from mandit.tokens.schemas import (
    IssuedToken,
    PaymentToken,
    TokenStatus,
)
from mock_psp.crypto import PspKeyManager
from mock_psp.models import PspBase
from mock_psp.service import MockPspService
from mock_psp.token_client import TokenClient

# --- Mock Doubles for API & Reconciliation ---


class MockDecision:
    def __init__(
        self,
        decision_id: str = "dec_api_001",
        proposal_id: str = "prop_api_001",
        outcome: str = "ALLOW",
        expires_at: datetime | None = None,
        transaction_id: str = "txn_api_001",
        mandate_id: str = "man_api_001",
        proposal_hash: str = "sha256:proposal_hash_001",
    ) -> None:
        self.proposal_hash = proposal_hash
        self.decision_id = decision_id
        self.proposal_id = proposal_id
        self.outcome = outcome
        self.expires_at = expires_at or (datetime.now(UTC) + timedelta(minutes=15))
        self.transaction_id = transaction_id
        self.mandate_id = mandate_id


class MockProposal:
    def __init__(
        self,
        proposal_id: str = "prop_api_001",
        agent_id: str = "agent_01",
        mandate_id: str = "man_api_001",
        checkout_id: str = "co_api_001",
        checkout_hash: str = "sha256:api_checkout_hash",
        merchant_id: str = "mer_demo",
        payee_id: str = "acq_demo_001",
        amount_minor: int = 100000,
        currency: str = "INR",
        rail: str = "CARD",
        transaction_id: str = "txn_api_001",
        proposal_hash: str = "sha256:proposal_hash_001",
    ) -> None:
        self.proposal_hash = proposal_hash
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
        checkout_id: str = "co_api_001",
        checkout_hash: str = "sha256:api_checkout_hash",
        merchant_id: str = "mer_demo",
        payee_id: str = "acq_demo_001",
        amount_minor: int = 100000,
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
    def __init__(self, reservation_id: str = "res_api_001") -> None:
        self.reservation_id = reservation_id
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
    def __init__(self) -> None:
        self.issued_tokens: list[str] = []
        self.redeemed_tokens: list[str] = []
        self.failed_tokens: list[str] = []

    async def issue(
        self, decision_id: str, reservation_id: str, session: Any = None
    ) -> IssuedToken:
        now = datetime.now(UTC)
        token_id = f"ptok_{uuid.uuid4().hex[:8]}"
        self.issued_tokens.append(token_id)
        record = PaymentToken(
            token_id=token_id,
            proposal_id="prop_api_001",
            decision_id=decision_id,
            mandate_id="man_api_001",
            reservation_id=reservation_id,
            merchant_id="mer_demo",
            payee_id="acq_demo_001",
            amount_minor=100000,
            currency="INR",
            checkout_hash="sha256:api_checkout_hash",
            rail="CARD",
            status=TokenStatus.ISSUED,
            idem_key=None,
            expires_at=now + timedelta(minutes=10),
            issued_at=now,
        )
        claims_dict = {
            "jti": token_id,
            "merchant_id": "mer_demo",
            "payee_id": "acq_demo_001",
            "amount_minor": 100000,
            "currency": "INR",
            "checkout_hash": "sha256:api_checkout_hash",
            "rail": "CARD",
        }
        header_b64 = b64url_encode(b'{"alg":"EdDSA","typ":"mandit-pay+jwt"}')
        claims_b64 = b64url_encode(json.dumps(claims_dict).encode("utf-8"))
        signed_token = f"{header_b64}.{claims_b64}.mock_sig"
        return IssuedToken(token_record=record, signed_token=signed_token)

    async def mark_redeemed(self, token_id: str, session: Any = None) -> None:
        self.redeemed_tokens.append(token_id)

    async def mark_failed(self, token_id: str, session: Any = None) -> None:
        self.failed_tokens.append(token_id)

    async def mark_unknown(self, token_id: str, session: Any = None) -> None:
        pass


class MockPspClient:
    def __init__(
        self,
        psp_status: str = "CAPTURED",
        auth_status: str = "AUTHORIZED",
    ) -> None:
        self.psp_status = psp_status
        self.auth_status = auth_status
        self.status_queries: list[str] = []

    async def create_scoped_credential(self, req: Any) -> PspCreateScopedCredentialResponse:
        return PspCreateScopedCredentialResponse(
            credential_id="spc_api_001",
            status="ACTIVE",
            max_amount_minor=req.max_amount_minor,
            currency=req.currency,
            expires_at=req.expires_at,
        )

    async def authorize_card(self, req: Any) -> PspAuthorizeCardResponse:
        return PspAuthorizeCardResponse(
            psp_payment_id="psp_pay_api_001",
            status=self.auth_status,
            amount_minor=req.amount_minor,
            currency=req.currency,
        )

    async def capture_card(self, req: Any) -> PspCaptureCardResponse:
        return PspCaptureCardResponse(
            psp_payment_id=req.psp_payment_id,
            status="CAPTURED",
            amount_minor=req.amount_minor,
            currency="INR",
        )

    async def create_upi_intent(self, req: Any) -> PspCreateUpiIntentResponse:
        return PspCreateUpiIntentResponse(
            intent_id="upi_intent_api_001",
            psp_payment_id="psp_pay_upi_001",
            status="PENDING",
            amount_minor=req.amount_minor,
            currency=req.currency,
            payee_vpa=req.payee_vpa,
            expires_at=req.expires_at,
        )

    async def get_payment_status(self, psp_payment_id: str) -> PspPaymentStatusResponse:
        self.status_queries.append(psp_payment_id)
        return PspPaymentStatusResponse(
            psp_payment_id=psp_payment_id,
            status=self.psp_status,
            amount_minor=100000,
            currency="INR",
            merchant_id="mer_demo",
        )

    async def get_public_jwks(self) -> Any:
        return {"keys": []}


class AsyncSessionWrapper:
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


def make_signed_webhook_header(
    private_key: ed25519.Ed25519PrivateKey, key_id: str, body: dict[str, Any]
) -> str:
    """Helper creating valid Mock-PSP-Signature header over RFC 8785 canonical bytes."""
    canonical_bytes = jcs.canonicalize(body)
    sig_bytes = private_key.sign(canonical_bytes)
    sig_b64 = b64url_encode(sig_bytes)
    return f'keyid="{key_id}",sig="{sig_b64}"'


@pytest.fixture
def webhook_keypair():
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    return priv, pub


@pytest.fixture
def db_session():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        echo=False,
    )
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
def test_setup(webhook_keypair):
    priv, pub = webhook_keypair
    verifier = PspWebhookVerifier()
    verifier.register_trusted_key("psp-2026-11", pub)

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
        webhook_verifier=verifier,
    )

    app = FastAPI()
    app.include_router(router)

    return {
        "app": app,
        "orchestrator": orchestrator,
        "psp_client": psp_client,
        "mandate_client": mandate_client,
        "grounding_client": grounding_client,
        "token_service": token_service,
        "webhook_keypair": (priv, pub),
        "verifier": verifier,
    }


# =============================================================================
# API ROUTE TESTS
# =============================================================================


def test_api_execute_success(test_setup, db_session):
    """1. POST /v1/payments/execute executes payment and returns 200 OK with receipt."""
    app = test_setup["app"]
    orch = test_setup["orchestrator"]

    app.dependency_overrides[get_payment_orchestrator] = lambda: orch
    app.dependency_overrides[get_db_session] = lambda: db_session

    client = TestClient(app)
    resp = client.post(
        "/v1/payments/execute",
        json={"proposal_id": "prop_api_001"},
        headers={"Idempotency-Key": "api_key_001"},
    )

    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "CAPTURED"
    assert data["rail"] == "CARD"
    assert data["amount_minor"] == 100000
    assert data["currency"] == "INR"
    assert data["receipt"]["transaction_id"] == "txn_api_001"


def test_api_execute_missing_idempotency_header(test_setup, db_session):
    """2. POST /v1/payments/execute without Idempotency-Key header returns 422."""
    app = test_setup["app"]
    orch = test_setup["orchestrator"]

    app.dependency_overrides[get_payment_orchestrator] = lambda: orch
    app.dependency_overrides[get_db_session] = lambda: db_session

    client = TestClient(app)
    resp = client.post(
        "/v1/payments/execute",
        json={"proposal_id": "prop_api_001"},
    )
    assert resp.status_code == 422


def test_api_execute_decision_not_found(test_setup, db_session):
    """3. POST /v1/payments/execute maps DecisionNotFoundError to 404."""
    app = test_setup["app"]
    orch = test_setup["orchestrator"]

    async def _fail(*args: Any, **kwargs: Any) -> Any:
        raise DecisionNotFoundError("No decision found")

    orch.execute = _fail  # type: ignore[assignment]
    app.dependency_overrides[get_payment_orchestrator] = lambda: orch
    app.dependency_overrides[get_db_session] = lambda: db_session

    client = TestClient(app)
    resp = client.post(
        "/v1/payments/execute",
        json={"proposal_id": "prop_api_001"},
        headers={"Idempotency-Key": "api_key_002"},
    )
    assert resp.status_code == 404
    assert resp.json()["detail"]["code"] == "DECISION_NOT_FOUND"


def test_api_execute_idempotency_conflict(test_setup, db_session):
    """4. POST /v1/payments/execute maps IdempotencyConflictError to 409."""
    app = test_setup["app"]
    orch = test_setup["orchestrator"]

    async def _fail(*args: Any, **kwargs: Any) -> Any:
        raise IdempotencyConflictError("Key reused with different request")

    orch.execute = _fail  # type: ignore[assignment]
    app.dependency_overrides[get_payment_orchestrator] = lambda: orch
    app.dependency_overrides[get_db_session] = lambda: db_session

    client = TestClient(app)
    resp = client.post(
        "/v1/payments/execute",
        json={"proposal_id": "prop_api_001"},
        headers={"Idempotency-Key": "api_key_003"},
    )
    assert resp.status_code == 409
    assert resp.json()["detail"]["code"] == "IDEMPOTENCY_KEY_MISMATCH"


def test_api_get_payment_status(test_setup, db_session):
    """5. GET /v1/payments/{payment_id} returns payment details and 404 when not found."""
    app = test_setup["app"]
    orch = test_setup["orchestrator"]

    now = datetime.now(UTC)

    async def _mock_get(pid: str, session: Any = None) -> Any:
        if pid == "pay_found":
            return PaymentStatusResponse(
                payment_id="pay_found",
                proposal_id="prop_01",
                rail=PaymentRail.CARD,
                status=PaymentStatus.CAPTURED,
                amount_minor=100000,
                currency="INR",
                created_at=now,
                updated_at=now,
                receipt=PaymentReceiptSchema(transaction_id="txn_01"),
            )
        return None

    orch.get = _mock_get  # type: ignore[assignment]
    app.dependency_overrides[get_payment_orchestrator] = lambda: orch
    app.dependency_overrides[get_db_session] = lambda: db_session

    client = TestClient(app)

    # Found
    resp1 = client.get("/v1/payments/pay_found")
    assert resp1.status_code == 200
    assert resp1.json()["payment_id"] == "pay_found"

    # Not found
    resp2 = client.get("/v1/payments/pay_missing")
    assert resp2.status_code == 404
    assert resp2.json()["detail"]["code"] == "PAYMENT_NOT_FOUND"


# =============================================================================
# WEBHOOK PROCESSING TESTS
# =============================================================================


def test_webhook_valid_signature_success(test_setup, db_session):
    """6. Valid signed webhook callback processes and returns 200 PROCESSED."""
    app = test_setup["app"]
    orch: PaymentOrchestratorImpl = test_setup["orchestrator"]
    priv, _ = test_setup["webhook_keypair"]
    mandate_client: MockMandateClient = test_setup["mandate_client"]

    app.dependency_overrides[get_payment_orchestrator] = lambda: orch
    app.dependency_overrides[get_db_session] = lambda: db_session

    # First, insert a pending payment into DB
    now = datetime.now(UTC)
    db_session.add(
        PaymentModel(
            payment_id="pay_wh_001",
            proposal_id="prop_wh_001",
            token_id="ptok_wh_001",
            rail="CARD",
            psp_payment_id="psp_wh_001",
            status=PaymentStatus.PENDING.value,
            amount_minor=100000,
            currency="INR",
            created_at=now,
            updated_at=now,
        )
    )
    db_session.add(
        PaymentTokenModel(
            token_id="ptok_wh_001",
            proposal_id="prop_wh_001",
            decision_id="dec_01",
            mandate_id="man_01",
            reservation_id="res_wh_001",
            merchant_id="mer_demo",
            payee_id="acq_demo_001",
            amount_minor=100000,
            currency="INR",
            checkout_hash="hash_01",
            rail="CARD",
            status="ISSUED",
            expires_at=now + timedelta(minutes=10),
            issued_at=now,
        )
    )

    body = {
        "psp_event_id": "pspevt_001",
        "type": "payment.captured",
        "psp_payment_id": "psp_wh_001",
        "payment_ref": "pay_wh_001",
        "amount_minor": 100000,
        "currency": "INR",
        "status": "CAPTURED",
        "occurred_at": now.isoformat(),
    }
    sig_header = make_signed_webhook_header(priv, "psp-2026-11", body)

    client = TestClient(app)
    resp = client.post(
        "/v1/payments/webhooks/mock-psp",
        json=body,
        headers={"Mock-PSP-Signature": sig_header},
    )

    assert resp.status_code == 200
    assert resp.json()["status"] == "PROCESSED"
    assert resp.json()["payment_status"] == "CAPTURED"

    # Verify spend was committed
    assert "res_wh_001" in mandate_client.committed_reservations


def test_webhook_invalid_signature_rejection(test_setup, db_session):
    """7. Webhook with invalid/forged signature fails closed with 401."""
    app = test_setup["app"]
    orch: PaymentOrchestratorImpl = test_setup["orchestrator"]
    priv, _ = test_setup["webhook_keypair"]

    app.dependency_overrides[get_payment_orchestrator] = lambda: orch
    app.dependency_overrides[get_db_session] = lambda: db_session

    body = {
        "psp_event_id": "pspevt_002",
        "type": "payment.captured",
        "psp_payment_id": "psp_wh_002",
        "payment_ref": "pay_wh_002",
        "amount_minor": 100000,
        "currency": "INR",
        "status": "CAPTURED",
        "occurred_at": datetime.now(UTC).isoformat(),
    }
    # Sign with an unrelated private key so the signature is well-formed (64 bytes)
    # but fails cryptographic verification against the trusted public key for "psp-2026-11".
    unrelated_priv = ed25519.Ed25519PrivateKey.generate()
    bad_header = make_signed_webhook_header(unrelated_priv, "psp-2026-11", body)

    client = TestClient(app)
    resp = client.post(
        "/v1/payments/webhooks/mock-psp",
        json=body,
        headers={"Mock-PSP-Signature": bad_header},
    )

    assert resp.status_code == 401
    assert resp.json()["detail"]["code"] == "SIGNATURE_MISMATCH"


def test_webhook_unknown_key_id(test_setup, db_session):
    """8. Webhook with unknown key ID fails closed with 401."""
    app = test_setup["app"]
    orch: PaymentOrchestratorImpl = test_setup["orchestrator"]
    priv, _ = test_setup["webhook_keypair"]

    app.dependency_overrides[get_payment_orchestrator] = lambda: orch
    app.dependency_overrides[get_db_session] = lambda: db_session

    body = {
        "psp_event_id": "pspevt_003",
        "type": "payment.captured",
        "psp_payment_id": "psp_wh_003",
        "payment_ref": "pay_wh_003",
        "amount_minor": 100000,
        "currency": "INR",
        "status": "CAPTURED",
        "occurred_at": datetime.now(UTC).isoformat(),
    }
    # Use unknown key ID 'untrusted-key'
    sig_header = make_signed_webhook_header(priv, "untrusted-key", body)

    client = TestClient(app)
    resp = client.post(
        "/v1/payments/webhooks/mock-psp",
        json=body,
        headers={"Mock-PSP-Signature": sig_header},
    )

    assert resp.status_code == 401
    assert resp.json()["detail"]["code"] == "UNKNOWN_KEY_ID"


def test_webhook_payload_tampering(test_setup, db_session):
    """9. Tampered webhook body fails verification with 401."""
    app = test_setup["app"]
    orch: PaymentOrchestratorImpl = test_setup["orchestrator"]
    priv, _ = test_setup["webhook_keypair"]

    app.dependency_overrides[get_payment_orchestrator] = lambda: orch
    app.dependency_overrides[get_db_session] = lambda: db_session

    body = {
        "psp_event_id": "pspevt_004",
        "type": "payment.captured",
        "psp_payment_id": "psp_wh_004",
        "amount_minor": 100000,
        "currency": "INR",
        "status": "CAPTURED",
        "occurred_at": datetime.now(UTC).isoformat(),
    }
    sig_header = make_signed_webhook_header(priv, "psp-2026-11", body)

    # Tamper with amount
    tampered_body = dict(body)
    tampered_body["amount_minor"] = 200000

    client = TestClient(app)
    resp = client.post(
        "/v1/payments/webhooks/mock-psp",
        json=tampered_body,
        headers={"Mock-PSP-Signature": sig_header},
    )

    assert resp.status_code == 401
    assert resp.json()["detail"]["code"] == "SIGNATURE_MISMATCH"


def test_webhook_duplicate_replay_prevention(test_setup, db_session):
    """10. Duplicate webhook delivery returns 200 with REPLAYED and no state changes."""
    app = test_setup["app"]
    orch: PaymentOrchestratorImpl = test_setup["orchestrator"]
    priv, _ = test_setup["webhook_keypair"]
    mandate_client: MockMandateClient = test_setup["mandate_client"]

    app.dependency_overrides[get_payment_orchestrator] = lambda: orch
    app.dependency_overrides[get_db_session] = lambda: db_session

    now = datetime.now(UTC)
    db_session.add(
        PaymentModel(
            payment_id="pay_wh_dup",
            proposal_id="prop_wh_dup",
            token_id="ptok_wh_dup",
            rail="CARD",
            psp_payment_id="psp_wh_dup",
            status=PaymentStatus.PENDING.value,
            amount_minor=100000,
            currency="INR",
            created_at=now,
            updated_at=now,
        )
    )

    body = {
        "psp_event_id": "pspevt_replay_001",
        "type": "payment.captured",
        "psp_payment_id": "psp_wh_dup",
        "payment_ref": "pay_wh_dup",
        "amount_minor": 100000,
        "currency": "INR",
        "status": "CAPTURED",
        "occurred_at": now.isoformat(),
    }
    sig_header = make_signed_webhook_header(priv, "psp-2026-11", body)

    client = TestClient(app)

    # First delivery
    resp1 = client.post(
        "/v1/payments/webhooks/mock-psp",
        json=body,
        headers={"Mock-PSP-Signature": sig_header},
    )
    assert resp1.status_code == 200
    assert resp1.json()["status"] == "PROCESSED"
    initial_commits = len(mandate_client.committed_reservations)

    # Duplicate replay delivery
    resp2 = client.post(
        "/v1/payments/webhooks/mock-psp",
        json=body,
        headers={"Mock-PSP-Signature": sig_header},
    )
    assert resp2.status_code == 200
    assert resp2.json()["status"] == "REPLAYED"
    assert resp2.json()["detail"] == "WEBHOOK_REPLAYED"

    # Invariant: No additional commit_spend call on duplicate replay
    assert len(mandate_client.committed_reservations) == initial_commits


def test_webhook_out_of_band_psp_verification(test_setup, db_session):
    """11. Core queries PSP status out-of-band and rejects settlement if PSP reports FAILED."""
    orch: PaymentOrchestratorImpl = test_setup["orchestrator"]
    priv, _ = test_setup["webhook_keypair"]
    psp_client: MockPspClient = test_setup["psp_client"]
    mandate_client: MockMandateClient = test_setup["mandate_client"]

    # PSP authoritative status is FAILED, while webhook claims CAPTURED
    psp_client.psp_status = "FAILED"

    now = datetime.now(UTC)
    db_session.add(
        PaymentModel(
            payment_id="pay_spoof",
            proposal_id="prop_spoof",
            token_id="ptok_spoof",
            rail="CARD",
            psp_payment_id="psp_spoof",
            status=PaymentStatus.PENDING.value,
            amount_minor=100000,
            currency="INR",
            created_at=now,
            updated_at=now,
        )
    )

    body = {
        "psp_event_id": "pspevt_spoof_001",
        "type": "payment.captured",
        "psp_payment_id": "psp_spoof",
        "payment_ref": "pay_spoof",
        "amount_minor": 100000,
        "currency": "INR",
        "status": "CAPTURED",  # Webhook claims CAPTURED
        "occurred_at": now.isoformat(),
    }
    sig_header = make_signed_webhook_header(priv, "psp-2026-11", body)

    # Process webhook
    import anyio

    anyio.run(orch.process_webhook, body, sig_header, db_session)

    # Check payment transitioned to FAILED (matching PSP authoritative query, not the webhook claim)
    updated = anyio.run(orch.get, "pay_spoof", db_session)
    assert updated.status == PaymentStatus.FAILED

    # Spend was released, NOT committed
    assert len(mandate_client.committed_reservations) == 0


# =============================================================================
# RECONCILIATION TESTS
# =============================================================================


@pytest.mark.anyio
async def test_reconciliation_unknown_card_payment(test_setup, db_session):
    """12. Reconciliation transitions UNKNOWN payment to CAPTURED and commits spend."""
    orch: PaymentOrchestratorImpl = test_setup["orchestrator"]
    mandate_client: MockMandateClient = test_setup["mandate_client"]
    token_service: MockTokenService = test_setup["token_service"]
    psp_client: MockPspClient = test_setup["psp_client"]

    psp_client.psp_status = "CAPTURED"

    old_time = datetime.now(UTC) - timedelta(seconds=30)
    db_session.add(
        PaymentModel(
            payment_id="pay_rec_001",
            proposal_id="prop_rec_001",
            token_id="ptok_rec_001",
            rail="CARD",
            psp_payment_id="psp_rec_001",
            status=PaymentStatus.UNKNOWN.value,
            amount_minor=100000,
            currency="INR",
            created_at=old_time,
            updated_at=old_time,
        )
    )
    db_session.add(
        PaymentTokenModel(
            token_id="ptok_rec_001",
            proposal_id="prop_rec_001",
            decision_id="dec_rec_001",
            mandate_id="man_rec_001",
            reservation_id="res_rec_001",
            merchant_id="mer_demo",
            payee_id="acq_demo_001",
            amount_minor=100000,
            currency="INR",
            checkout_hash="hash_rec_01",
            rail="CARD",
            status="REDEEMING",
            expires_at=old_time + timedelta(minutes=10),
            issued_at=old_time,
        )
    )

    reconciled = await orch.reconcile(timeout_threshold_seconds=15, session=db_session)

    assert len(reconciled) == 1
    assert reconciled[0].payment_id == "pay_rec_001"
    assert reconciled[0].status == PaymentStatus.CAPTURED

    # Invariant: Spend committed on established success
    assert "res_rec_001" in mandate_client.committed_reservations
    assert len(token_service.redeemed_tokens) == 1


@pytest.mark.anyio
async def test_reconciliation_expired_upi_payment(test_setup, db_session):
    """13. Reconciliation transitions expired PENDING UPI payment to EXPIRED and releases spend."""
    orch: PaymentOrchestratorImpl = test_setup["orchestrator"]
    mandate_client: MockMandateClient = test_setup["mandate_client"]
    token_service: MockTokenService = test_setup["token_service"]
    psp_client: MockPspClient = test_setup["psp_client"]

    psp_client.psp_status = "EXPIRED"

    old_time = datetime.now(UTC) - timedelta(seconds=60)
    db_session.add(
        PaymentModel(
            payment_id="pay_upi_exp",
            proposal_id="prop_upi_exp",
            token_id="ptok_upi_exp",
            rail="UPI",
            psp_payment_id="psp_upi_exp",
            status=PaymentStatus.PENDING.value,
            amount_minor=50000,
            currency="INR",
            created_at=old_time,
            updated_at=old_time,
        )
    )
    db_session.add(
        PaymentTokenModel(
            token_id="ptok_upi_exp",
            proposal_id="prop_upi_exp",
            decision_id="dec_02",
            mandate_id="man_02",
            reservation_id="res_upi_exp",
            merchant_id="mer_demo",
            payee_id="acq_demo_001",
            amount_minor=50000,
            currency="INR",
            checkout_hash="hash_02",
            rail="UPI",
            status="ISSUED",
            expires_at=old_time + timedelta(minutes=10),
            issued_at=old_time,
        )
    )

    reconciled = await orch.reconcile(timeout_threshold_seconds=15, session=db_session)

    assert len(reconciled) == 1
    assert reconciled[0].payment_id == "pay_upi_exp"
    assert reconciled[0].status == PaymentStatus.EXPIRED

    # Invariant: Spend released on established terminal failure
    assert "res_upi_exp" in mandate_client.released_reservations
    assert len(token_service.failed_tokens) == 1


@pytest.mark.anyio
async def test_reconciliation_idempotency(test_setup, db_session):
    """14. Repeated reconciliation passes are idempotent and do not duplicate commit/release."""
    orch: PaymentOrchestratorImpl = test_setup["orchestrator"]
    mandate_client: MockMandateClient = test_setup["mandate_client"]
    psp_client: MockPspClient = test_setup["psp_client"]

    psp_client.psp_status = "CAPTURED"

    old_time = datetime.now(UTC) - timedelta(seconds=45)
    db_session.add(
        PaymentModel(
            payment_id="pay_rec_idem",
            proposal_id="prop_rec_idem",
            token_id="ptok_rec_idem",
            rail="CARD",
            psp_payment_id="psp_rec_idem",
            status=PaymentStatus.UNKNOWN.value,
            amount_minor=100000,
            currency="INR",
            created_at=old_time,
            updated_at=old_time,
        )
    )
    db_session.add(
        PaymentTokenModel(
            token_id="ptok_rec_idem",
            proposal_id="prop_rec_idem",
            decision_id="dec_rec_idem",
            mandate_id="man_rec_idem",
            reservation_id="res_rec_idem",
            merchant_id="mer_demo",
            payee_id="acq_demo_001",
            amount_minor=100000,
            currency="INR",
            checkout_hash="hash_rec_idem",
            rail="CARD",
            status="REDEEMING",
            expires_at=old_time + timedelta(minutes=10),
            issued_at=old_time,
        )
    )

    # Pass 1
    rec1 = await orch.reconcile(timeout_threshold_seconds=15, session=db_session)
    assert len(rec1) == 1
    assert "res_rec_idem" in mandate_client.committed_reservations

    # Pass 2: should find 0 unresolved payments
    rec2 = await orch.reconcile(timeout_threshold_seconds=15, session=db_session)
    assert len(rec2) == 0

    # Ensure commit_spend was only called once
    assert mandate_client.committed_reservations.count("res_rec_idem") == 1


# =============================================================================
# END-TO-END INTEGRATION TEST WITH IN-PROCESS PSP ADAPTER
# =============================================================================


class DummyTokenClient(TokenClient):
    """In-memory TokenClient for MockPspService."""

    def __init__(self) -> None:
        pass

    async def redeem_token(self, req: Any) -> Any:
        return {"token_id": "ptok_e2e_001", "result": "ACCEPTED", "status": "REDEEMING"}


@pytest.mark.anyio
async def test_end_to_end_inprocess_psp_execution(webhook_keypair, db_session):
    """15. End-to-end payment execution using real InProcessPspClient and MockPspService."""
    # Setup Mock PSP in-memory database
    psp_engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        echo=False,
    )
    PspBase.metadata.create_all(psp_engine)
    PspSession = sessionmaker(bind=psp_engine)
    psp_sync_sess = PspSession()
    psp_session = AsyncSessionWrapper(psp_sync_sess)

    # Mock PSP Service
    psp_key_manager = PspKeyManager()
    psp_service = MockPspService(
        token_client=DummyTokenClient(),
        key_manager=psp_key_manager,
    )

    # Core verifier trusts Mock PSP public key
    verifier = PspWebhookVerifier()
    verifier.register_trusted_key(psp_key_manager.key_id, psp_key_manager.public_key)

    # InProcess PSP Client
    inprocess_client = InProcessPspClient(
        psp_service=psp_service,
        session_factory=lambda: psp_session,
    )

    decision_provider = MockDecisionProvider()
    mandate_client = MockMandateClient()
    grounding_client = MockGroundingClient()
    token_service = MockTokenService()

    orchestrator = PaymentOrchestratorImpl(
        decision_provider=decision_provider,
        token_service=token_service,
        mandate_client=mandate_client,
        grounding_client=grounding_client,
        psp_client=inprocess_client,
        webhook_verifier=verifier,
    )

    # Execute payment
    resp = await orchestrator.execute("prop_api_001", "idem_e2e_001", session=db_session)

    assert resp.status == PaymentStatus.CAPTURED
    assert resp.rail == PaymentRail.CARD
    assert resp.amount_minor == 100000
    assert resp.merchant_id == "mer_demo"
    assert "res_api_001" in mandate_client.committed_reservations
    assert len(token_service.redeemed_tokens) == 1
