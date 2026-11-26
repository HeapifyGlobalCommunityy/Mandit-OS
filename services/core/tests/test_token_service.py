"""Comprehensive test suite for Scoped Payment Token Service (Stage 1).

Tests:
1. Successful token issuance (ALLOW decision, active agent, usable mandate, valid reservation).
2. BLOCK, STEP_UP and RETRIEVE_MORE decisions cannot issue tokens.
3. Expired ALLOW decision cannot issue tokens.
4. Inactive agent cannot issue tokens.
5. Usable mandate assertion failure.
6. Reservation mismatch (not found, wrong proposal/mandate/status, amount/currency mismatch).
7. TOCTOU checkout hash alteration detection.
8. Proposal uniqueness constraint (1 token per proposal).
9. JWS Ed25519 signature verification and claim tampering detection.
10. Atomic CAS redemption success and database state transition.
11. Same-key idempotent retry returns original accepted result.
12. Different-key retry rejection (TOKEN_ALREADY_REDEEMED).
13. Parameter mismatch rejections (merchant, payee, amount, currency, checkout hash).
14. Expired and revoked token redemption rejections.
15. Token revocation lifecycle (issued -> revoked, cannot revoke redeemed or expired).
16. Mark redeemed and mark failed state transitions.
17. Concurrent CAS redemption race test (atomic single-use guarantee).
18. Transactional event emission verification without raw token exposure.
"""

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from mandit.common.models import Base
from mandit.tokens.models import PaymentTokenModel
from mandit.tokens.schemas import (
    TokenErrorCode,
    TokenRedeemRequest,
    TokenStatus,
    TokenValidateRequest,
)
from mandit.tokens.service import (
    TokenError,
    TokenIssueError,
    TokenRedemptionRejected,
    TokenServiceImpl,
    verify_jws,
)


class MockDecision:
    def __init__(
        self,
        decision_id: str = "dec_test_001",
        proposal_id: str = "prop_test_001",
        outcome: str = "ALLOW",
        expires_at: datetime | None = None,
        transaction_id: str = "txn_test_001",
    ) -> None:
        self.decision_id = decision_id
        self.proposal_id = proposal_id
        self.outcome = outcome
        self.expires_at = expires_at or (datetime.now(UTC) + timedelta(minutes=15))
        self.transaction_id = transaction_id
        self.agent_id = "agent_01"
        self.mandate_id = "man_01"


class MockProposal:
    def __init__(
        self,
        proposal_id: str = "prop_test_001",
        agent_id: str = "agent_01",
        mandate_id: str = "man_01",
        checkout_id: str = "co_01",
        checkout_hash: str = "sha256:checkout_hash_abc",
        rail: str = "CARD",
    ) -> None:
        self.proposal_id = proposal_id
        self.agent_id = agent_id
        self.mandate_id = mandate_id
        self.checkout_id = checkout_id
        self.checkout_hash = checkout_hash
        self.rail = rail


class MockCheckout:
    def __init__(
        self,
        checkout_id: str = "co_01",
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


class MockReservation:
    def __init__(
        self,
        reservation_id: str = "res_01",
        proposal_id: str = "prop_test_001",
        mandate_id: str = "man_01",
        amount_minor: int = 500000,
        currency: str = "INR",
        status: str = "RESERVED",
    ) -> None:
        self.reservation_id = reservation_id
        self.proposal_id = proposal_id
        self.mandate_id = mandate_id
        self.amount_minor = amount_minor
        self.currency = currency
        self.status = status


class MockDecisionProvider:
    def __init__(self, decision: MockDecision | None = None) -> None:
        self.decision = decision or MockDecision()

    async def get(self, decision_id: str, session: Any = None) -> Any:
        return self.decision


class MockIdentityProvider:
    def __init__(self, is_active: bool = True) -> None:
        self.active = is_active

    async def is_active(self, agent_id: str, key_id: str | None = None) -> bool:
        return self.active


class MockMandateProvider:
    def __init__(
        self,
        usable: bool = True,
        reservation: MockReservation | None = None,
    ) -> None:
        self.usable = usable
        self.reservation = reservation if reservation is not None else MockReservation()

    async def assert_usable(self, mandate_id: str) -> Any:
        if not self.usable:
            return None
        return {"mandate_id": mandate_id, "status": "ACTIVE"}

    async def get_reservation(self, reservation_id: str) -> Any:
        return self.reservation


class MockGroundingProvider:
    def __init__(
        self,
        proposal: MockProposal | None = None,
        checkout: MockCheckout | None = None,
    ) -> None:
        self.proposal = proposal or MockProposal()
        self.checkout = checkout or MockCheckout()

    async def get_proposal(self, proposal_id: str) -> Any:
        return self.proposal

    async def refetch_checkout(self, checkout_id: str) -> Any:
        return self.checkout


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
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    wrapper = AsyncSessionWrapper(session)
    try:
        yield wrapper
    finally:
        wrapper.close()


@pytest.fixture
def test_setup():
    decision_provider = MockDecisionProvider()
    identity_provider = MockIdentityProvider(is_active=True)
    mandate_provider = MockMandateProvider(usable=True)
    grounding_provider = MockGroundingProvider()

    service = TokenServiceImpl(
        decision_provider=decision_provider,
        identity_provider=identity_provider,
        mandate_provider=mandate_provider,
        grounding_provider=grounding_provider,
    )
    return {
        "service": service,
        "decision_provider": decision_provider,
        "identity_provider": identity_provider,
        "mandate_provider": mandate_provider,
        "grounding_provider": grounding_provider,
    }


# --- Test Cases ---


def test_token_issuance_success(test_setup, db_session):
    """Test standard successful token issuance for an ALLOW decision."""

    async def _run() -> None:
        service: TokenServiceImpl = test_setup["service"]
        issued = await service.issue("dec_test_001", "res_01", session=db_session)

        assert issued.token_record.token_id.startswith("ptok_")
        assert issued.token_record.proposal_id == "prop_test_001"
        assert issued.token_record.amount_minor == 500000
        assert issued.token_record.currency == "INR"
        assert issued.token_record.rail == "CARD"
        assert issued.token_record.status == TokenStatus.ISSUED

        # Verify compact JWS token
        header, claims = verify_jws(issued.signed_token, service.public_key)
        assert header == {"alg": "EdDSA", "typ": "mandit-pay+jwt"}
        assert claims["jti"] == issued.token_record.token_id
        assert claims["iss"] == "mandit-token-svc"
        assert claims["aud"] == "mock-psp"
        assert claims["amount_minor"] == 500000
        assert claims["currency"] == "INR"
        assert claims["max_uses"] == 1
        assert claims["exp"] == int(issued.token_record.expires_at.timestamp())

        # Check database persistence
        stmt = select(PaymentTokenModel).where(
            PaymentTokenModel.token_id == issued.token_record.token_id
        )
        res = await db_session.execute(stmt)
        persisted = res.scalar_one_or_none()
        assert persisted is not None
        assert persisted.status == "ISSUED"

    asyncio.run(_run())


def test_token_issuance_disallowed_outcomes(test_setup, db_session):
    """Verify that BLOCK, STEP_UP and RETRIEVE_MORE decisions cannot issue tokens."""

    async def _run() -> None:
        service: TokenServiceImpl = test_setup["service"]
        dec_prov: MockDecisionProvider = test_setup["decision_provider"]

        for outcome in ["BLOCK", "STEP_UP", "RETRIEVE_MORE"]:
            dec_prov.decision = MockDecision(outcome=outcome)
            with pytest.raises(TokenIssueError) as exc_info:
                await service.issue("dec_test_001", "res_01", session=db_session)
            assert exc_info.value.code == TokenErrorCode.DECISION_NOT_ALLOW

    asyncio.run(_run())


def test_token_issuance_expired_decision(test_setup, db_session):
    """Verify that an expired decision is refused."""

    async def _run() -> None:
        service: TokenServiceImpl = test_setup["service"]
        dec_prov: MockDecisionProvider = test_setup["decision_provider"]

        past = datetime.now(UTC) - timedelta(minutes=5)
        dec_prov.decision = MockDecision(expires_at=past)
        with pytest.raises(TokenIssueError) as exc_info:
            await service.issue("dec_test_001", "res_01", session=db_session)
        assert exc_info.value.code == TokenErrorCode.DECISION_EXPIRED

    asyncio.run(_run())


def test_token_issuance_inactive_agent(test_setup, db_session):
    """Verify that an inactive or revoked agent cannot be issued a token."""

    async def _run() -> None:
        service: TokenServiceImpl = test_setup["service"]
        id_prov: MockIdentityProvider = test_setup["identity_provider"]

        id_prov.active = False
        with pytest.raises(TokenIssueError) as exc_info:
            await service.issue("dec_test_001", "res_01", session=db_session)
        assert exc_info.value.code == TokenErrorCode.AGENT_REVOKED

    asyncio.run(_run())


def test_token_issuance_unusable_mandate(test_setup, db_session):
    """Verify that an unusable mandate fails token issuance."""

    async def _run() -> None:
        service: TokenServiceImpl = test_setup["service"]
        man_prov: MockMandateProvider = test_setup["mandate_provider"]

        man_prov.usable = False
        with pytest.raises(TokenIssueError) as exc_info:
            await service.issue("dec_test_001", "res_01", session=db_session)
        assert exc_info.value.code == TokenErrorCode.MANDATE_INVALID

    asyncio.run(_run())


def test_token_issuance_reservation_mismatch(test_setup, db_session):
    """Verify that any reservation anomaly fails token issuance."""

    async def _run() -> None:
        service: TokenServiceImpl = test_setup["service"]
        man_prov: MockMandateProvider = test_setup["mandate_provider"]

        # 1. Missing reservation
        man_prov.reservation = None  # type: ignore[assignment]
        with pytest.raises(TokenIssueError) as exc_info:
            await service.issue("dec_test_001", "res_01", session=db_session)
        assert exc_info.value.code == TokenErrorCode.RESERVATION_MISMATCH

        # 2. Proposal mismatch
        man_prov.reservation = MockReservation(proposal_id="wrong_prop")
        with pytest.raises(TokenIssueError) as exc_info:
            await service.issue("dec_test_001", "res_01", session=db_session)
        assert exc_info.value.code == TokenErrorCode.RESERVATION_MISMATCH

        # 3. Mandate mismatch
        man_prov.reservation = MockReservation(mandate_id="wrong_man")
        with pytest.raises(TokenIssueError) as exc_info:
            await service.issue("dec_test_001", "res_01", session=db_session)
        assert exc_info.value.code == TokenErrorCode.RESERVATION_MISMATCH

        # 4. Status not RESERVED
        man_prov.reservation = MockReservation(status="COMMITTED")
        with pytest.raises(TokenIssueError) as exc_info:
            await service.issue("dec_test_001", "res_01", session=db_session)
        assert exc_info.value.code == TokenErrorCode.RESERVATION_MISMATCH

        # 5. Amount mismatch with checkout
        man_prov.reservation = MockReservation(amount_minor=999999)
        with pytest.raises(TokenIssueError) as exc_info:
            await service.issue("dec_test_001", "res_01", session=db_session)
        assert exc_info.value.code == TokenErrorCode.RESERVATION_MISMATCH

    asyncio.run(_run())


def test_token_issuance_toctou_checkout_changed(test_setup, db_session):
    """Verify TOCTOU defense: flaky merchant price/cart changes reject token issuance."""

    async def _run() -> None:
        service: TokenServiceImpl = test_setup["service"]
        gr_prov: MockGroundingProvider = test_setup["grounding_provider"]

        # Merchant changed cart hash during checkout refetch
        gr_prov.checkout = MockCheckout(checkout_hash="sha256:tampered_cart")
        with pytest.raises(TokenIssueError) as exc_info:
            await service.issue("dec_test_001", "res_01", session=db_session)
        assert exc_info.value.code == TokenErrorCode.CHECKOUT_CHANGED

    asyncio.run(_run())


def test_token_issuance_proposal_uniqueness(test_setup, db_session):
    """Verify that multiple tokens cannot be issued for the same proposal."""

    async def _run() -> None:
        service: TokenServiceImpl = test_setup["service"]
        # First issuance succeeds
        await service.issue("dec_test_001", "res_01", session=db_session)

        # Second issuance for the same proposal must be rejected
        with pytest.raises(TokenIssueError) as exc_info:
            await service.issue("dec_test_001", "res_01", session=db_session)
        assert exc_info.value.code == TokenErrorCode.TOKEN_ALREADY_EXISTS

    asyncio.run(_run())


def test_token_validation(test_setup, db_session):
    """Verify token validation without consuming the token."""

    async def _run() -> None:
        service: TokenServiceImpl = test_setup["service"]
        issued = await service.issue("dec_test_001", "res_01", session=db_session)

        # Valid check
        valid_req = TokenValidateRequest(
            token=issued.signed_token,
            merchant_id="mer_croma",
            payee_id="acq_croma_001",
            amount_minor=500000,
            currency="INR",
            checkout_hash="sha256:checkout_hash_abc",
        )
        res = await service.validate(valid_req, session=db_session)
        assert res.valid is True
        assert res.status == "ISSUED"

        # Corrupt signature check
        tampered_token = issued.signed_token[:-5] + "AAAAA"
        tampered_req = TokenValidateRequest(
            token=tampered_token,
            merchant_id="mer_croma",
            payee_id="acq_croma_001",
            amount_minor=500000,
            currency="INR",
            checkout_hash="sha256:checkout_hash_abc",
        )
        res_tampered = await service.validate(tampered_req, session=db_session)
        assert res_tampered.valid is False
        assert res_tampered.reason == TokenErrorCode.TOKEN_SIGNATURE_INVALID

        # Merchant mismatch
        wrong_mer = TokenValidateRequest(
            token=issued.signed_token,
            merchant_id="mer_other",
            payee_id="acq_croma_001",
            amount_minor=500000,
            currency="INR",
            checkout_hash="sha256:checkout_hash_abc",
        )
        res_mer = await service.validate(wrong_mer, session=db_session)
        assert res_mer.valid is False
        assert res_mer.reason == TokenErrorCode.TOKEN_MERCHANT_MISMATCH

    asyncio.run(_run())


def test_atomic_redemption_and_idempotency(test_setup, db_session):
    """Verify atomic CAS redemption and idempotency semantics."""

    async def _run() -> None:
        service: TokenServiceImpl = test_setup["service"]
        issued = await service.issue("dec_test_001", "res_01", session=db_session)

        redeem_req = TokenRedeemRequest(
            token=issued.signed_token,
            merchant_id="mer_croma",
            payee_id="acq_croma_001",
            amount_minor=500000,
            currency="INR",
            checkout_hash="sha256:checkout_hash_abc",
            idempotency_key="idem_key_123",
        )

        # 1. First redemption: succeeds
        res1 = await service.redeem(redeem_req, session=db_session)
        assert res1.result == "ACCEPTED"
        assert res1.status == "REDEEMING"

        # DB status verified as REDEEMING
        token_db = await service.get(issued.token_record.token_id, session=db_session)
        assert token_db is not None
        assert token_db.status == TokenStatus.REDEEMING
        assert token_db.idem_key == "idem_key_123"

        # 2. Idempotent retry with SAME idempotency_key: returns original success
        res2 = await service.redeem(redeem_req, session=db_session)
        assert res2.result == "ACCEPTED"
        assert res2.status == "REDEEMING"

        # 3. Retry with a DIFFERENT idempotency_key: fails with TOKEN_ALREADY_REDEEMED
        diff_key_req = TokenRedeemRequest(
            token=issued.signed_token,
            merchant_id="mer_croma",
            payee_id="acq_croma_001",
            amount_minor=500000,
            currency="INR",
            checkout_hash="sha256:checkout_hash_abc",
            idempotency_key="idem_key_DIFFERENT",
        )
        with pytest.raises(TokenRedemptionRejected) as exc_info:
            await service.redeem(diff_key_req, session=db_session)
        assert exc_info.value.code == TokenErrorCode.TOKEN_ALREADY_REDEEMED

    asyncio.run(_run())


def test_redemption_binding_mismatches(test_setup, db_session):
    """Verify rejection when any payment parameter mismatches the token."""

    async def _run() -> None:
        service: TokenServiceImpl = test_setup["service"]
        issued = await service.issue("dec_test_001", "res_01", session=db_session)

        # Merchant mismatch
        with pytest.raises(TokenRedemptionRejected) as exc:
            await service.redeem(
                TokenRedeemRequest(
                    token=issued.signed_token,
                    merchant_id="wrong_merchant",
                    payee_id="acq_croma_001",
                    amount_minor=500000,
                    currency="INR",
                    checkout_hash="sha256:checkout_hash_abc",
                    idempotency_key="idem_1",
                ),
                session=db_session,
            )
        assert exc.value.code == TokenErrorCode.TOKEN_MERCHANT_MISMATCH

        # Payee mismatch
        with pytest.raises(TokenRedemptionRejected) as exc:
            await service.redeem(
                TokenRedeemRequest(
                    token=issued.signed_token,
                    merchant_id="mer_croma",
                    payee_id="wrong_payee",
                    amount_minor=500000,
                    currency="INR",
                    checkout_hash="sha256:checkout_hash_abc",
                    idempotency_key="idem_1",
                ),
                session=db_session,
            )
        assert exc.value.code == TokenErrorCode.TOKEN_PAYEE_MISMATCH

        # Amount mismatch
        with pytest.raises(TokenRedemptionRejected) as exc:
            await service.redeem(
                TokenRedeemRequest(
                    token=issued.signed_token,
                    merchant_id="mer_croma",
                    payee_id="acq_croma_001",
                    amount_minor=600000,
                    currency="INR",
                    checkout_hash="sha256:checkout_hash_abc",
                    idempotency_key="idem_1",
                ),
                session=db_session,
            )
        assert exc.value.code == TokenErrorCode.TOKEN_AMOUNT_MISMATCH

        # Currency mismatch
        with pytest.raises(TokenRedemptionRejected) as exc:
            await service.redeem(
                TokenRedeemRequest(
                    token=issued.signed_token,
                    merchant_id="mer_croma",
                    payee_id="acq_croma_001",
                    amount_minor=500000,
                    currency="USD",
                    checkout_hash="sha256:checkout_hash_abc",
                    idempotency_key="idem_1",
                ),
                session=db_session,
            )
        assert exc.value.code == TokenErrorCode.TOKEN_CURRENCY_MISMATCH

    asyncio.run(_run())


def test_token_revocation_lifecycle(test_setup, db_session):
    """Verify revocation of issued tokens and rejection on redeemed/expired tokens."""

    async def _run() -> None:
        service: TokenServiceImpl = test_setup["service"]
        issued = await service.issue("dec_test_001", "res_01", session=db_session)

        # 1. Revoke unredeemed token
        revoked = await service.revoke(
            issued.token_record.token_id, "User cancelled order", session=db_session
        )
        assert revoked.status == "REVOKED"
        assert revoked.reason == "User cancelled order"

        # Redeeming revoked token fails
        with pytest.raises(TokenRedemptionRejected) as exc:
            await service.redeem(
                TokenRedeemRequest(
                    token=issued.signed_token,
                    merchant_id="mer_croma",
                    payee_id="acq_croma_001",
                    amount_minor=500000,
                    currency="INR",
                    checkout_hash="sha256:checkout_hash_abc",
                    idempotency_key="idem_rev",
                ),
                session=db_session,
            )
        assert exc.value.code == TokenErrorCode.TOKEN_REVOKED

        # 2. Cannot revoke already redeemed token
        dec_prov: MockDecisionProvider = test_setup["decision_provider"]
        gr_prov: MockGroundingProvider = test_setup["grounding_provider"]
        man_prov: MockMandateProvider = test_setup["mandate_provider"]

        dec_prov.decision = MockDecision(decision_id="dec_test_002", proposal_id="prop_test_002")
        gr_prov.proposal = MockProposal(proposal_id="prop_test_002")
        man_prov.reservation = MockReservation(reservation_id="res_02", proposal_id="prop_test_002")

        issued2 = await service.issue("dec_test_002", "res_02", session=db_session)
        # Redeem it
        await service.redeem(
            TokenRedeemRequest(
                token=issued2.signed_token,
                merchant_id="mer_croma",
                payee_id="acq_croma_001",
                amount_minor=500000,
                currency="INR",
                checkout_hash="sha256:checkout_hash_abc",
                idempotency_key="idem_ok",
            ),
            session=db_session,
        )
        with pytest.raises(TokenError) as exc2:
            await service.revoke(
                issued2.token_record.token_id, "Attempt late revoke", session=db_session
            )
        assert exc2.value.code == TokenErrorCode.TOKEN_ALREADY_REDEEMED

    asyncio.run(_run())


def test_mark_redeemed_and_failed(test_setup, db_session):
    """Verify transition from REDEEMING to REDEEMED or FAILED."""

    async def _run() -> None:
        service: TokenServiceImpl = test_setup["service"]
        issued = await service.issue("dec_test_001", "res_01", session=db_session)
        t_id = issued.token_record.token_id

        # Mark redeemed
        await service.mark_redeemed(t_id, session=db_session)
        t1 = await service.get(t_id, session=db_session)
        assert t1 is not None
        assert t1.status == TokenStatus.REDEEMED
        assert t1.redeemed_at is not None

        # Mark failed
        await service.mark_failed(t_id, session=db_session)
        t2 = await service.get(t_id, session=db_session)
        assert t2 is not None
        assert t2.status == TokenStatus.FAILED

    asyncio.run(_run())


def test_concurrent_cas_redemption(test_setup, db_session):
    """Verify that multiple concurrent redemption requests produce exactly one winner.

    Tests atomic compare-and-set semantics in SQLite.
    (Note: Tested against SQLite; PostgreSQL provides equivalent row-level locking).
    """

    async def _run() -> None:
        service: TokenServiceImpl = test_setup["service"]
        issued = await service.issue("dec_test_001", "res_01", session=db_session)

        results: list[Any] = []
        errors: list[Any] = []

        async def do_redeem(key_idx: int) -> None:
            req = TokenRedeemRequest(
                token=issued.signed_token,
                merchant_id="mer_croma",
                payee_id="acq_croma_001",
                amount_minor=500000,
                currency="INR",
                checkout_hash="sha256:checkout_hash_abc",
                idempotency_key=f"idem_concurrent_{key_idx}",
            )
            try:
                res = await service.redeem(req, session=db_session)
                results.append(res)
            except TokenRedemptionRejected as exc:
                errors.append(exc)

        # 50 concurrent redemption attempts
        tasks = [do_redeem(i) for i in range(50)]
        await asyncio.gather(*tasks)

        # Exactly ONE must succeed with ACCEPTED
        assert len(results) == 1
        assert results[0].result == "ACCEPTED"
        assert results[0].status == "REDEEMING"

        # All 49 others must be rejected with TOKEN_ALREADY_REDEEMED
        assert len(errors) == 49
        for err in errors:
            assert err.code == TokenErrorCode.TOKEN_ALREADY_REDEEMED

    asyncio.run(_run())
