"""Comprehensive test suite for Human Confirmation Service (Stage 4).

Tests:
1. Valid approval and successful policy re-evaluation (ALLOW, stage=CONFIRMATION, events).
2. Valid rejection (REJECTED, event).
3. Invalid signature (SignatureInvalidError).
4. Incorrect challenge (ChallengeMismatchError).
5. Expired confirmation (ConfirmationExpiredError, EXPIRED state, CONFIRMATION_EXPIRED event).
6. Wrong user attempting approval (ConfirmationOwnershipError).
7. Revoked or inactive signing key (UserKeyInvalidError).
8. Changed proposal hash (TOCTOU invalidation, CONFIRMATION_INVALIDATED event).
9. Expired checkout (TOCTOU invalidation, CONFIRMATION_INVALIDATED event).
10. Duplicate approval request (ConfirmationNotPendingError).
11. Approval after rejection (ConfirmationNotPendingError).
12. Approval after expiry (ConfirmationExpiredError).
13. Concurrency safety (atomic CAS ensures only one request succeeds).
14. Hard-gate BLOCK cannot be overridden by human approval (Invariant INV-07).
15. Correct event emission across all lifecycle transitions.
16. Transaction rollback consistency.
"""
import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from mandit.common import events, hashing
from mandit.common.crypto import b64url_encode
from mandit.common.models import Base
from mandit.confirmation.schemas import (
    ChallengeMismatchError,
    ConfirmationExpiredError,
    ConfirmationInvalidatedError,
    ConfirmationNotFoundError,
    ConfirmationNotPendingError,
    ConfirmationOwnershipError,
    ConfirmationRespondRequest,
    SignatureInvalidError,
    UserKeyInvalidError,
    UserKeyRecord,
)
from mandit.confirmation.service import ConfirmationServiceImpl
from mandit.policy.models import ConfirmationModel, DecisionModel
from mandit.policy.repository import DecisionRepository
from mandit.policy.schemas import (
    AgentContext,
    CalculationResult,
    CheckoutSnapshot,
    DecisionOutcome,
    EvaluationStage,
    FrozenDecisionInputs,
    IdentityResult,
    MandateConstraints,
    MandateMatchResult,
    MandateSnapshot,
    RiskSummary,
    SelectionResult,
    TrustResult,
    VerificationReport,
)
from mandit.policy.service import (
    DecisionServiceImpl,
    DefaultPolicyEngine,
    build_display_payload,
)


class InMemoryUserKeyService:
    """In-memory UserKeyService for tests."""

    def __init__(self) -> None:
        self.keys: dict[str, UserKeyRecord] = {}

    def add_key(self, key: UserKeyRecord) -> None:
        self.keys[key.key_id] = key

    async def get_key(self, key_id: str) -> UserKeyRecord | None:
        return self.keys.get(key_id)

    async def get_active_key(self, user_id: str) -> UserKeyRecord | None:
        for k in self.keys.values():
            if k.user_id == user_id and k.status == "ACTIVE":
                return k
        return None


class MockGroundingService:
    """Mock GroundingService for tests."""

    def __init__(self, proposal_hash: str, checkout: CheckoutSnapshot) -> None:
        self.proposal_hash = proposal_hash
        self.checkout = checkout

    async def get_proposal(self, proposal_id: str) -> Any:
        class Prop:
            def __init__(self, p_hash: str):
                self.proposal_hash = p_hash
                self.transaction_id = f"txn_{proposal_id}"
                self.mandate_id = "man_test_01"
                self.agent_id = "agent_test_01"
                self.payment_method = "CARD_TOKEN"
        return Prop(self.proposal_hash)

    async def latest_verification(self, proposal_id: str) -> VerificationReport:
        calc = CalculationResult(
            computed_total_minor=self.checkout.amount_minor,
            merchant_total_minor=self.checkout.amount_minor,
            agent_stated_total_minor=self.checkout.amount_minor,
            reconciled=True,
            calculator_version="calc-1.0.0",
            subtotal_minor=self.checkout.amount_minor,
        )
        return VerificationReport(
            verification_id=f"ver_{proposal_id}",
            proposal_id=proposal_id,
            proposal_hash=self.proposal_hash,
            attempt=1,
            checkout=self.checkout,
            calculation=calc,
            mandate_match=MandateMatchResult(satisfied=True, violations=(), signals=()),
            selection=SelectionResult(pricier_alternative_chosen=False),
            trust=TrustResult(
                score=0.85,
                band="STEP_UP",
                components={"G": 0.85},
                weights={"G": 1.0},
                trust_model_version="trust-1.0.0",
            ),
        )


def generate_test_user_key(user_id: str = "usr_harsh_01", key_id: str = "ukey_01JD3Z0000DEMOUSERKEY0001", status: str = "ACTIVE") -> tuple[ec.EllipticCurvePrivateKey, UserKeyRecord]:
    """Generate a test ECDSA P-256 key pair and corresponding UserKeyRecord."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_numbers = private_key.public_key().public_numbers()
    x_bytes = public_numbers.x.to_bytes(32, "big")
    y_bytes = public_numbers.y.to_bytes(32, "big")

    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": b64url_encode(x_bytes),
        "y": b64url_encode(y_bytes),
    }
    record = UserKeyRecord(
        key_id=key_id,
        user_id=user_id,
        alg="ES256",
        jwk=jwk,
        status=status,  # type: ignore[arg-type]
        created_at=datetime.now(timezone.utc),
    )
    return private_key, record


def sign_challenge_es256(private_key: ec.EllipticCurvePrivateKey, key_id: str, challenge: str) -> dict[str, str]:
    """Sign challenge string using ES256 and return canonical signature envelope."""
    # Signs UTF-8 bytes of challenge using ECDSA P-256 / SHA-256
    sig_bytes = private_key.sign(challenge.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
    return {
        "alg": "ES256",
        "key_id": key_id,
        "signed_digest": challenge,
        "value": b64url_encode(sig_bytes),
    }


@pytest.fixture
def db_session():
    """Create in-memory SQLite database and return a session."""
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture(autouse=True)
def clear_events():
    events._default_emitter.clear()
    yield
    events._default_emitter.clear()


@pytest.fixture
def test_setup():
    """Setup base models, services, user keys, and confirmation row."""
    now = datetime(2026, 11, 24, 12, 0, 0, tzinfo=timezone.utc)
    future = now + timedelta(days=7)
    user_id = "usr_harsh_01"
    key_id = "ukey_01JD3Z0000DEMOUSERKEY0001"
    proposal_id = "prop_01JD4300000000000000000001"
    proposal_hash = "sha256:7ab2croma0000000000000000000000000000000000000000000000000000000"
    confirmation_id = "cnf_01JD4900000000000000000001"
    initial_decision_id = "dec_01JD4800000000000000000001"

    priv_key, user_key_record = generate_test_user_key(user_id=user_id, key_id=key_id)
    user_key_service = InMemoryUserKeyService()
    user_key_service.add_key(user_key_record)

    checkout = CheckoutSnapshot(
        checkout_id="chk_01JD4800000000000000000001",
        checkout_hash=proposal_hash,
        merchant_id="mer_croma_01",
        merchant_domain="croma.example.com",
        payee_id="payee_croma_corp",
        amount_minor=6482966,
        currency="INR",
        merchant_signature_valid=True,
        expires_at=future,
    )
    grounding_service = MockGroundingService(proposal_hash=proposal_hash, checkout=checkout)

    # Initial inputs
    agent = AgentContext(
        agent_id="agent_shopping_01",
        operator_id="op_acme_corp",
        key_id="key_agent_ed25519_01",
        key_thumbprint="kth_thumbprint_base64url",
        scopes=frozenset({"purchase:propose", "purchase:execute"}),
        credential_id="kya_credential_jwt_01",
        verified_at=now - timedelta(minutes=5),
    )
    identity = IdentityResult(agent=agent, is_active=True, operator_verified=True, kya_token_valid=True, key_bound=True)
    constraints = MandateConstraints(
        allowed_merchants=("mer_croma_demo", "mer_croma_01"),
        allowed_domains=("croma.mock.mandit.local", "croma.example.com"),
        allowed_categories=("electronics.laptops", "electronics"),
        currency="INR",
        max_amount_per_txn_minor=8000000,
        max_amount_total_minor=10000000,
        max_txn_count=5,
        approval_threshold_minor=5000000,  # Below 6,482,966 -> triggers SU-01
        payment_methods=("CARD_TOKEN", "UPI"),
    )
    mandate = MandateSnapshot(
        mandate_id="man_01JD3Y00000000000000000001",
        version=1,
        user_id=user_id,
        agent_id="agent_shopping_01",
        agent_key_thumbprint="kth_thumbprint_base64url",
        constraints=constraints,
        not_before=now - timedelta(days=1),
        expires_at=future,
        status="ACTIVE",
        spent_minor=1000000,
        spend_count=1,
    )
    risk = RiskSummary(
        merchant_domain="croma.example.com",
        site_risk_score=0.05,
        site_risk_level="LOW",
        max_injection_severity="NONE",
        injection_content_ids=(),
        signals=(),
        scanner_version="scanner-1.0.0",
    )
    calc = CalculationResult(
        computed_total_minor=6482966,
        merchant_total_minor=6482966,
        agent_stated_total_minor=6482966,
        reconciled=True,
        calculator_version="calc-1.0.0",
        subtotal_minor=5500000,
        tax_minor=982966,
    )
    verif = VerificationReport(
        verification_id="ver_01JD4700000000000000000001",
        proposal_id=proposal_id,
        proposal_hash=proposal_hash,
        attempt=1,
        checkout=checkout,
        calculation=calc,
        mandate_match=MandateMatchResult(satisfied=True, violations=(), signals=()),
        selection=SelectionResult(pricier_alternative_chosen=False),
        trust=TrustResult(
            score=0.95,
            band="ALLOW",
            components={"G": 1.0},
            weights={"G": 1.0},
            trust_model_version="trust-1.0.0",
        ),
    )

    inputs = FrozenDecisionInputs(
        evaluated_at=now,
        attempt=1,
        proposal_id=proposal_id,
        proposal_hash=proposal_hash,
        transaction_id="txn_01JD3Y9X000000000000000001",
        identity=identity,
        mandate=mandate,
        risk=risk,
        verification=verif,
        user_merchant_history=3,
        payment_method="CARD_TOKEN",
        confirmation=None,
    )

    display = build_display_payload(inputs, ())
    expires_at = now + timedelta(minutes=10)
    # Strictly 4 canonical fields: confirmation_id, display, expires_at, proposal_hash
    challenge = hashing.digest({
        "confirmation_id": confirmation_id,
        "display": display,
        "expires_at": expires_at.isoformat(),
        "proposal_hash": proposal_hash,
    })

    conf_model = ConfirmationModel(
        confirmation_id=confirmation_id,
        decision_id=initial_decision_id,
        proposal_id=proposal_id,
        proposal_hash=proposal_hash,
        user_id=user_id,
        display=display,
        challenge=challenge,
        status="PENDING",
        response_signature=None,
        responded_at=None,
        expires_at=expires_at,
    )

    # Initial decision record
    initial_decision = DecisionModel(
        decision_id=initial_decision_id,
        proposal_id=proposal_id,
        proposal_hash=proposal_hash,
        transaction_id="txn_01JD3Y9X000000000000000001",
        attempt=1,
        outcome="STEP_UP",
        stage="RULE",
        rules_fired=[{"rule_id": "SU-01", "code": "ABOVE_APPROVAL_THRESHOLD", "effect": "STEP_UP"}],
        trust_score=0.95,
        policy_version="policy-1.0.0",
        trust_model_version="trust-1.0.0",
        inputs_snapshot_id="snp_01JD4800000000000000000001",
        inputs_hash="sha256:inputs_hash_01",
        confirmation_id=confirmation_id,
        expires_at=expires_at,
        signature={"alg": "Ed25519", "key_id": "mandit-policy-2026-11", "signed_digest": "sha256:d", "value": "val"},
        created_at=now,
    )

    class MockIdentityService:
        async def get_identity_result(self, p_id: str):
            return identity

    class MockMandateService:
        async def get(self, m_id: str):
            return mandate

    class MockSafetyService:
        async def get_risk_summary(self, p_id: str):
            return risk

    class MockUserHistoryService:
        async def get_user_merchant_history(self, u_id: str, m_id: str):
            return 3

    repo = DecisionRepository()
    engine = DefaultPolicyEngine()
    decision_service = DecisionServiceImpl(
        engine=engine,
        repository=repo,
        grounding_service=grounding_service,
        identity_service=MockIdentityService(),
        mandate_service=MockMandateService(),
        safety_service=MockSafetyService(),
        user_history_service=MockUserHistoryService(),
    )

    confirmation_service = ConfirmationServiceImpl(
        repository=repo,
        decision_service=decision_service,
        grounding_service=grounding_service,
        user_key_service=user_key_service,
        now_fn=lambda: now,
    )

    return {
        "now": now,
        "user_id": user_id,
        "key_id": key_id,
        "priv_key": priv_key,
        "user_key_record": user_key_record,
        "user_key_service": user_key_service,
        "grounding_service": grounding_service,
        "decision_service": decision_service,
        "confirmation_service": confirmation_service,
        "repo": repo,
        "conf_model": conf_model,
        "initial_decision": initial_decision,
        "challenge": challenge,
        "confirmation_id": confirmation_id,
        "initial_decision_id": initial_decision_id,
    }


def test_valid_approval_and_policy_reevaluation(db_session, test_setup):
    """Test 1: Valid approval produces ALLOW decision, stage=CONFIRMATION, events, and preserves initial decision."""
    async def _run():
        s = test_setup
        repo: DecisionRepository = s["repo"]
        conf_svc: ConfirmationServiceImpl = s["confirmation_service"]

        # Persist initial records
        await repo.save_confirmation(db_session, s["conf_model"])
        await repo.save_decision(db_session, s["initial_decision"])

        # Sign challenge with valid ES256 key
        sig = sign_challenge_es256(s["priv_key"], s["key_id"], s["challenge"])
        req = ConfirmationRespondRequest(response="APPROVE", signature=sig)

        res = await conf_svc.respond(db_session, s["confirmation_id"], s["user_id"], req)

        # 1. Assertions on Response
        assert res.confirmation_id == s["confirmation_id"]
        assert res.status == "APPROVED"
        assert res.decision_id is not None
        assert res.decision_id != s["initial_decision_id"]  # Brand new decision created
        assert res.outcome == "ALLOW"

        # 2. Confirmation row in DB is APPROVED
        updated_conf = await repo.get_confirmation(db_session, s["confirmation_id"])
        assert updated_conf is not None
        assert updated_conf.status == "APPROVED"
        assert updated_conf.response_signature == sig
        assert updated_conf.responded_at is not None

        # 3. New Decision row in DB has stage=CONFIRMATION and outcome=ALLOW
        new_dec = await repo.get_decision(db_session, res.decision_id)
        assert new_dec is not None
        assert new_dec.outcome == "ALLOW"
        assert new_dec.stage == "CONFIRMATION"

        # 4. Initial Decision record is preserved unchanged (immutable history)
        orig_dec = await repo.get_decision(db_session, s["initial_decision_id"])
        assert orig_dec is not None
        assert orig_dec.outcome == "STEP_UP"
        assert orig_dec.stage == "RULE"

        # 5. Events emitted: CONFIRMATION_APPROVED and DECISION_MADE
        emitted = events._default_emitter.emitted_events
        types = [e["event_type"] for e in emitted]
        assert "CONFIRMATION_APPROVED" in types
        assert "DECISION_MADE" in types

        conf_evt = next(e for e in emitted if e["event_type"] == "CONFIRMATION_APPROVED")
        assert conf_evt["refs"]["confirmation_id"] == s["confirmation_id"]
        assert conf_evt["refs"]["user_id"] == s["user_id"]
        assert conf_evt["payload"]["challenge"] == s["challenge"]
        assert conf_evt["payload"]["key_id"] == s["key_id"]

        dec_evt = next(e for e in emitted if e["event_type"] == "DECISION_MADE")
        assert dec_evt["payload"]["outcome"] == "ALLOW"
        assert dec_evt["payload"]["stage"] == "CONFIRMATION"

    asyncio.run(_run())


def test_valid_rejection(db_session, test_setup):
    """Test 2: Valid rejection marks confirmation REJECTED and emits CONFIRMATION_REJECTED."""
    async def _run():
        s = test_setup
        repo: DecisionRepository = s["repo"]
        conf_svc: ConfirmationServiceImpl = s["confirmation_service"]

        await repo.save_confirmation(db_session, s["conf_model"])
        await repo.save_decision(db_session, s["initial_decision"])

        req = ConfirmationRespondRequest(response="REJECT")
        res = await conf_svc.respond(db_session, s["confirmation_id"], s["user_id"], req)

        assert res.confirmation_id == s["confirmation_id"]
        assert res.status == "REJECTED"
        assert res.decision_id is None
        assert res.outcome is None

        # Check DB status
        updated_conf = await repo.get_confirmation(db_session, s["confirmation_id"])
        assert updated_conf is not None
        assert updated_conf.status == "REJECTED"

        # Check Event
        emitted = events._default_emitter.emitted_events
        assert len(emitted) == 1
        assert emitted[0]["event_type"] == "CONFIRMATION_REJECTED"
        assert emitted[0]["refs"]["confirmation_id"] == s["confirmation_id"]
        assert emitted[0]["payload"]["challenge"] == s["challenge"]
        assert emitted[0]["payload"]["key_id"] == s["key_id"]

    asyncio.run(_run())


def test_invalid_signature_rejected(db_session, test_setup):
    """Test 3: Corrupted or invalid signature raises SignatureInvalidError."""
    async def _run():
        s = test_setup
        repo: DecisionRepository = s["repo"]
        conf_svc: ConfirmationServiceImpl = s["confirmation_service"]
        await repo.save_confirmation(db_session, s["conf_model"])

        # Create signature with a different private key
        other_priv, _ = generate_test_user_key(user_id=s["user_id"], key_id=s["key_id"])
        bad_sig = sign_challenge_es256(other_priv, s["key_id"], s["challenge"])

        req = ConfirmationRespondRequest(response="APPROVE", signature=bad_sig)

        with pytest.raises(SignatureInvalidError):
            await conf_svc.respond(db_session, s["confirmation_id"], s["user_id"], req)

        # Status must remain PENDING
        unchanged = await repo.get_confirmation(db_session, s["confirmation_id"])
        assert unchanged is not None and unchanged.status == "PENDING"

    asyncio.run(_run())


def test_challenge_mismatch_rejected(db_session, test_setup):
    """Test 4: Signature signed_digest not matching challenge raises ChallengeMismatchError."""
    async def _run():
        s = test_setup
        repo: DecisionRepository = s["repo"]
        conf_svc: ConfirmationServiceImpl = s["confirmation_service"]
        await repo.save_confirmation(db_session, s["conf_model"])

        # Sign a completely different digest
        wrong_digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        sig = sign_challenge_es256(s["priv_key"], s["key_id"], wrong_digest)

        req = ConfirmationRespondRequest(response="APPROVE", signature=sig)

        with pytest.raises(ChallengeMismatchError):
            await conf_svc.respond(db_session, s["confirmation_id"], s["user_id"], req)

    asyncio.run(_run())


def test_expired_confirmation_rejected(db_session, test_setup):
    """Test 5: Responding after expiry transitions status to EXPIRED and raises ConfirmationExpiredError."""
    async def _run():
        s = test_setup
        repo: DecisionRepository = s["repo"]

        # Set confirmation expiry in the past
        s["conf_model"].expires_at = s["now"] - timedelta(seconds=1)
        await repo.save_confirmation(db_session, s["conf_model"])

        conf_svc: ConfirmationServiceImpl = s["confirmation_service"]
        sig = sign_challenge_es256(s["priv_key"], s["key_id"], s["challenge"])
        req = ConfirmationRespondRequest(response="APPROVE", signature=sig)

        with pytest.raises(ConfirmationExpiredError):
            await conf_svc.respond(db_session, s["confirmation_id"], s["user_id"], req)

        # Status transitioned to EXPIRED
        updated = await repo.get_confirmation(db_session, s["confirmation_id"])
        assert updated is not None and updated.status == "EXPIRED"

        # Event emitted
        emitted = events._default_emitter.emitted_events
        assert len(emitted) == 1
        assert emitted[0]["event_type"] == "CONFIRMATION_EXPIRED"

    asyncio.run(_run())


def test_wrong_user_ownership_rejected(db_session, test_setup):
    """Test 6: Caller user ID mismatch raises ConfirmationOwnershipError."""
    async def _run():
        s = test_setup
        repo: DecisionRepository = s["repo"]
        conf_svc: ConfirmationServiceImpl = s["confirmation_service"]
        await repo.save_confirmation(db_session, s["conf_model"])

        sig = sign_challenge_es256(s["priv_key"], s["key_id"], s["challenge"])
        req = ConfirmationRespondRequest(response="APPROVE", signature=sig)

        with pytest.raises(ConfirmationOwnershipError):
            await conf_svc.respond(db_session, s["confirmation_id"], "usr_attacker_99", req)

    asyncio.run(_run())


def test_revoked_key_rejected(db_session, test_setup):
    """Test 7: User key marked REVOKED raises UserKeyInvalidError."""
    async def _run():
        s = test_setup
        repo: DecisionRepository = s["repo"]
        conf_svc: ConfirmationServiceImpl = s["confirmation_service"]
        await repo.save_confirmation(db_session, s["conf_model"])

        # Revoke key in user_key_service
        revoked_record = UserKeyRecord(
            key_id=s["key_id"],
            user_id=s["user_id"],
            alg="ES256",
            jwk=s["user_key_record"].jwk,
            status="REVOKED",
        )
        s["user_key_service"].add_key(revoked_record)

        sig = sign_challenge_es256(s["priv_key"], s["key_id"], s["challenge"])
        req = ConfirmationRespondRequest(response="APPROVE", signature=sig)

        with pytest.raises(UserKeyInvalidError):
            await conf_svc.respond(db_session, s["confirmation_id"], s["user_id"], req)

    asyncio.run(_run())


def test_proposal_hash_changed_invalidates_confirmation(db_session, test_setup):
    """Test 8: TOCTOU protection - changed proposal hash invalidates confirmation."""
    async def _run():
        s = test_setup
        repo: DecisionRepository = s["repo"]
        conf_svc: ConfirmationServiceImpl = s["confirmation_service"]
        await repo.save_confirmation(db_session, s["conf_model"])

        # Grounding service reports altered proposal hash
        s["grounding_service"].proposal_hash = "sha256:altered_proposal_hash_9999999"

        sig = sign_challenge_es256(s["priv_key"], s["key_id"], s["challenge"])
        req = ConfirmationRespondRequest(response="APPROVE", signature=sig)

        with pytest.raises(ConfirmationInvalidatedError) as exc_info:
            await conf_svc.respond(db_session, s["confirmation_id"], s["user_id"], req)

        assert exc_info.value.code == "CONFIRMATION_PROPOSAL_CHANGED"

        # Confirmation transitioned to INVALIDATED in DB
        updated = await repo.get_confirmation(db_session, s["confirmation_id"])
        assert updated is not None and updated.status == "INVALIDATED"

        # CONFIRMATION_INVALIDATED event emitted
        emitted = events._default_emitter.emitted_events
        assert len(emitted) == 1
        assert emitted[0]["event_type"] == "CONFIRMATION_INVALIDATED"
        assert emitted[0]["payload"]["code"] == "CONFIRMATION_PROPOSAL_CHANGED"

    asyncio.run(_run())


def test_checkout_expired_invalidates_confirmation(db_session, test_setup):
    """Test 9: TOCTOU protection - expired checkout invalidates confirmation."""
    async def _run():
        s = test_setup
        repo: DecisionRepository = s["repo"]
        conf_svc: ConfirmationServiceImpl = s["confirmation_service"]
        await repo.save_confirmation(db_session, s["conf_model"])

        # Checkout expired
        expired_checkout = CheckoutSnapshot(
            checkout_id="chk_01JD4800000000000000000001",
            checkout_hash=s["conf_model"].proposal_hash,
            merchant_id="mer_croma_01",
            merchant_domain="croma.example.com",
            payee_id="payee_croma_corp",
            amount_minor=6482966,
            currency="INR",
            merchant_signature_valid=True,
            expires_at=s["now"] - timedelta(seconds=1),  # Expired
        )
        s["grounding_service"].checkout = expired_checkout

        sig = sign_challenge_es256(s["priv_key"], s["key_id"], s["challenge"])
        req = ConfirmationRespondRequest(response="APPROVE", signature=sig)

        with pytest.raises(ConfirmationInvalidatedError) as exc_info:
            await conf_svc.respond(db_session, s["confirmation_id"], s["user_id"], req)

        assert exc_info.value.code == "CONFIRMATION_CHECKOUT_EXPIRED"

        updated = await repo.get_confirmation(db_session, s["confirmation_id"])
        assert updated is not None and updated.status == "INVALIDATED"

        emitted = events._default_emitter.emitted_events
        assert len(emitted) == 1
        assert emitted[0]["event_type"] == "CONFIRMATION_INVALIDATED"
        assert emitted[0]["payload"]["code"] == "CONFIRMATION_CHECKOUT_EXPIRED"

    asyncio.run(_run())


def test_duplicate_approval_rejected(db_session, test_setup):
    """Test 10: Calling approve twice raises ConfirmationNotPendingError on the second call."""
    async def _run():
        s = test_setup
        repo: DecisionRepository = s["repo"]
        conf_svc: ConfirmationServiceImpl = s["confirmation_service"]
        await repo.save_confirmation(db_session, s["conf_model"])
        await repo.save_decision(db_session, s["initial_decision"])

        sig = sign_challenge_es256(s["priv_key"], s["key_id"], s["challenge"])
        req = ConfirmationRespondRequest(response="APPROVE", signature=sig)

        # First call succeeds
        res1 = await conf_svc.respond(db_session, s["confirmation_id"], s["user_id"], req)
        assert res1.status == "APPROVED"

        # Second call fails
        with pytest.raises(ConfirmationNotPendingError):
            await conf_svc.respond(db_session, s["confirmation_id"], s["user_id"], req)

    asyncio.run(_run())


def test_approval_after_rejection_rejected(db_session, test_setup):
    """Test 11: Calling approve on an already rejected confirmation fails."""
    async def _run():
        s = test_setup
        repo: DecisionRepository = s["repo"]
        conf_svc: ConfirmationServiceImpl = s["confirmation_service"]
        await repo.save_confirmation(db_session, s["conf_model"])

        # Reject first
        await conf_svc.respond(db_session, s["confirmation_id"], s["user_id"], ConfirmationRespondRequest(response="REJECT"))

        # Attempt to approve
        sig = sign_challenge_es256(s["priv_key"], s["key_id"], s["challenge"])
        with pytest.raises(ConfirmationNotPendingError):
            await conf_svc.respond(db_session, s["confirmation_id"], s["user_id"], ConfirmationRespondRequest(response="APPROVE", signature=sig))

    asyncio.run(_run())


def test_concurrency_race_condition_handled_safely(db_session, test_setup):
    """Test 13: Concurrent approval and rejection: atomic CAS ensures exactly one succeeds."""
    async def _run():
        s = test_setup
        repo: DecisionRepository = s["repo"]
        conf_svc: ConfirmationServiceImpl = s["confirmation_service"]
        await repo.save_confirmation(db_session, s["conf_model"])
        await repo.save_decision(db_session, s["initial_decision"])

        sig = sign_challenge_es256(s["priv_key"], s["key_id"], s["challenge"])
        req_approve = ConfirmationRespondRequest(response="APPROVE", signature=sig)
        req_reject = ConfirmationRespondRequest(response="REJECT")

        # Simulate concurrent execution using asyncio.gather
        results = await asyncio.gather(
            conf_svc.respond(db_session, s["confirmation_id"], s["user_id"], req_approve),
            conf_svc.respond(db_session, s["confirmation_id"], s["user_id"], req_reject),
            return_exceptions=True,
        )

        successes = [r for r in results if not isinstance(r, Exception)]
        failures = [r for r in results if isinstance(r, Exception)]

        # Exactly one must succeed, and the other must fail with ConfirmationNotPendingError
        assert len(successes) == 1
        assert len(failures) == 1
        assert isinstance(failures[0], ConfirmationNotPendingError)

    asyncio.run(_run())


def test_hard_gate_block_cannot_be_overridden_by_user_approval(db_session, test_setup):
    """Test 14: Invariant INV-07 - Human confirmation never overrides a hard-gate BLOCK."""
    async def _run():
        s = test_setup
        repo: DecisionRepository = s["repo"]
        conf_svc: ConfirmationServiceImpl = s["confirmation_service"]

        # Suppose checkout amount changed to exceed max_amount_per_txn (e.g. 15,000,000 > 8,000,000)
        over_cap_checkout = CheckoutSnapshot(
            checkout_id="chk_01JD4800000000000000000001",
            checkout_hash=s["conf_model"].proposal_hash,
            merchant_id="mer_croma_01",
            merchant_domain="croma.example.com",
            payee_id="payee_croma_corp",
            amount_minor=15000000,  # Exceeds per txn cap of 8,000,000 -> HG-07 BLOCK
            currency="INR",
            merchant_signature_valid=True,
            expires_at=s["now"] + timedelta(days=1),
        )
        s["grounding_service"].checkout = over_cap_checkout

        await repo.save_confirmation(db_session, s["conf_model"])
        await repo.save_decision(db_session, s["initial_decision"])

        sig = sign_challenge_es256(s["priv_key"], s["key_id"], s["challenge"])
        req = ConfirmationRespondRequest(response="APPROVE", signature=sig)

        res = await conf_svc.respond(db_session, s["confirmation_id"], s["user_id"], req)

        # User approved, but policy re-evaluation returned BLOCK
        assert res.status == "APPROVED"
        assert res.outcome == "BLOCK"  # NEVER forced to ALLOW

        # Stored decision in DB is BLOCK
        new_dec = await repo.get_decision(db_session, res.decision_id)
        assert new_dec is not None
        assert new_dec.outcome == "BLOCK"
        assert new_dec.stage == "HARD_GATE"

    asyncio.run(_run())


def test_transaction_rollback_preserves_consistency(db_session, test_setup):
    """Test 16: DB transaction rollback ensures no partial confirmation or decision state is saved."""
    async def _run():
        s = test_setup
        repo: DecisionRepository = s["repo"]
        await repo.save_confirmation(db_session, s["conf_model"])
        db_session.commit()

        # Begin transaction that gets rolled back
        await repo.update_confirmation_status_cas(
            db_session, s["confirmation_id"], expected_status="PENDING", new_status="APPROVED"
        )
        # Roll back transaction
        db_session.rollback()

        # State must remain PENDING
        conf = await repo.get_confirmation(db_session, s["confirmation_id"])
        assert conf is not None and conf.status == "PENDING"

    asyncio.run(_run())


def test_database_user_key_service(db_session):
    """Test DatabaseUserKeyService querying user_keys table."""
    from mandit.confirmation.models import UserKeyModel
    from mandit.confirmation.service import DatabaseUserKeyService
    from mandit.common.crypto import load_es256_public_key_from_jwk

    async def _run():
        priv_key = ec.generate_private_key(ec.SECP256R1())
        pub_numbers = priv_key.public_key().public_numbers()
        x_bytes = pub_numbers.x.to_bytes(32, "big")
        y_bytes = pub_numbers.y.to_bytes(32, "big")
        valid_jwk = {
            "kty": "EC",
            "crv": "P-256",
            "x": b64url_encode(x_bytes),
            "y": b64url_encode(y_bytes),
        }

        # Insert active key
        key1 = UserKeyModel(
            key_id="ukey_db_01",
            user_id="usr_db_test",
            alg="ES256",
            jwk=valid_jwk,
            status="ACTIVE",
        )
        # Insert revoked key
        key2 = UserKeyModel(
            key_id="ukey_db_02",
            user_id="usr_db_test",
            alg="ES256",
            jwk=valid_jwk,
            status="REVOKED",
        )
        db_session.add_all([key1, key2])
        db_session.commit()

        service = DatabaseUserKeyService(session_factory_or_session=db_session)

        # 1. get_key for active key
        rec1 = await service.get_key("ukey_db_01", session=db_session)
        assert rec1 is not None
        assert rec1.key_id == "ukey_db_01"
        assert rec1.status == "ACTIVE"

        # 2. get_key for revoked key
        rec2 = await service.get_key("ukey_db_02", session=db_session)
        assert rec2 is not None
        assert rec2.status == "REVOKED"

        # 3. get_active_key returns the active key, ignoring revoked
        active = await service.get_active_key("usr_db_test", session=db_session)
        assert active is not None
        assert active.key_id == "ukey_db_01"

        # 4. non-existent key
        none_key = await service.get_key("ukey_nonexistent", session=db_session)
        assert none_key is None

    asyncio.run(_run())


def test_es256_jwk_hardening_and_validation():
    """Test cryptographic hardening of load_es256_public_key_from_jwk."""
    from mandit.common.crypto import load_es256_public_key_from_jwk

    priv_key = ec.generate_private_key(ec.SECP256R1())
    pub_numbers = priv_key.public_key().public_numbers()
    x_bytes = pub_numbers.x.to_bytes(32, "big")
    y_bytes = pub_numbers.y.to_bytes(32, "big")

    valid_jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": b64url_encode(x_bytes),
        "y": b64url_encode(y_bytes),
    }

    # 1. Valid JWK loads successfully
    pub = load_es256_public_key_from_jwk(valid_jwk)
    assert isinstance(pub, ec.EllipticCurvePublicKey)

    # 2. Reject if private parameter 'd' is present
    with pytest.raises(ValueError, match="private key parameter 'd' must not be present"):
        load_es256_public_key_from_jwk({**valid_jwk, "d": "some_secret_d"})

    # 3. Reject wrong kty or crv
    with pytest.raises(ValueError, match="expected kty='EC'"):
        load_es256_public_key_from_jwk({**valid_jwk, "kty": "RSA"})
    with pytest.raises(ValueError, match="expected kty='EC', crv='P-256'"):
        load_es256_public_key_from_jwk({**valid_jwk, "crv": "P-384"})

    # 4. Reject coordinate with wrong length (not 32 bytes)
    short_x = b64url_encode(b"too_short")
    with pytest.raises(ValueError, match="expected exactly 43 characters"):
        load_es256_public_key_from_jwk({**valid_jwk, "x": short_x})

    # 5. Reject invalid characters in coordinate
    with pytest.raises(ValueError, match="matching alphabet"):
        load_es256_public_key_from_jwk({**valid_jwk, "x": "invalid!characters!inside!base64url!string!"})


def test_event_outbox_transactional_persistence(db_session):
    """Test that events.emit writes to event_outbox table when mapped."""
    from mandit.common.events import EventOutboxModel

    async def _run():
        events.clear()
        evt_id = await events.emit(
            db_session,
            transaction_id="txn_outbox_test",
            event_type="TEST_EVENT",
            producer="test",
            actor={"type": "SERVICE", "id": "test_actor"},
            refs={"key": "val"},
            payload={"test_param": 123},
        )
        db_session.commit()

        # Verify entry exists in event_outbox
        from sqlalchemy import select
        stmt = select(EventOutboxModel)
        result = db_session.execute(stmt).scalars().all()
        assert len(result) >= 1
        draft = result[-1].event_draft
        assert draft["event_id"] == evt_id
        assert draft["event_type"] == "TEST_EVENT"
        assert draft["transaction_id"] == "txn_outbox_test"
        assert draft["payload"]["test_param"] == 123

    asyncio.run(_run())
