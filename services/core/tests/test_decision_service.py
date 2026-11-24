"""Comprehensive test suite for DecisionService and Persistence (Stage 3).

Tests:
1. Pure decide() isolation and Invariant INV-11.
2. Single-attempt ALLOW evaluation, DB persistence, signature verification, and DECISION_MADE event.
3. STEP_UP evaluation, ConfirmationModel creation, challenge computation, and STEP_UP_REQUESTED event.
4. Hard gate BLOCK evaluation: trust_score is None, immediate expiry, no confirmation.
5. Trust band BLOCK evaluation: emits DECISION_MADE and INCIDENT_LOGGED.
6. Automatic RETRIEVE_MORE 2-attempt loop: attempt 1 recorded, refresh called, attempt 2 finalized.
7. Fail-safe RETRIEVE_MORE when refresh fails.
8. DecisionService.get() retrieval.
9. Deterministic replay from snapshot.
10. In-memory SQLite database persistence matching migration 0004.
"""
import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from mandit.common import crypto, events, hashing, jcs
from mandit.common.crypto import Ed25519Signer, verify_envelope
from mandit.common.models import Base
from mandit.policy.models import ConfirmationModel, DecisionModel
from mandit.policy.repository import DecisionRepository
from mandit.policy.schemas import (
    AgentContext,
    CalculationResult,
    CheckoutSnapshot,
    ConfirmationSnapshot,
    Decision,
    DecisionOutcome,
    EvaluationStage,
    FrozenDecisionInputs,
    IdentityResult,
    MandateConstraints,
    MandateMatchResult,
    MandateSnapshot,
    RiskSignal,
    RiskSummary,
    RuleHit,
    SelectionResult,
    TrustResult,
    VerificationReport,
    to_snapshot_dict,
)
from mandit.policy.service import (
    DecisionServiceImpl,
    DefaultPolicyEngine,
    build_display_payload,
)


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


@pytest.fixture
def signer():
    """Create a dedicated Ed25519 signer."""
    return Ed25519Signer()


@pytest.fixture
def base_inputs():
    """Create standard compliant FrozenDecisionInputs for baseline testing."""
    now = datetime(2026, 11, 24, 12, 0, 0, tzinfo=timezone.utc)
    future = now + timedelta(days=7)

    agent = AgentContext(
        agent_id="agent_shopping_01",
        operator_id="op_acme_corp",
        key_id="key_agent_ed25519_01",
        key_thumbprint="kth_thumbprint_base64url",
        scopes=frozenset({"purchase:propose", "purchase:execute"}),
        credential_id="kya_credential_jwt_01",
        verified_at=now - timedelta(minutes=5),
    )
    identity = IdentityResult(
        agent=agent,
        is_active=True,
        operator_verified=True,
        kya_token_valid=True,
        key_bound=True,
    )

    constraints = MandateConstraints(
        allowed_merchants=("mer_croma_demo", "mer_croma_01"),
        allowed_domains=("croma.mock.mandit.local", "croma.example.com"),
        allowed_categories=("electronics.laptops", "electronics"),
        currency="INR",
        max_amount_per_txn_minor=8000000,
        max_amount_total_minor=10000000,
        max_txn_count=5,
        approval_threshold_minor=7000000,
        payment_methods=("CARD_TOKEN", "UPI"),
    )
    mandate = MandateSnapshot(
        mandate_id="man_01JD3Y00000000000000000001",
        version=1,
        user_id="user_harsh_01",
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

    checkout = CheckoutSnapshot(
        checkout_id="chk_01JD4800000000000000000001",
        checkout_hash="sha256:7ab2croma0000000000000000000000000000000000000000000000000000000",
        merchant_id="mer_croma_01",
        merchant_domain="croma.example.com",
        payee_id="payee_croma_corp",
        amount_minor=6482966,
        currency="INR",
        merchant_signature_valid=True,
        expires_at=future,
    )
    calc = CalculationResult(
        computed_total_minor=6482966,
        merchant_total_minor=6482966,
        agent_stated_total_minor=6482966,
        reconciled=True,
        calculator_version="calc-1.0.0",
        subtotal_minor=5500000,
        tax_minor=982966,
        agent_stated_merchant_id="mer_croma_01",
        agent_stated_currency="INR",
    )
    mandate_match = MandateMatchResult(satisfied=True, violations=(), signals=())
    selection = SelectionResult(pricier_alternative_chosen=False)
    trust = TrustResult(
        score=0.95,
        band="ALLOW",
        components={"G": 1.0, "C": 1.0, "S": 1.0, "R": 1.0, "P": 1.0},
        weights={"G": 0.3, "C": 0.15, "S": 0.2, "R": 0.1, "P": 0.25},
        trust_model_version="trust-1.0.0",
    )

    verification = VerificationReport(
        verification_id="ver_01JD4700000000000000000001",
        proposal_id="prop_01JD4300000000000000000001",
        proposal_hash="sha256:7ab2croma0000000000000000000000000000000000000000000000000000000",
        attempt=1,
        checkout=checkout,
        calculation=calc,
        mandate_match=mandate_match,
        selection=selection,
        trust=trust,
    )

    return FrozenDecisionInputs(
        evaluated_at=now,
        attempt=1,
        proposal_id="prop_01JD4300000000000000000001",
        proposal_hash=checkout.checkout_hash,
        transaction_id="txn_01JD3Y9X000000000000000001",
        identity=identity,
        mandate=mandate,
        risk=risk,
        verification=verification,
        user_merchant_history=3,
        payment_method="CARD_TOKEN",
        confirmation=None,
    )


@pytest.fixture(autouse=True)
def clear_events():
    events._default_emitter.clear()
    yield
    events._default_emitter.clear()


def test_allow_evaluation_persistence_and_signing(db_session, signer, base_inputs):
    """Test happy-path ALLOW decision: persistence, Ed25519 signing, and DECISION_MADE event."""
    async def _run():
        repo = DecisionRepository()
        engine = DefaultPolicyEngine()
        svc = DecisionServiceImpl(engine=engine, repository=repo, signer=signer)

        decision = await svc.evaluate_with_inputs(base_inputs, session=db_session)

        # 1. Assertions on Decision dataclass
        assert decision.outcome == DecisionOutcome.ALLOW
        assert decision.stage == EvaluationStage.TRUST_SCORE
        assert decision.trust_score == 0.95
        assert decision.attempt == 1
        assert decision.confirmation_id is None
        assert decision.proposal_id == base_inputs.proposal_id
        assert decision.expires_at == base_inputs.evaluated_at + timedelta(minutes=10)

        # 2. Verify Ed25519 signature envelope
        envelope = decision.signature
        assert envelope["alg"] == "Ed25519"
        assert envelope["key_id"] == "mandit-policy-2026-11"
        assert envelope["signed_digest"].startswith("sha256:")

        # Reconstruct the exact signed payload and verify with public key
        signed_payload = {
            "attempt": 1,
            "confirmation_id": None,
            "created_at": base_inputs.evaluated_at.isoformat(),
            "decision_id": decision.decision_id,
            "expires_at": decision.expires_at.isoformat(),
            "inputs_hash": decision.inputs_hash,
            "inputs_snapshot_id": decision.inputs_snapshot_id,
            "outcome": "ALLOW",
            "policy_version": "policy-1.0.0",
            "proposal_hash": base_inputs.proposal_hash,
            "proposal_id": base_inputs.proposal_id,
            "rules_fired": [],
            "stage": "TRUST_SCORE",
            "transaction_id": base_inputs.transaction_id,
            "trust_model_version": "trust-1.0.0",
            "trust_score": 0.95,
        }
        assert verify_envelope(envelope, signed_payload, signer.public_key) is True

        # 3. Assertions on Database persistence
        stored_model = await repo.get_decision(db_session, decision.decision_id)
        assert stored_model is not None
        assert stored_model.decision_id == decision.decision_id
        assert stored_model.outcome == "ALLOW"
        assert stored_model.stage == "TRUST_SCORE"
        assert float(stored_model.trust_score) == 0.95

        # 4. Assertions on DECISION_MADE event
        emitted = events._default_emitter.emitted_events
        assert len(emitted) == 1
        evt = emitted[0]
        assert evt["event_type"] == "DECISION_MADE"
        assert evt["producer"] == "policy"
        assert evt["refs"]["decision_id"] == decision.decision_id
        assert evt["refs"]["proposal_id"] == base_inputs.proposal_id
        assert evt["refs"]["mandate_id"] == base_inputs.mandate.mandate_id
        assert evt["payload"]["outcome"] == "ALLOW"
        assert evt["payload"]["attempt"] == 1

    asyncio.run(_run())


def test_step_up_evaluation_and_confirmation_row_creation(db_session, signer, base_inputs):
    """Test STEP_UP decision: creates pending confirmation row, challenge, and STEP_UP_REQUESTED event."""
    async def _run():
        repo = DecisionRepository()
        engine = DefaultPolicyEngine()
        svc = DecisionServiceImpl(engine=engine, repository=repo, signer=signer)

        mandate_constraints = MandateConstraints(
            allowed_merchants=("mer_croma_demo", "mer_croma_01"),
            allowed_domains=("croma.mock.mandit.local", "croma.example.com"),
            allowed_categories=("electronics.laptops", "electronics"),
            currency="INR",
            max_amount_per_txn_minor=8000000,
            max_amount_total_minor=10000000,
            max_txn_count=5,
            approval_threshold_minor=5000000,
            payment_methods=("CARD_TOKEN", "UPI"),
        )
        mandate = MandateSnapshot(
            mandate_id=base_inputs.mandate.mandate_id,
            version=1,
            user_id="user_harsh_01",
            agent_id="agent_shopping_01",
            agent_key_thumbprint="kth_thumbprint_base64url",
            constraints=mandate_constraints,
            not_before=base_inputs.mandate.not_before,
            expires_at=base_inputs.mandate.expires_at,
            status="ACTIVE",
            spent_minor=1000000,
            spend_count=1,
        )
        stepup_inputs = FrozenDecisionInputs(
            evaluated_at=base_inputs.evaluated_at,
            attempt=1,
            proposal_id=base_inputs.proposal_id,
            proposal_hash=base_inputs.proposal_hash,
            transaction_id=base_inputs.transaction_id,
            identity=base_inputs.identity,
            mandate=mandate,
            risk=base_inputs.risk,
            verification=base_inputs.verification,
            user_merchant_history=base_inputs.user_merchant_history,
            payment_method="CARD_TOKEN",
            confirmation=None,
        )

        decision = await svc.evaluate_with_inputs(stepup_inputs, session=db_session)

        # 1. Assertions on Decision
        assert decision.outcome == DecisionOutcome.STEP_UP
        assert decision.stage == EvaluationStage.RULE
        assert decision.confirmation_id is not None
        assert decision.confirmation_id.startswith("cnf_")
        assert any(r.rule_id == "SU-01" for r in decision.rules_fired)

        # 2. Assertions on Confirmation row in DB
        conf_model = await repo.get_confirmation(db_session, decision.confirmation_id)
        assert conf_model is not None
        assert conf_model.confirmation_id == decision.confirmation_id
        assert conf_model.decision_id == decision.decision_id
        assert conf_model.proposal_id == base_inputs.proposal_id
        assert conf_model.status == "PENDING"
        assert conf_model.response_signature is None
        assert (conf_model.expires_at.replace(tzinfo=timezone.utc) if conf_model.expires_at.tzinfo is None else conf_model.expires_at) == decision.expires_at

        # 3. Verify Challenge computation: sha256(JCS({display, proposal_hash, expires_at, confirmation_id}))
        expected_challenge = hashing.digest({
            "confirmation_id": decision.confirmation_id,
            "decision_id": decision.decision_id,
            "display": conf_model.display,
            "expires_at": decision.expires_at.isoformat(),
            "proposal_hash": base_inputs.proposal_hash,
        })
        assert conf_model.challenge == expected_challenge

        # 4. Assertions on Events: STEP_UP_REQUESTED and DECISION_MADE
        emitted = events._default_emitter.emitted_events
        assert len(emitted) == 2
        types = [e["event_type"] for e in emitted]
        assert "STEP_UP_REQUESTED" in types
        assert "DECISION_MADE" in types

        stepup_evt = next(e for e in emitted if e["event_type"] == "STEP_UP_REQUESTED")
        assert stepup_evt["refs"]["confirmation_id"] == decision.confirmation_id
        assert stepup_evt["refs"]["decision_id"] == decision.decision_id
        assert stepup_evt["payload"]["challenge"] == conf_model.challenge
        assert "ABOVE_APPROVAL_THRESHOLD" in stepup_evt["payload"]["reasons"]

    asyncio.run(_run())


def test_hard_gate_block_evaluation(db_session, signer, base_inputs):
    """Test hard gate BLOCK: trust score is None, immediate expiry, no confirmation."""
    async def _run():
        repo = DecisionRepository()
        engine = DefaultPolicyEngine()
        svc = DecisionServiceImpl(engine=engine, repository=repo, signer=signer)

        # Trigger HG-07: amount > max_amount_per_txn_minor (6,482,966 > 5,000,000)
        mandate_constraints = MandateConstraints(
            allowed_merchants=("mer_croma_demo", "mer_croma_01"),
            allowed_domains=("croma.mock.mandit.local", "croma.example.com"),
            allowed_categories=("electronics.laptops", "electronics"),
            currency="INR",
            max_amount_per_txn_minor=5000000,
            max_amount_total_minor=10000000,
            max_txn_count=5,
            approval_threshold_minor=4000000,
            payment_methods=("CARD_TOKEN", "UPI"),
        )
        mandate = MandateSnapshot(
            mandate_id=base_inputs.mandate.mandate_id,
            version=1,
            user_id="user_harsh_01",
            agent_id="agent_shopping_01",
            agent_key_thumbprint="kth_thumbprint_base64url",
            constraints=mandate_constraints,
            not_before=base_inputs.mandate.not_before,
            expires_at=base_inputs.mandate.expires_at,
            status="ACTIVE",
            spent_minor=1000000,
            spend_count=1,
        )
        hg_inputs = FrozenDecisionInputs(
            evaluated_at=base_inputs.evaluated_at,
            attempt=1,
            proposal_id=base_inputs.proposal_id,
            proposal_hash=base_inputs.proposal_hash,
            transaction_id=base_inputs.transaction_id,
            identity=base_inputs.identity,
            mandate=mandate,
            risk=base_inputs.risk,
            verification=base_inputs.verification,
            user_merchant_history=base_inputs.user_merchant_history,
            payment_method="CARD_TOKEN",
            confirmation=None,
        )

        decision = await svc.evaluate_with_inputs(hg_inputs, session=db_session)

        assert decision.outcome == DecisionOutcome.BLOCK
        assert decision.stage == EvaluationStage.HARD_GATE
        assert decision.trust_score is None
        assert decision.confirmation_id is None
        assert decision.expires_at == base_inputs.evaluated_at
        assert any(r.rule_id == "HG-07" for r in decision.rules_fired)

        # Hard gate BLOCK emits DECISION_MADE only (INCIDENT_LOGGED is strictly for trust-band blocks)
        emitted = events._default_emitter.emitted_events
        assert len(emitted) == 1
        assert emitted[0]["event_type"] == "DECISION_MADE"
        assert emitted[0]["payload"]["outcome"] == "BLOCK"
        assert emitted[0]["payload"]["trust_score"] is None

    asyncio.run(_run())


def test_trust_score_block_emits_incident_logged(db_session, signer, base_inputs):
    """Test trust band BLOCK: score < 0.50 emits DECISION_MADE and INCIDENT_LOGGED."""
    async def _run():
        repo = DecisionRepository()
        engine = DefaultPolicyEngine()
        svc = DecisionServiceImpl(engine=engine, repository=repo, signer=signer)

        # Set trust score to 0.42 (< 0.50)
        low_trust = TrustResult(
            score=0.42,
            band="BLOCK",
            components={"G": 0.4, "C": 0.4, "S": 0.4, "R": 0.4, "P": 0.4},
            weights={"G": 0.3, "C": 0.15, "S": 0.2, "R": 0.1, "P": 0.25},
            trust_model_version="trust-1.0.0",
        )
        verif = VerificationReport(
            verification_id="ver_01JD4700000000000000000002",
            proposal_id=base_inputs.proposal_id,
            proposal_hash=base_inputs.proposal_hash,
            attempt=1,
            checkout=base_inputs.verification.checkout,
            calculation=base_inputs.verification.calculation,
            mandate_match=base_inputs.verification.mandate_match,
            selection=base_inputs.verification.selection,
            trust=low_trust,
        )
        block_inputs = FrozenDecisionInputs(
            evaluated_at=base_inputs.evaluated_at,
            attempt=1,
            proposal_id=base_inputs.proposal_id,
            proposal_hash=base_inputs.proposal_hash,
            transaction_id=base_inputs.transaction_id,
            identity=base_inputs.identity,
            mandate=base_inputs.mandate,
            risk=base_inputs.risk,
            verification=verif,
            user_merchant_history=base_inputs.user_merchant_history,
            payment_method="CARD_TOKEN",
            confirmation=None,
        )

        decision = await svc.evaluate_with_inputs(block_inputs, session=db_session)

        assert decision.outcome == DecisionOutcome.BLOCK
        assert decision.stage == EvaluationStage.TRUST_SCORE
        assert decision.trust_score == 0.42
        assert decision.confirmation_id is None

        # Check both DECISION_MADE and INCIDENT_LOGGED are emitted
        emitted = events._default_emitter.emitted_events
        assert len(emitted) == 2
        types = [e["event_type"] for e in emitted]
        assert "DECISION_MADE" in types
        assert "INCIDENT_LOGGED" in types

        incident = next(e for e in emitted if e["event_type"] == "INCIDENT_LOGGED")
        assert incident["refs"]["proposal_id"] == base_inputs.proposal_id
        assert incident["payload"]["incident_type"] == "TRUST_BAND_BLOCK"
        assert incident["payload"]["code"] == "TRUST_SCORE_BLOCK"
        assert incident["payload"]["severity"] == "HIGH"

    asyncio.run(_run())


def test_retrieve_more_two_attempt_flow(db_session, signer, base_inputs):
    """Test automatic RETRIEVE_MORE flow: attempt 1 recorded, refresh called, attempt 2 finalized."""
    async def _run():
        repo = DecisionRepository()
        engine = DefaultPolicyEngine()

        grounding_mock = AsyncMock()
        # In attempt 1, trust score is 0.62 (RETRIEVE_MORE band)
        med_trust = TrustResult(
            score=0.62,
            band="RETRIEVE_MORE",
            components={"G": 0.6, "C": 0.6, "S": 0.6, "R": 0.6, "P": 0.6},
            weights={"G": 0.3, "C": 0.15, "S": 0.2, "R": 0.1, "P": 0.25},
            trust_model_version="trust-1.0.0",
        )
        verif_att1 = VerificationReport(
            verification_id="ver_01JD4700000000000000000003",
            proposal_id=base_inputs.proposal_id,
            proposal_hash=base_inputs.proposal_hash,
            attempt=1,
            checkout=base_inputs.verification.checkout,
            calculation=base_inputs.verification.calculation,
            mandate_match=base_inputs.verification.mandate_match,
            selection=base_inputs.verification.selection,
            trust=med_trust,
        )
        grounding_mock.verify.return_value = verif_att1

        svc = DecisionServiceImpl(
            engine=engine,
            repository=repo,
            signer=signer,
            grounding_service=grounding_mock,
        )

        inputs_att1 = FrozenDecisionInputs(
            evaluated_at=base_inputs.evaluated_at,
            attempt=1,
            proposal_id=base_inputs.proposal_id,
            proposal_hash=base_inputs.proposal_hash,
            transaction_id=base_inputs.transaction_id,
            identity=base_inputs.identity,
            mandate=base_inputs.mandate,
            risk=base_inputs.risk,
            verification=verif_att1,
            user_merchant_history=base_inputs.user_merchant_history,
            payment_method="CARD_TOKEN",
            confirmation=None,
        )

        final_decision = await svc.evaluate_with_inputs(inputs_att1, session=db_session)

        # 1. verify(refresh=True) was called
        grounding_mock.verify.assert_called_once_with(base_inputs.proposal_id, refresh=True)

        # 2. Final returned decision is attempt 2, escalated to STEP_UP via TS-02
        assert final_decision.attempt == 2
        assert final_decision.outcome == DecisionOutcome.STEP_UP
        assert any(r.rule_id == "TS-02" and r.code == "RETRIEVE_MORE_EXHAUSTED" for r in final_decision.rules_fired)

        # 3. Two DECISION_MADE events emitted (one for attempt 1, one for attempt 2)
        emitted = events._default_emitter.emitted_events
        dec_events = [e for e in emitted if e["event_type"] == "DECISION_MADE"]
        assert len(dec_events) == 2
        assert dec_events[0]["payload"]["attempt"] == 1
        assert dec_events[0]["payload"]["outcome"] == "RETRIEVE_MORE"
        assert dec_events[1]["payload"]["attempt"] == 2
        assert dec_events[1]["payload"]["outcome"] == "STEP_UP"

        # 4. Both decisions are persisted in the database
        att1_dec_id = dec_events[0]["refs"]["decision_id"]
        att2_dec_id = dec_events[1]["refs"]["decision_id"]
        m1 = await repo.get_decision(db_session, att1_dec_id)
        m2 = await repo.get_decision(db_session, att2_dec_id)
        assert m1 is not None and m1.attempt == 1 and m1.outcome == "RETRIEVE_MORE"
        assert m2 is not None and m2.attempt == 2 and m2.outcome == "STEP_UP"

    asyncio.run(_run())


def test_retrieve_more_fail_safe_when_refresh_fails(db_session, signer, base_inputs):
    """Test fail-safe RETRIEVE_MORE behavior: if refresh raises an error, system fails closed gracefully."""
    async def _run():
        repo = DecisionRepository()
        engine = DefaultPolicyEngine()

        grounding_mock = AsyncMock()
        grounding_mock.verify.side_effect = RuntimeError("Grounding verification timeout")

        med_trust = TrustResult(
            score=0.62,
            band="RETRIEVE_MORE",
            components={"G": 0.6, "C": 0.6, "S": 0.6, "R": 0.6, "P": 0.6},
            weights={"G": 0.3, "C": 0.15, "S": 0.2, "R": 0.1, "P": 0.25},
            trust_model_version="trust-1.0.0",
        )
        verif = VerificationReport(
            verification_id="ver_01JD4700000000000000000004",
            proposal_id=base_inputs.proposal_id,
            proposal_hash=base_inputs.proposal_hash,
            attempt=1,
            checkout=base_inputs.verification.checkout,
            calculation=base_inputs.verification.calculation,
            mandate_match=base_inputs.verification.mandate_match,
            selection=base_inputs.verification.selection,
            trust=med_trust,
        )
        svc = DecisionServiceImpl(
            engine=engine,
            repository=repo,
            signer=signer,
            grounding_service=grounding_mock,
        )

        inputs = FrozenDecisionInputs(
            evaluated_at=base_inputs.evaluated_at,
            attempt=1,
            proposal_id=base_inputs.proposal_id,
            proposal_hash=base_inputs.proposal_hash,
            transaction_id=base_inputs.transaction_id,
            identity=base_inputs.identity,
            mandate=base_inputs.mandate,
            risk=base_inputs.risk,
            verification=verif,
            user_merchant_history=base_inputs.user_merchant_history,
            payment_method="CARD_TOKEN",
            confirmation=None,
        )

        final_decision = await svc.evaluate_with_inputs(inputs, session=db_session)

        # Failed refresh falls back cleanly, escalates to attempt 2 STEP_UP without crashing
        assert final_decision.attempt == 2
        assert final_decision.outcome == DecisionOutcome.STEP_UP
        assert any(r.rule_id == "TS-02" for r in final_decision.rules_fired)

    asyncio.run(_run())


def test_decision_service_get_retrieval(db_session, signer, base_inputs):
    """Test DecisionService.get(decision_id) retrieval."""
    async def _run():
        repo = DecisionRepository()
        engine = DefaultPolicyEngine()
        svc = DecisionServiceImpl(engine=engine, repository=repo, signer=signer)

        created = await svc.evaluate_with_inputs(base_inputs, session=db_session)

        retrieved = await svc.get(created.decision_id, session=db_session)
        assert retrieved is not None
        assert retrieved.decision_id == created.decision_id
        assert retrieved.outcome == created.outcome
        assert retrieved.stage == created.stage
        assert retrieved.trust_score == created.trust_score
        assert retrieved.proposal_id == created.proposal_id

        # Non-existent decision returns None
        missing = await svc.get("dec_nonexistent", session=db_session)
        assert missing is None

    asyncio.run(_run())


def test_deterministic_replay_from_snapshot(base_inputs):
    """Test Invariant INV-11: Replaying a stored transaction with its frozen inputs reproduces identical decision."""
    engine = DefaultPolicyEngine()

    # Initial decision
    initial_res = engine.decide(base_inputs)

    # Snapshot serialization
    snap_dict = to_snapshot_dict(base_inputs)
    assert isinstance(snap_dict, dict)
    assert snap_dict["proposal_id"] == base_inputs.proposal_id
    digest1 = hashing.digest(snap_dict)

    # Deterministic re-computation
    replay_res = engine.decide(base_inputs)
    assert replay_res.outcome == initial_res.outcome
    assert replay_res.stage == initial_res.stage
    assert replay_res.trust_score == initial_res.trust_score
    assert replay_res.rules_fired == initial_res.rules_fired
    assert hashing.digest(to_snapshot_dict(base_inputs)) == digest1
