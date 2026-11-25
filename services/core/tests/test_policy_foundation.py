"""Unit tests for Mandit OS Policy Engine Foundation.

Tests pure function determinism, stage transitions, severity resolution,
trust score bands, and confirmation constraints (INV-07, INV-11).
"""

from datetime import UTC, datetime

from mandit.policy.schemas import (
    AgentContext,
    CalculationResult,
    CheckoutSnapshot,
    ConfirmationSnapshot,
    DecisionOutcome,
    EvaluationStage,
    FrozenDecisionInputs,
    IdentityResult,
    MandateConstraints,
    MandateMatchResult,
    MandateSnapshot,
    RiskSummary,
    RuleHit,
    SelectionResult,
    TrustResult,
    VerificationReport,
)
from mandit.policy.service import DefaultPolicyEngine, decide


class MockRule:
    """Configurable mock rule implementing PolicyRule for unit testing."""

    def __init__(self, rule_id: str, code: str, effect: DecisionOutcome, fires: bool = False):
        self.rule_id = rule_id
        self.code = code
        self.effect = effect
        self.fires = fires

    def evaluate(self, inputs: FrozenDecisionInputs) -> RuleHit | None:
        if self.fires:
            return RuleHit(rule_id=self.rule_id, code=self.code, effect=self.effect)
        return None


def create_sample_inputs(
    *,
    attempt: int = 1,
    trust_score: float = 0.95,
    confirmation: ConfirmationSnapshot | None = None,
    proposal_hash: str = "sha256:7ab2...",
    evaluated_at: datetime | None = None,
) -> FrozenDecisionInputs:
    """Helper fixture to create valid, immutable FrozenDecisionInputs."""
    if evaluated_at is None:
        evaluated_at = datetime(2026, 11, 24, 12, 0, 0, tzinfo=UTC)

    agent_ctx = AgentContext(
        agent_id="agt_01JD3Y0000SHOPPERV3000000",
        operator_id="op_01JD3Y0000ACMEOPERATOR0000",
        key_id="akey_01JD3Y0000SHOPPERKEY0001",
        key_thumbprint="q8xR3...",
        scopes=frozenset(["mandit:propose", "mandit:execute"]),
        credential_id="kya_01JD3Y4K1M2N3P4Q5R6S7T8V9W",
        verified_at=datetime(2026, 11, 24, 11, 55, 0, tzinfo=UTC),
    )

    identity = IdentityResult(agent=agent_ctx, is_active=True, operator_verified=True)

    constraints = MandateConstraints(
        allowed_merchants=("mer_croma_demo",),
        allowed_domains=("croma.mock.mandit.local",),
        allowed_categories=("electronics.laptops",),
        currency="INR",
        max_amount_per_txn_minor=8000000,
        max_amount_total_minor=10000000,
        max_txn_count=5,
        approval_threshold_minor=7000000,
    )

    mandate = MandateSnapshot(
        mandate_id="man_01JD3Z0000LAPTOP60K000000",
        version=1,
        user_id="usr_01JD3Y...",
        agent_id="agt_01JD3Y0000SHOPPERV3000000",
        agent_key_thumbprint="q8xR3...",
        constraints=constraints,
        not_before=datetime(2026, 11, 24, 0, 0, 0, tzinfo=UTC),
        expires_at=datetime(2026, 11, 25, 0, 0, 0, tzinfo=UTC),
        status="ACTIVE",
        spent_minor=0,
        spend_count=0,
    )

    risk = RiskSummary(
        merchant_domain="croma.mock.mandit.local",
        site_risk_score=0.05,
        site_risk_level="LOW",
        max_injection_severity="NONE",
        injection_content_ids=(),
        signals=(),
        scanner_version="scanner-1.0.0",
    )

    checkout = CheckoutSnapshot(
        checkout_id="co_01JD42...",
        checkout_hash="sha256:9c1e...",
        merchant_id="mer_croma_demo",
        merchant_domain="croma.mock.mandit.local",
        payee_id="acq_croma_001",
        amount_minor=6482966,
        currency="INR",
        merchant_signature_valid=True,
        expires_at=datetime(2026, 11, 24, 12, 30, 0, tzinfo=UTC),
    )

    calculation = CalculationResult(
        computed_total_minor=6482966,
        merchant_total_minor=6482966,
        agent_stated_total_minor=6482966,
        reconciled=True,
        calculator_version="calc-1.0.0",
        subtotal_minor=6482966,
    )

    mandate_match = MandateMatchResult(satisfied=True, violations=(), signals=())
    selection = SelectionResult(pricier_alternative_chosen=False)

    trust_band = "ALLOW"
    if trust_score < 0.50:
        trust_band = "BLOCK"
    elif trust_score < 0.70:
        trust_band = "RETRIEVE_MORE"
    elif trust_score < 0.90:
        trust_band = "STEP_UP"

    trust = TrustResult(
        score=trust_score,
        band=trust_band,
        components={"G": 1.0, "C": 1.0, "S": 1.0, "R": 1.0, "P": 1.0},
        weights={"G": 0.3, "C": 0.15, "S": 0.2, "R": 0.1, "P": 0.25},
        trust_model_version="trust-1.0.0",
    )

    verification = VerificationReport(
        verification_id="ver_01JD47...",
        proposal_id="prop_01JD43...",
        proposal_hash=proposal_hash,
        attempt=attempt,
        checkout=checkout,
        calculation=calculation,
        mandate_match=mandate_match,
        selection=selection,
        trust=trust,
    )

    return FrozenDecisionInputs(
        evaluated_at=evaluated_at,
        attempt=attempt,
        proposal_id="prop_01JD43...",
        proposal_hash=proposal_hash,
        transaction_id="txn_01JD3Y9X8W7V6T5S4R3Q2P1N0M",
        identity=identity,
        mandate=mandate,
        risk=risk,
        verification=verification,
        user_merchant_history=2,
        confirmation=confirmation,
    )


def test_pure_decide_happy_path_allow() -> None:
    """When hard gates pass, no step-up rules fire, and trust score >= 0.90, result is ALLOW."""
    inputs = create_sample_inputs(trust_score=0.95)
    engine = DefaultPolicyEngine()

    res = engine.decide(inputs)

    assert res.outcome == DecisionOutcome.ALLOW
    assert res.stage == EvaluationStage.TRUST_SCORE
    assert len(res.rules_fired) == 0
    assert res.trust_score == 0.95


def test_pure_decide_hard_gate_blocks_immediately() -> None:
    """When a hard gate fires with BLOCK, returns BLOCK immediately with stage HARD_GATE."""
    inputs = create_sample_inputs(trust_score=0.98)
    hg_failing = MockRule("HG-01", "AGENT_REVOKED", DecisionOutcome.BLOCK, fires=True)
    su_firing = MockRule("SU-01", "ABOVE_APPROVAL_THRESHOLD", DecisionOutcome.STEP_UP, fires=True)

    engine = DefaultPolicyEngine(hard_gates=(hg_failing,), step_up_rules=(su_firing,))
    res = engine.decide(inputs)

    assert res.outcome == DecisionOutcome.BLOCK
    assert res.stage == EvaluationStage.HARD_GATE
    assert len(res.rules_fired) == 1
    assert res.rules_fired[0].rule_id == "HG-01"
    assert res.trust_score is None  # Trust score not evaluated when hard gate fails


def test_pure_decide_all_hard_gates_evaluated() -> None:
    """Every hard gate must be evaluated even if an earlier one fails."""
    inputs = create_sample_inputs()
    hg1 = MockRule("HG-01", "AGENT_REVOKED", DecisionOutcome.BLOCK, fires=True)
    hg2 = MockRule("HG-03", "MERCHANT_NOT_ALLOWED", DecisionOutcome.BLOCK, fires=True)

    res = decide(inputs, hard_gates=(hg1, hg2))

    assert res.outcome == DecisionOutcome.BLOCK
    assert res.stage == EvaluationStage.HARD_GATE
    assert len(res.rules_fired) == 2
    assert {r.rule_id for r in res.rules_fired} == {"HG-01", "HG-03"}


def test_pure_decide_step_up_rule_fires() -> None:
    """When a step-up rule fires, outcome is STEP_UP and stage is RULE."""
    inputs = create_sample_inputs(trust_score=0.95)
    su = MockRule("SU-01", "ABOVE_APPROVAL_THRESHOLD", DecisionOutcome.STEP_UP, fires=True)

    res = decide(inputs, step_up_rules=(su,))

    assert res.outcome == DecisionOutcome.STEP_UP
    assert res.stage == EvaluationStage.RULE
    assert len(res.rules_fired) == 1
    assert res.rules_fired[0].code == "ABOVE_APPROVAL_THRESHOLD"


def test_pure_decide_trust_score_bands() -> None:
    """Validate all four Trust Score bands per REFERENCE §11.3."""
    # Band 1: >= 0.90 -> ALLOW
    res_allow = decide(create_sample_inputs(trust_score=0.90))
    assert res_allow.outcome == DecisionOutcome.ALLOW
    assert res_allow.stage == EvaluationStage.TRUST_SCORE

    # Band 2: 0.70 - 0.89 -> STEP_UP
    res_step_up = decide(create_sample_inputs(trust_score=0.75))
    assert res_step_up.outcome == DecisionOutcome.STEP_UP
    assert res_step_up.stage == EvaluationStage.TRUST_SCORE
    assert any(r.code == "TRUST_SCORE_STEP_UP" for r in res_step_up.rules_fired)

    # Band 3: 0.50 - 0.69 (attempt 1) -> RETRIEVE_MORE
    res_ret_1 = decide(create_sample_inputs(trust_score=0.60, attempt=1))
    assert res_ret_1.outcome == DecisionOutcome.RETRIEVE_MORE
    assert res_ret_1.stage == EvaluationStage.TRUST_SCORE
    assert any(r.code == "TRUST_SCORE_RETRIEVE_MORE" for r in res_ret_1.rules_fired)

    # Band 3: 0.50 - 0.69 (attempt 2) -> STEP_UP (exhausted refresh)
    res_ret_2 = decide(create_sample_inputs(trust_score=0.60, attempt=2))
    assert res_ret_2.outcome == DecisionOutcome.STEP_UP
    assert res_ret_2.stage == EvaluationStage.TRUST_SCORE
    assert any(r.code == "RETRIEVE_MORE_EXHAUSTED" for r in res_ret_2.rules_fired)

    # Band 4: < 0.50 -> BLOCK
    res_block = decide(create_sample_inputs(trust_score=0.49))
    assert res_block.outcome == DecisionOutcome.BLOCK
    assert res_block.stage == EvaluationStage.TRUST_SCORE
    assert any(r.code == "TRUST_SCORE_BLOCK" for r in res_block.rules_fired)


def test_pure_decide_confirmation_satisfies_step_up() -> None:
    """Human approval resolves STEP_UP to ALLOW with stage CONFIRMATION."""
    eval_time = datetime(2026, 11, 24, 12, 0, 0, tzinfo=UTC)
    proposal_hash = "sha256:7ab2..."

    valid_confirmation = ConfirmationSnapshot(
        confirmation_id="cnf_01JD49...",
        status="APPROVED",
        proposal_hash=proposal_hash,
        expires_at=datetime(2026, 11, 24, 12, 10, 0, tzinfo=UTC),
        response_signature={"alg": "ES256", "value": "MEQCIF..."},
        signature_verified=True,
    )

    inputs = create_sample_inputs(
        trust_score=0.95,
        confirmation=valid_confirmation,
        proposal_hash=proposal_hash,
        evaluated_at=eval_time,
    )
    su = MockRule("SU-01", "ABOVE_APPROVAL_THRESHOLD", DecisionOutcome.STEP_UP, fires=True)

    res = decide(inputs, step_up_rules=(su,))

    assert res.outcome == DecisionOutcome.ALLOW
    assert res.stage == EvaluationStage.CONFIRMATION
    assert len(res.rules_fired) == 1
    assert res.rules_fired[0].code == "ABOVE_APPROVAL_THRESHOLD"


def test_pure_decide_confirmation_cannot_override_block_or_retrieve_more() -> None:
    """INV-07: Human confirmation cannot override a BLOCK or RETRIEVE_MORE."""
    valid_confirmation = ConfirmationSnapshot(
        confirmation_id="cnf_01JD49...",
        status="APPROVED",
        proposal_hash="sha256:7ab2...",
        expires_at=datetime(2026, 11, 24, 12, 10, 0, tzinfo=UTC),
        response_signature={"alg": "ES256", "value": "MEQCIF..."},
        signature_verified=True,
    )

    # Hard gate BLOCK + valid confirmation -> BLOCK
    hg = MockRule("HG-01", "AGENT_REVOKED", DecisionOutcome.BLOCK, fires=True)
    inputs_block = create_sample_inputs(confirmation=valid_confirmation)
    res_block = decide(inputs_block, hard_gates=(hg,))
    assert res_block.outcome == DecisionOutcome.BLOCK
    assert res_block.stage == EvaluationStage.HARD_GATE

    # RETRIEVE_MORE + valid confirmation -> RETRIEVE_MORE
    inputs_retrieve = create_sample_inputs(
        trust_score=0.60, attempt=1, confirmation=valid_confirmation
    )
    res_retrieve = decide(inputs_retrieve)
    assert res_retrieve.outcome == DecisionOutcome.RETRIEVE_MORE


def test_pure_decide_unverified_confirmation_rejected() -> None:
    """A confirmation without verified signature fails valid_for() and does not resolve STEP_UP."""
    unverified_confirmation = ConfirmationSnapshot(
        confirmation_id="cnf_01JD49...",
        status="APPROVED",
        proposal_hash="sha256:7ab2...",
        expires_at=datetime(2026, 11, 24, 12, 10, 0, tzinfo=UTC),
        response_signature={"alg": "ES256", "value": "MEQCIF..."},
        signature_verified=False,  # Unverified!
    )

    inputs = create_sample_inputs(trust_score=0.75, confirmation=unverified_confirmation)
    res = decide(inputs)

    assert res.outcome == DecisionOutcome.STEP_UP
    assert res.stage == EvaluationStage.TRUST_SCORE


def test_pure_decide_determinism() -> None:
    """Running decide() on same frozen inputs produces identical output (INV-11)."""
    inputs = create_sample_inputs(trust_score=0.82)
    su = MockRule("SU-02", "NEW_MERCHANT_FOR_USER", DecisionOutcome.STEP_UP, fires=True)

    res1 = decide(inputs, step_up_rules=(su,))
    res2 = decide(inputs, step_up_rules=(su,))

    assert res1 == res2
    assert res1.outcome == res2.outcome
    assert res1.stage == res2.stage
    assert res1.rules_fired == res2.rules_fired
    assert res1.trust_score == res2.trust_score
