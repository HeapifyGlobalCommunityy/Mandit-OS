"""Unit tests for Mandit OS Step-Up Rules (SU-01 to SU-07) and Trust Score Bands.

Verifies advisory triggers, trust score boundaries, RETRIEVE_MORE attempt handling,
precedence hierarchies, and confirmation resolution.
"""

from datetime import UTC, datetime
from typing import Any, Literal

from mandit.policy.rules import (
    SU01ApprovalThresholdRule,
    SU02NewMerchantRule,
    SU03MediumSiteRiskRule,
    SU04MediumInjectionRule,
    SU05PriceUnverifiedRule,
    SU06TermsUnverifiedRule,
    SU07PricierAlternativeRule,
)
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
    SelectionResult,
    TrustResult,
    VerificationReport,
)
from mandit.policy.service import DefaultPolicyEngine, decide


def create_baseline_inputs(
    *,
    amount_minor: int = 4000000,
    approval_threshold_minor: int = 5000000,
    user_merchant_history: int = 5,
    site_risk_level: Literal["LOW", "MEDIUM", "HIGH"] = "LOW",
    max_injection_severity: Literal["NONE", "LOW", "MEDIUM", "HIGH"] = "NONE",
    claims: tuple[dict[str, Any], ...] = (),
    pricier_alternative_chosen: bool = False,
    trust_score: float = 0.95,
    attempt: int = 1,
    confirmation: ConfirmationSnapshot | None = None,
    signals: tuple[str, ...] = (),
) -> FrozenDecisionInputs:
    """Helper creating clean baseline inputs satisfying all hard gates with no step-ups."""
    eval_time = datetime(2026, 11, 24, 12, 0, 0, tzinfo=UTC)

    agent_ctx = AgentContext(
        agent_id="agt_01JD3Y0000SHOPPERV3000000",
        operator_id="op_01JD3Y0000ACMEOPERATOR0000",
        key_id="akey_01JD3Y0000SHOPPERKEY0001",
        key_thumbprint="q8xR3...thumbprint",
        scopes=frozenset(["mandit:propose", "mandit:execute"]),
        credential_id="kya_01JD3Y4K1M2N3P4Q5R6S7T8V9W",
        verified_at=datetime(2026, 11, 24, 11, 55, 0, tzinfo=UTC),
    )

    identity = IdentityResult(
        agent=agent_ctx,
        is_active=True,
        operator_verified=True,
        kya_token_valid=True,
        key_bound=True,
    )

    constraints = MandateConstraints(
        allowed_merchants=("mer_croma_demo",),
        allowed_domains=("croma.mock.mandit.local",),
        allowed_categories=("electronics.laptops",),
        currency="INR",
        max_amount_per_txn_minor=8000000,
        max_amount_total_minor=10000000,
        max_txn_count=10,
        approval_threshold_minor=approval_threshold_minor,
        payment_methods=("CARD_TOKEN", "UPI"),
        max_delivery_days=7,
        require_refund_policy=True,
    )

    mandate = MandateSnapshot(
        mandate_id="man_01JD3Z0000LAPTOP60K000000",
        version=1,
        user_id="usr_01JD3Y...",
        agent_id="agt_01JD3Y0000SHOPPERV3000000",
        agent_key_thumbprint="q8xR3...thumbprint",
        constraints=constraints,
        not_before=datetime(2026, 11, 24, 0, 0, 0, tzinfo=UTC),
        expires_at=datetime(2026, 11, 25, 0, 0, 0, tzinfo=UTC),
        status="ACTIVE",
        spent_minor=1000000,
        spend_count=1,
    )

    risk = RiskSummary(
        merchant_domain="croma.mock.mandit.local",
        site_risk_score=0.05,
        site_risk_level=site_risk_level,
        max_injection_severity=max_injection_severity,
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
        amount_minor=amount_minor,
        currency="INR",
        merchant_signature_valid=True,
        expires_at=datetime(2026, 11, 24, 12, 30, 0, tzinfo=UTC),
    )

    calculation = CalculationResult(
        computed_total_minor=amount_minor,
        merchant_total_minor=amount_minor,
        agent_stated_total_minor=amount_minor,
        reconciled=True,
        calculator_version="calc-1.0.0",
        subtotal_minor=amount_minor,
        agent_stated_merchant_id="mer_croma_demo",
        agent_stated_currency="INR",
    )

    mandate_match = MandateMatchResult(satisfied=True, violations=(), signals=signals)
    selection = SelectionResult(pricier_alternative_chosen=pricier_alternative_chosen)

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
        proposal_hash="sha256:7ab2...",
        attempt=attempt,
        checkout=checkout,
        calculation=calculation,
        mandate_match=mandate_match,
        selection=selection,
        trust=trust,
        claims=claims,
    )

    return FrozenDecisionInputs(
        evaluated_at=eval_time,
        attempt=attempt,
        proposal_id="prop_01JD43...",
        proposal_hash="sha256:7ab2...",
        transaction_id="txn_01JD3Y9X8W7V6T5S4R3Q2P1N0M",
        identity=identity,
        mandate=mandate,
        risk=risk,
        verification=verification,
        user_merchant_history=user_merchant_history,
        payment_method="CARD_TOKEN",
        confirmation=confirmation,
    )


# --- 1. Positive Baseline Test ---


def test_compliant_repeat_merchant_allows_cleanly() -> None:
    """In-mandate transaction with repeat merchant, under threshold, high trust yields ALLOW."""
    inputs = create_baseline_inputs(
        amount_minor=4000000, approval_threshold_minor=5000000, user_merchant_history=3
    )
    engine = DefaultPolicyEngine()

    res = engine.decide(inputs)

    assert res.outcome == DecisionOutcome.ALLOW
    assert res.stage == EvaluationStage.TRUST_SCORE
    assert len(res.rules_fired) == 0


# --- 2. Gate-by-Gate Tests for SU-01 to SU-07 ---


def test_su01_above_approval_threshold() -> None:
    """SU-01: Fires when amount_minor >= approval_threshold_minor."""
    rule = SU01ApprovalThresholdRule()

    # Under threshold: no hit
    inputs_under = create_baseline_inputs(amount_minor=4999900, approval_threshold_minor=5000000)
    assert rule.evaluate(inputs_under) is None

    # At threshold: fires
    inputs_at = create_baseline_inputs(amount_minor=5000000, approval_threshold_minor=5000000)
    hit = rule.evaluate(inputs_at)
    assert hit is not None and hit.code == "ABOVE_APPROVAL_THRESHOLD"

    # Above threshold: fires
    inputs_above = create_baseline_inputs(amount_minor=6500000, approval_threshold_minor=5000000)
    hit = rule.evaluate(inputs_above)
    assert hit is not None and hit.code == "ABOVE_APPROVAL_THRESHOLD"


def test_su01_zero_approval_threshold_always_requires_confirmation() -> None:
    """SU-01: When threshold == 0, mandate requires confirmation for every purchase."""
    rule = SU01ApprovalThresholdRule()
    inputs = create_baseline_inputs(amount_minor=100000, approval_threshold_minor=0)

    hit = rule.evaluate(inputs)
    assert hit is not None
    assert hit.code == "ABOVE_APPROVAL_THRESHOLD"


def test_su02_new_merchant_for_user() -> None:
    """SU-02: Fires on first purchase from a merchant (user_merchant_history == 0)."""
    rule = SU02NewMerchantRule()

    # Repeat merchant: no hit
    inputs_repeat = create_baseline_inputs(user_merchant_history=3)
    assert rule.evaluate(inputs_repeat) is None

    # First purchase: fires
    inputs_new = create_baseline_inputs(user_merchant_history=0)
    hit = rule.evaluate(inputs_new)
    assert hit is not None and hit.code == "NEW_MERCHANT_FOR_USER"


def test_su03_medium_site_risk() -> None:
    """SU-03: Fires when merchant domain site risk is MEDIUM."""
    rule = SU03MediumSiteRiskRule()

    # Low risk: no hit
    inputs_low = create_baseline_inputs(site_risk_level="LOW")
    assert rule.evaluate(inputs_low) is None

    # Medium risk: fires
    inputs_med = create_baseline_inputs(site_risk_level="MEDIUM")
    hit = rule.evaluate(inputs_med)
    assert hit is not None and hit.code == "SITE_RISK_MEDIUM"


def test_su04_medium_injection() -> None:
    """SU-04: Fires when max_injection_severity is MEDIUM."""
    rule = SU04MediumInjectionRule()

    # None: no hit
    inputs_none = create_baseline_inputs(max_injection_severity="NONE")
    assert rule.evaluate(inputs_none) is None

    # Medium injection: fires
    inputs_med = create_baseline_inputs(max_injection_severity="MEDIUM")
    hit = rule.evaluate(inputs_med)
    assert hit is not None and hit.code == "INJECTION_DETECTED_MEDIUM"


def test_su05_price_mismatch_and_unverified() -> None:
    """SU-05: Fires when displayed price differs from catalog or price is unverified."""
    rule = SU05PriceUnverifiedRule()

    # Verified price claim: no hit
    verified_claim = ({"claim_id": "clm_p1", "claim_type": "PRICE", "status": "VERIFIED"},)
    inputs_verified = create_baseline_inputs(claims=verified_claim)
    assert rule.evaluate(inputs_verified) is None

    # Price mismatch: fires PRICE_MISMATCH
    mismatch_claim = ({"claim_id": "clm_p2", "claim_type": "PRICE", "status": "MISMATCH"},)
    inputs_mismatch = create_baseline_inputs(claims=mismatch_claim)
    hit = rule.evaluate(inputs_mismatch)
    assert hit is not None and hit.code == "PRICE_MISMATCH"

    # Price unverifiable: fires PRICE_UNVERIFIED
    unverifiable_claim = ({"claim_id": "clm_p3", "claim_type": "PRICE", "status": "UNVERIFIABLE"},)
    inputs_unverifiable = create_baseline_inputs(claims=unverifiable_claim)
    hit = rule.evaluate(inputs_unverifiable)
    assert hit is not None and hit.code == "PRICE_UNVERIFIED"


def test_su06_terms_unverified_while_required() -> None:
    """SU-06: Fires when delivery or returns unverified while mandate requires it."""
    rule = SU06TermsUnverifiedRule()

    # Clean signals: no hit
    inputs_clean = create_baseline_inputs(signals=())
    assert rule.evaluate(inputs_clean) is None

    # Delivery unverified: fires
    inputs_deliv = create_baseline_inputs(signals=("DELIVERY_UNVERIFIED",))
    hit = rule.evaluate(inputs_deliv)
    assert hit is not None and hit.code == "DELIVERY_UNVERIFIED"

    # Returns unverified: fires
    inputs_returns = create_baseline_inputs(signals=("RETURNS_UNVERIFIED",))
    hit = rule.evaluate(inputs_returns)
    assert hit is not None and hit.code == "RETURNS_UNVERIFIED"


def test_su07_pricier_alternative_chosen() -> None:
    """SU-07: Fires when agent chose a pricier item than a matching cheaper alternative."""
    rule = SU07PricierAlternativeRule()

    # Not chosen: no hit
    inputs_clean = create_baseline_inputs(pricier_alternative_chosen=False)
    assert rule.evaluate(inputs_clean) is None

    # Pricier alternative chosen: fires
    inputs_pricier = create_baseline_inputs(pricier_alternative_chosen=True)
    hit = rule.evaluate(inputs_pricier)
    assert hit is not None and hit.code == "PRICIER_ALTERNATIVE_CHOSEN"


# --- 3. Trust Score Boundaries and Refresh Exhaustion ---


def test_trust_score_boundaries_and_codes() -> None:
    """Validate exact trust score thresholds, reason codes, and attempt-based refresh."""
    # 0.90 -> ALLOW
    res_90 = decide(create_baseline_inputs(trust_score=0.90))
    assert res_90.outcome == DecisionOutcome.ALLOW
    assert res_90.stage == EvaluationStage.TRUST_SCORE

    # 0.89 -> STEP_UP with TS-01
    res_89 = decide(create_baseline_inputs(trust_score=0.89))
    assert res_89.outcome == DecisionOutcome.STEP_UP
    assert res_89.stage == EvaluationStage.TRUST_SCORE
    assert any(h.rule_id == "TS-01" and h.code == "TRUST_SCORE_STEP_UP" for h in res_89.rules_fired)

    # 0.70 -> STEP_UP with TS-01
    res_70 = decide(create_baseline_inputs(trust_score=0.70))
    assert res_70.outcome == DecisionOutcome.STEP_UP
    assert res_70.stage == EvaluationStage.TRUST_SCORE

    # 0.69 attempt 1 -> RETRIEVE_MORE with TS-01
    res_69_att1 = decide(create_baseline_inputs(trust_score=0.69, attempt=1))
    assert res_69_att1.outcome == DecisionOutcome.RETRIEVE_MORE
    assert res_69_att1.stage == EvaluationStage.TRUST_SCORE
    assert any(
        h.rule_id == "TS-01" and h.code == "TRUST_SCORE_RETRIEVE_MORE"
        for h in res_69_att1.rules_fired
    )

    # 0.50 attempt 1 -> RETRIEVE_MORE
    res_50_att1 = decide(create_baseline_inputs(trust_score=0.50, attempt=1))
    assert res_50_att1.outcome == DecisionOutcome.RETRIEVE_MORE

    # 0.60 attempt 2 -> STEP_UP with TS-02 (refresh exhausted)
    res_60_att2 = decide(create_baseline_inputs(trust_score=0.60, attempt=2))
    assert res_60_att2.outcome == DecisionOutcome.STEP_UP
    assert res_60_att2.stage == EvaluationStage.TRUST_SCORE
    assert any(
        h.rule_id == "TS-02" and h.code == "RETRIEVE_MORE_EXHAUSTED"
        for h in res_60_att2.rules_fired
    )

    # 0.49 -> BLOCK with TS-01
    res_49 = decide(create_baseline_inputs(trust_score=0.49))
    assert res_49.outcome == DecisionOutcome.BLOCK
    assert res_49.stage == EvaluationStage.TRUST_SCORE
    assert any(h.rule_id == "TS-01" and h.code == "TRUST_SCORE_BLOCK" for h in res_49.rules_fired)


# --- 4. Precedence, Multiple Rules, and Confirmation Resolution ---


def test_multiple_step_up_rules_recorded_and_stage_is_rule() -> None:
    """When multiple Step-Up rules fire, all are recorded in rules_fired and stage is RULE."""
    inputs = create_baseline_inputs(
        amount_minor=6000000,
        approval_threshold_minor=5000000,  # SU-01
        user_merchant_history=0,  # SU-02
        site_risk_level="MEDIUM",  # SU-03
        pricier_alternative_chosen=True,  # SU-07
    )

    res = decide(inputs)

    assert res.outcome == DecisionOutcome.STEP_UP
    assert res.stage == EvaluationStage.RULE

    fired_codes = {h.code for h in res.rules_fired}
    expected_codes = {
        "ABOVE_APPROVAL_THRESHOLD",
        "NEW_MERCHANT_FOR_USER",
        "SITE_RISK_MEDIUM",
        "PRICIER_ALTERNATIVE_CHOSEN",
    }
    assert expected_codes.issubset(fired_codes)


def test_trust_score_block_overrides_step_up_rules() -> None:
    """Precedence: Trust score BLOCK (< 0.50) overrides Step-Up rule STEP_UP."""
    inputs = create_baseline_inputs(
        user_merchant_history=0,  # SU-02 fires
        trust_score=0.42,  # Trust score BLOCK
    )

    res = decide(inputs)

    assert res.outcome == DecisionOutcome.BLOCK
    assert res.stage == EvaluationStage.TRUST_SCORE
    assert any(h.rule_id == "SU-02" for h in res.rules_fired)
    assert any(h.code == "TRUST_SCORE_BLOCK" for h in res.rules_fired)


def test_trust_score_retrieve_more_overrides_step_up_rules_on_attempt_1() -> None:
    """Precedence: On attempt 1, RETRIEVE_MORE (2) takes precedence over STEP_UP (1)."""
    inputs = create_baseline_inputs(
        user_merchant_history=0,  # SU-02 fires
        trust_score=0.62,  # RETRIEVE_MORE band
        attempt=1,
    )

    res = decide(inputs)

    assert res.outcome == DecisionOutcome.RETRIEVE_MORE
    assert res.stage == EvaluationStage.TRUST_SCORE
    assert any(h.rule_id == "SU-02" for h in res.rules_fired)
    assert any(h.code == "TRUST_SCORE_RETRIEVE_MORE" for h in res.rules_fired)


def test_valid_confirmation_resolves_step_up_to_allow() -> None:
    """Valid user confirmation resolves candidate STEP_UP to ALLOW with stage CONFIRMATION."""
    proposal_hash = "sha256:7ab2..."

    confirmation = ConfirmationSnapshot(
        confirmation_id="cnf_01JD49...",
        status="APPROVED",
        proposal_hash=proposal_hash,
        expires_at=datetime(2026, 11, 24, 12, 10, 0, tzinfo=UTC),
        response_signature={"alg": "ES256", "value": "MEQCIF..."},
        signature_verified=True,
    )

    inputs = create_baseline_inputs(
        user_merchant_history=0,  # SU-02 fires STEP_UP
        confirmation=confirmation,
    )

    res = decide(inputs)

    assert res.outcome == DecisionOutcome.ALLOW
    assert res.stage == EvaluationStage.CONFIRMATION
    assert any(h.rule_id == "SU-02" for h in res.rules_fired)


def test_confirmation_cannot_override_trust_score_block_or_retrieve_more() -> None:
    """INV-07: Human confirmation cannot resolve BLOCK or RETRIEVE_MORE."""
    proposal_hash = "sha256:7ab2..."

    confirmation = ConfirmationSnapshot(
        confirmation_id="cnf_01JD49...",
        status="APPROVED",
        proposal_hash=proposal_hash,
        expires_at=datetime(2026, 11, 24, 12, 10, 0, tzinfo=UTC),
        response_signature={"alg": "ES256", "value": "MEQCIF..."},
        signature_verified=True,
    )

    # 1. Trust Score BLOCK with confirmation -> BLOCK
    inputs_block = create_baseline_inputs(trust_score=0.45, confirmation=confirmation)
    res_block = decide(inputs_block)
    assert res_block.outcome == DecisionOutcome.BLOCK
    assert res_block.stage == EvaluationStage.TRUST_SCORE

    # 2. RETRIEVE_MORE with confirmation -> RETRIEVE_MORE
    inputs_retrieve = create_baseline_inputs(trust_score=0.60, attempt=1, confirmation=confirmation)
    res_retrieve = decide(inputs_retrieve)
    assert res_retrieve.outcome == DecisionOutcome.RETRIEVE_MORE
    assert res_retrieve.stage == EvaluationStage.TRUST_SCORE
