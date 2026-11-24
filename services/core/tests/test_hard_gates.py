"""Unit tests for Mandit OS Hard Gates (HG-01 to HG-16).

Verifies positive and negative cases for every hard gate, security invariant enforcement,
and compound attack scenarios.
"""
from datetime import datetime, timezone
from dataclasses import replace

from mandit.policy.rules import (
    ALL_HARD_GATES,
    HG01AgentIdentityGate,
    HG02MandateValidityGate,
    HG03MerchantAllowlistGate,
    HG04MerchantRegistryGate,
    HG05CheckoutIntegrityGate,
    HG06CurrencyGate,
    HG07PerTxnCapGate,
    HG08CumulativeCapsGate,
    HG09CalculationRecomputeGate,
    HG10AgentStatementGate,
    HG11LineTypeAndCategoryGate,
    HG12CriticalClaimsGate,
    HG13PaymentMethodGate,
    HG14PromptInjectionGate,
    HG15SiteRiskGate,
    HG16DeliveryAndReturnsGate,
)
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
from mandit.policy.service import DefaultPolicyEngine, decide


def create_compliant_inputs() -> FrozenDecisionInputs:
    """Helper returning an honest, fully compliant, in-mandate transaction input."""
    eval_time = datetime(2026, 11, 24, 12, 0, 0, tzinfo=timezone.utc)

    agent_ctx = AgentContext(
        agent_id="agt_01JD3Y0000SHOPPERV3000000",
        operator_id="op_01JD3Y0000ACMEOPERATOR0000",
        key_id="akey_01JD3Y0000SHOPPERKEY0001",
        key_thumbprint="q8xR3...thumbprint",
        scopes=frozenset(["mandit:propose", "mandit:execute"]),
        credential_id="kya_01JD3Y4K1M2N3P4Q5R6S7T8V9W",
        verified_at=datetime(2026, 11, 24, 11, 55, 0, tzinfo=timezone.utc),
    )

    identity = IdentityResult(
        agent=agent_ctx,
        is_active=True,
        operator_verified=True,
        kya_token_valid=True,
        key_bound=True,
    )

    constraints = MandateConstraints(
        allowed_merchants=("mer_croma_demo", "mer_reliance_demo"),
        allowed_domains=("croma.mock.mandit.local", "reliance.mock.mandit.local"),
        allowed_categories=("electronics.laptops",),
        currency="INR",
        max_amount_per_txn_minor=8000000,
        max_amount_total_minor=10000000,
        max_txn_count=5,
        approval_threshold_minor=7000000,
        payment_methods=("CARD_TOKEN", "UPI"),
    )

    mandate = MandateSnapshot(
        mandate_id="man_01JD3Z0000LAPTOP60K000000",
        version=1,
        user_id="usr_01JD3Y...",
        agent_id="agt_01JD3Y0000SHOPPERV3000000",
        agent_key_thumbprint="q8xR3...thumbprint",
        constraints=constraints,
        not_before=datetime(2026, 11, 24, 0, 0, 0, tzinfo=timezone.utc),
        expires_at=datetime(2026, 11, 25, 0, 0, 0, tzinfo=timezone.utc),
        status="ACTIVE",
        spent_minor=1000000,
        spend_count=1,
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
        expires_at=datetime(2026, 11, 24, 12, 30, 0, tzinfo=timezone.utc),
    )

    calculation = CalculationResult(
        computed_total_minor=6482966,
        merchant_total_minor=6482966,
        agent_stated_total_minor=6482966,
        reconciled=True,
        calculator_version="calc-1.0.0",
        subtotal_minor=5500000,
        tax_minor=982966,
        agent_stated_merchant_id="mer_croma_demo",
        agent_stated_currency="INR",
    )

    mandate_match = MandateMatchResult(satisfied=True, violations=(), signals=())
    selection = SelectionResult(pricier_alternative_chosen=False)

    trust = TrustResult(
        score=0.96,
        band="ALLOW",
        components={"G": 1.0, "C": 1.0, "S": 1.0, "R": 1.0, "P": 1.0},
        weights={"G": 0.3, "C": 0.15, "S": 0.2, "R": 0.1, "P": 0.25},
        trust_model_version="trust-1.0.0",
    )

    verification = VerificationReport(
        verification_id="ver_01JD47...",
        proposal_id="prop_01JD43...",
        proposal_hash="sha256:7ab2...",
        attempt=1,
        checkout=checkout,
        calculation=calculation,
        mandate_match=mandate_match,
        selection=selection,
        trust=trust,
    )

    return FrozenDecisionInputs(
        evaluated_at=eval_time,
        attempt=1,
        proposal_id="prop_01JD43...",
        proposal_hash="sha256:7ab2...",
        transaction_id="txn_01JD3Y9X8W7V6T5S4R3Q2P1N0M",
        identity=identity,
        mandate=mandate,
        risk=risk,
        verification=verification,
        user_merchant_history=3,
        payment_method="CARD_TOKEN",
    )


# --- 1. Positive Baseline Test ---

def test_all_16_hard_gates_pass_on_compliant_transaction() -> None:
    """An honest, compliant transaction passes every hard gate with zero hits."""
    inputs = create_compliant_inputs()
    engine = DefaultPolicyEngine(hard_gates=ALL_HARD_GATES)

    res = engine.decide(inputs)

    assert res.outcome == DecisionOutcome.ALLOW
    assert res.stage == EvaluationStage.TRUST_SCORE
    assert len(res.rules_fired) == 0


# --- 2. Gate-by-Gate Positive & Negative Tests ---

def test_hg01_agent_identity_gate() -> None:
    """HG-01: Agent must be active, operator verified, KYA token valid, and key bound."""
    gate = HG01AgentIdentityGate()
    base_inputs = create_compliant_inputs()

    # Positive
    assert gate.evaluate(base_inputs) is None

    # Negative 1: Agent revoked
    revoked = replace(base_inputs, identity=replace(base_inputs.identity, is_active=False))
    hit = gate.evaluate(revoked)
    assert hit is not None and hit.code == "AGENT_REVOKED"

    # Negative 2: Operator unverified
    unverified_op = replace(base_inputs, identity=replace(base_inputs.identity, operator_verified=False))
    hit = gate.evaluate(unverified_op)
    assert hit is not None and hit.code == "OPERATOR_NOT_VERIFIED"

    # Negative 3: KYA token invalid
    invalid_token = replace(base_inputs, identity=replace(base_inputs.identity, kya_token_valid=False))
    hit = gate.evaluate(invalid_token)
    assert hit is not None and hit.code == "KYA_TOKEN_INVALID"

    # Negative 4: Key not bound
    unbound_key = replace(base_inputs, identity=replace(base_inputs.identity, key_bound=False))
    hit = gate.evaluate(unbound_key)
    assert hit is not None and hit.code == "KEY_NOT_BOUND"


def test_hg02_mandate_validity_gate() -> None:
    """HG-02: Mandate must be ACTIVE, within validity window, and bound to acting agent."""
    gate = HG02MandateValidityGate()
    base_inputs = create_compliant_inputs()

    # Positive
    assert gate.evaluate(base_inputs) is None

    # Negative 1: Mandate revoked
    revoked_mandate = replace(base_inputs, mandate=replace(base_inputs.mandate, status="REVOKED"))
    hit = gate.evaluate(revoked_mandate)
    assert hit is not None and hit.code == "MANDATE_REVOKED"

    # Negative 2: Mandate expired
    past_expiry = replace(base_inputs, evaluated_at=datetime(2026, 11, 26, 0, 0, 0, tzinfo=timezone.utc))
    hit = gate.evaluate(past_expiry)
    assert hit is not None and hit.code == "MANDATE_EXPIRED"

    # Negative 3: Not yet valid
    before_nbf = replace(base_inputs, evaluated_at=datetime(2026, 11, 23, 0, 0, 0, tzinfo=timezone.utc))
    hit = gate.evaluate(before_nbf)
    assert hit is not None and hit.code == "MANDATE_NOT_YET_VALID"

    # Negative 4: Agent not bound to mandate
    wrong_agent = replace(base_inputs, mandate=replace(base_inputs.mandate, agent_id="agt_attacker"))
    hit = gate.evaluate(wrong_agent)
    assert hit is not None and hit.code == "AGENT_NOT_BOUND_TO_MANDATE"


def test_hg03_merchant_allowlist_gate() -> None:
    """HG-03: Merchant ID and domain must be in mandate allowlists."""
    gate = HG03MerchantAllowlistGate()
    base_inputs = create_compliant_inputs()

    # Positive
    assert gate.evaluate(base_inputs) is None

    # Negative 1: Disallowed merchant ID
    bad_merchant = replace(
        base_inputs,
        verification=replace(
            base_inputs.verification,
            checkout=replace(base_inputs.verification.checkout, merchant_id="mer_untrusted"),
        ),
    )
    hit = gate.evaluate(bad_merchant)
    assert hit is not None and hit.code == "MERCHANT_NOT_ALLOWED"

    # Negative 2: Disallowed domain
    bad_domain = replace(
        base_inputs,
        verification=replace(
            base_inputs.verification,
            checkout=replace(base_inputs.verification.checkout, merchant_domain="evil.example.com"),
        ),
    )
    hit = gate.evaluate(bad_domain)
    assert hit is not None and hit.code == "DOMAIN_NOT_ALLOWED"


def test_hg04_merchant_registry_gate() -> None:
    """HG-04: Merchant must be verified in registry, active, and payee must match."""
    gate = HG04MerchantRegistryGate()
    base_inputs = create_compliant_inputs()

    # Positive
    assert gate.evaluate(base_inputs) is None

    # Negative 1: Merchant not in registry
    unregistered = replace(
        base_inputs,
        verification=replace(
            base_inputs.verification,
            mandate_match=MandateMatchResult(satisfied=False, violations=("MERCHANT_NOT_IN_REGISTRY",)),
        ),
    )
    hit = gate.evaluate(unregistered)
    assert hit is not None and hit.code == "MERCHANT_NOT_IN_REGISTRY"

    # Negative 2: Merchant suspended
    suspended = replace(
        base_inputs,
        verification=replace(
            base_inputs.verification,
            mandate_match=MandateMatchResult(satisfied=False, violations=("MERCHANT_SUSPENDED",)),
        ),
    )
    hit = gate.evaluate(suspended)
    assert hit is not None and hit.code == "MERCHANT_SUSPENDED"

    # Negative 3: Payee mismatch (account swapping attack)
    swapped_payee = replace(
        base_inputs,
        verification=replace(
            base_inputs.verification,
            mandate_match=MandateMatchResult(satisfied=False, violations=("PAYEE_MISMATCH",)),
        ),
    )
    hit = gate.evaluate(swapped_payee)
    assert hit is not None and hit.code == "PAYEE_MISMATCH"


def test_hg05_checkout_integrity_gate() -> None:
    """HG-05: Checkout signature must be valid and unexpired."""
    gate = HG05CheckoutIntegrityGate()
    base_inputs = create_compliant_inputs()

    # Positive
    assert gate.evaluate(base_inputs) is None

    # Negative 1: Signature invalid
    forged_sig = replace(
        base_inputs,
        verification=replace(
            base_inputs.verification,
            checkout=replace(base_inputs.verification.checkout, merchant_signature_valid=False),
        ),
    )
    hit = gate.evaluate(forged_sig)
    assert hit is not None and hit.code == "CHECKOUT_SIGNATURE_INVALID"

    # Negative 2: Checkout expired
    expired_co = replace(
        base_inputs,
        verification=replace(
            base_inputs.verification,
            checkout=replace(
                base_inputs.verification.checkout,
                expires_at=datetime(2026, 11, 24, 11, 0, 0, tzinfo=timezone.utc),
            ),
        ),
    )
    hit = gate.evaluate(expired_co)
    assert hit is not None and hit.code == "CHECKOUT_EXPIRED"


def test_hg06_currency_gate() -> None:
    """HG-06: Checkout currency must equal mandate currency."""
    gate = HG06CurrencyGate()
    base_inputs = create_compliant_inputs()

    # Positive
    assert gate.evaluate(base_inputs) is None

    # Negative: Currency confusion (e.g. paying USD when INR was authorized)
    usd_checkout = replace(
        base_inputs,
        verification=replace(
            base_inputs.verification,
            checkout=replace(base_inputs.verification.checkout, currency="USD"),
        ),
    )
    hit = gate.evaluate(usd_checkout)
    assert hit is not None and hit.code == "CURRENCY_MISMATCH"


def test_hg07_per_txn_cap_gate() -> None:
    """HG-07: Single order must not exceed max_amount_per_txn_minor."""
    gate = HG07PerTxnCapGate()
    base_inputs = create_compliant_inputs()

    # Positive
    assert gate.evaluate(base_inputs) is None

    # Negative: Exceeds per-txn cap of 80,000 INR (e.g. 150,000 INR)
    over_cap = replace(
        base_inputs,
        verification=replace(
            base_inputs.verification,
            checkout=replace(base_inputs.verification.checkout, amount_minor=15000000),
        ),
    )
    hit = gate.evaluate(over_cap)
    assert hit is not None and hit.code == "OVER_TXN_CAP"


def test_hg08_cumulative_caps_gate() -> None:
    """HG-08: Total cumulative spend and transaction count must not exceed mandate caps."""
    gate = HG08CumulativeCapsGate()
    base_inputs = create_compliant_inputs()

    # Positive
    assert gate.evaluate(base_inputs) is None

    # Negative 1: Cumulative spend cap exceeded (spent 80k + new order 64.8k > 100k cap)
    spent_high = replace(base_inputs, mandate=replace(base_inputs.mandate, spent_minor=8000000))
    hit = gate.evaluate(spent_high)
    assert hit is not None and hit.code == "OVER_TOTAL_CAP"

    # Negative 2: Transaction count limit reached (limit 5, count already 5)
    count_reached = replace(base_inputs, mandate=replace(base_inputs.mandate, spend_count=5))
    hit = gate.evaluate(count_reached)
    assert hit is not None and hit.code == "TXN_COUNT_EXCEEDED"


def test_hg09_calculation_recompute_gate() -> None:
    """HG-09: Computed total must equal merchant total and calculation must be reconciled."""
    gate = HG09CalculationRecomputeGate()
    base_inputs = create_compliant_inputs()

    # Positive
    assert gate.evaluate(base_inputs) is None

    # Negative 1: Recompute arithmetic mismatch
    mismatch = replace(
        base_inputs,
        verification=replace(
            base_inputs.verification,
            calculation=replace(base_inputs.verification.calculation, computed_total_minor=7000000),
        ),
    )
    hit = gate.evaluate(mismatch)
    assert hit is not None and hit.code == "TOTAL_RECOMPUTE_MISMATCH"

    # Negative 2: Unreconciled (missing tax or fee components)
    unreconciled = replace(
        base_inputs,
        verification=replace(
            base_inputs.verification,
            calculation=replace(base_inputs.verification.calculation, reconciled=False),
        ),
    )
    hit = gate.evaluate(unreconciled)
    assert hit is not None and hit.code == "TOTAL_RECOMPUTE_MISMATCH"


def test_hg10_agent_statement_gate() -> None:
    """HG-10: Agent's proposal claims must match checkout amount, currency, and merchant."""
    gate = HG10AgentStatementGate()
    base_inputs = create_compliant_inputs()

    # Positive
    assert gate.evaluate(base_inputs) is None

    # Negative 1: Amount mismatch (agent claims 5k, checkout is 64.8k)
    amt_mismatch = replace(
        base_inputs,
        verification=replace(
            base_inputs.verification,
            calculation=replace(base_inputs.verification.calculation, agent_stated_total_minor=5000000),
        ),
    )
    hit = gate.evaluate(amt_mismatch)
    assert hit is not None and hit.code == "AGENT_AMOUNT_MISMATCH"

    # Negative 2: Merchant mismatch (agent claims Amazon, checkout is Croma)
    merchant_mismatch = replace(
        base_inputs,
        verification=replace(
            base_inputs.verification,
            calculation=replace(base_inputs.verification.calculation, agent_stated_merchant_id="mer_amazon_demo"),
        ),
    )
    hit = gate.evaluate(merchant_mismatch)
    assert hit is not None and hit.code == "AGENT_MERCHANT_MISMATCH"


def test_hg11_line_type_and_category_gate() -> None:
    """HG-11: Forbidden line types or unapproved categories must be blocked."""
    gate = HG11LineTypeAndCategoryGate()
    base_inputs = create_compliant_inputs()

    # Positive
    assert gate.evaluate(base_inputs) is None

    # Negative 1: Forbidden line type (e.g. gift card or cash equivalent)
    forbidden_line = replace(
        base_inputs,
        verification=replace(
            base_inputs.verification,
            mandate_match=MandateMatchResult(satisfied=False, violations=("FORBIDDEN_LINE_TYPE",)),
        ),
    )
    hit = gate.evaluate(forbidden_line)
    assert hit is not None and hit.code == "FORBIDDEN_LINE_TYPE"

    # Negative 2: Category not allowed
    forbidden_cat = replace(
        base_inputs,
        verification=replace(
            base_inputs.verification,
            mandate_match=MandateMatchResult(satisfied=False, violations=("CATEGORY_NOT_ALLOWED",)),
        ),
    )
    hit = gate.evaluate(forbidden_cat)
    assert hit is not None and hit.code == "CATEGORY_NOT_ALLOWED"


def test_hg12_critical_claims_gate() -> None:
    """HG-12: Unverified critical claims must block execution."""
    gate = HG12CriticalClaimsGate()
    base_inputs = create_compliant_inputs()

    # Positive
    assert gate.evaluate(base_inputs) is None

    # Negative 1: Product identity unverified
    unverified_product = replace(
        base_inputs,
        verification=replace(
            base_inputs.verification,
            critical_unverified=("PRODUCT_UNVERIFIED",),
        ),
    )
    hit = gate.evaluate(unverified_product)
    assert hit is not None and hit.code == "PRODUCT_UNVERIFIED"

    # Negative 2: Amount unverified
    unverified_amt = replace(
        base_inputs,
        verification=replace(
            base_inputs.verification,
            critical_unverified=("AMOUNT_UNVERIFIED",),
        ),
    )
    hit = gate.evaluate(unverified_amt)
    assert hit is not None and hit.code == "AMOUNT_UNVERIFIED"


def test_hg13_payment_method_gate() -> None:
    """HG-13: Chosen payment rail must be authorized in mandate constraints."""
    gate = HG13PaymentMethodGate()
    base_inputs = create_compliant_inputs()

    # Positive
    assert gate.evaluate(base_inputs) is None

    # Negative: Chosen method crypto/wire not allowed
    bad_method = replace(base_inputs, payment_method="CRYPTO_TRANSFER")
    hit = gate.evaluate(bad_method)
    assert hit is not None and hit.code == "PAYMENT_METHOD_NOT_ALLOWED"


def test_hg14_prompt_injection_gate() -> None:
    """HG-14: High-severity prompt injection in referenced sources must block."""
    gate = HG14PromptInjectionGate()
    base_inputs = create_compliant_inputs()

    # Positive
    assert gate.evaluate(base_inputs) is None

    # Negative: High injection severity
    injected = replace(
        base_inputs,
        risk=replace(
            base_inputs.risk,
            max_injection_severity="HIGH",
            injection_content_ids=("cnt_01JD41_malicious",),
        ),
    )
    hit = gate.evaluate(injected)
    assert hit is not None and hit.code == "INJECTION_DETECTED_HIGH"
    assert hit.detail["content_id"] == "cnt_01JD41_malicious"


def test_hg15_site_risk_gate() -> None:
    """HG-15: High domain risk level must block."""
    gate = HG15SiteRiskGate()
    base_inputs = create_compliant_inputs()

    # Positive
    assert gate.evaluate(base_inputs) is None

    # Negative: High site risk
    risky_site = replace(
        base_inputs,
        risk=replace(base_inputs.risk, site_risk_level="HIGH", site_risk_score=0.92),
    )
    hit = gate.evaluate(risky_site)
    assert hit is not None and hit.code == "SITE_RISK_HIGH"
    assert hit.detail["site_risk_score"] == 0.92


def test_hg16_delivery_and_returns_gate() -> None:
    """HG-16: Stated terms violating user's mandatory delivery or return criteria must block."""
    gate = HG16DeliveryAndReturnsGate()
    base_inputs = create_compliant_inputs()

    # Positive
    assert gate.evaluate(base_inputs) is None

    # Negative 1: Delivery requirement unmet
    bad_delivery = replace(
        base_inputs,
        verification=replace(
            base_inputs.verification,
            mandate_match=MandateMatchResult(satisfied=False, violations=("DELIVERY_REQUIREMENT_UNMET",)),
        ),
    )
    hit = gate.evaluate(bad_delivery)
    assert hit is not None and hit.code == "DELIVERY_REQUIREMENT_UNMET"

    # Negative 2: Returns requirement unmet
    bad_returns = replace(
        base_inputs,
        verification=replace(
            base_inputs.verification,
            mandate_match=MandateMatchResult(satisfied=False, violations=("RETURNS_REQUIREMENT_UNMET",)),
        ),
    )
    hit = gate.evaluate(bad_returns)
    assert hit is not None and hit.code == "RETURNS_REQUIREMENT_UNMET"


# --- 3. Compound Attack Scenario Test ---

def test_compound_attack_scenario_records_all_fired_gates() -> None:
    """Compound attack violating multiple safety invariants records ALL triggered gates.

    Scenario: An attacker attempts a purchase with:
    - High-severity prompt injection (HG-14)
    - Expired checkout signature (HG-05)
    - Over transaction cap (HG-07)
    - Currency confusion USD instead of INR (HG-06)
    - Untrusted merchant domain (HG-03)
    """
    base_inputs = create_compliant_inputs()

    compound_inputs = replace(
        base_inputs,
        # HG-14: High injection
        risk=replace(
            base_inputs.risk,
            max_injection_severity="HIGH",
            injection_content_ids=("cnt_exploit_01",),
        ),
        # HG-05, HG-06, HG-07, HG-03
        verification=replace(
            base_inputs.verification,
            checkout=replace(
                base_inputs.verification.checkout,
                merchant_signature_valid=False,  # HG-05
                currency="USD",                  # HG-06
                amount_minor=99000000,           # HG-07
                merchant_id="mer_attacker_shop", # HG-03
            ),
        ),
    )

    engine = DefaultPolicyEngine(hard_gates=ALL_HARD_GATES)
    res = engine.decide(compound_inputs)

    assert res.outcome == DecisionOutcome.BLOCK
    assert res.stage == EvaluationStage.HARD_GATE
    assert res.trust_score is None

    # Every hard gate was evaluated and recorded
    fired_rule_ids = {hit.rule_id for hit in res.rules_fired}
    expected_rule_ids = {"HG-03", "HG-05", "HG-06", "HG-07", "HG-14"}
    assert expected_rule_ids.issubset(fired_rule_ids), f"Missing expected rules: {expected_rule_ids - fired_rule_ids}"
