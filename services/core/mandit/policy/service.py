"""Policy Engine implementation for Mandit OS.

Contains the pure decision evaluation pipeline and DefaultPolicyEngine.
Strictly adheres to Invariant INV-11 (pure function, no I/O, no clock reads).
"""
from mandit.policy.interface import PolicyRule
from mandit.policy.rules import ALL_HARD_GATES
from mandit.policy.schemas import (
    OUTCOME_SEVERITY,
    DecisionOutcome,
    DecisionResult,
    EvaluationStage,
    FrozenDecisionInputs,
    RuleHit,
)

DEFAULT_POLICY_VERSION = "policy-1.0.0"


def decide(
    inputs: FrozenDecisionInputs,
    hard_gates: tuple[PolicyRule, ...] = ALL_HARD_GATES,
    step_up_rules: tuple[PolicyRule, ...] = (),
) -> DecisionResult:
    """Evaluate policy against frozen decision inputs.

    Pure function adhering to Invariant INV-11:
    - Zero I/O, network, or database access.
    - Zero clock calls (timestamps are read strictly from inputs.evaluated_at).
    - Zero random or non-deterministic state.
    - Deterministic replay identical to live evaluation.

    Pipeline stages:
    1. Stage 1 (Hard Gates): Evaluate all hard gates. If ANY fails (BLOCK), return immediately.
    2. Stage 2 (Step-Up Rules): Evaluate advisory heuristics that flag transactions for user review.
    3. Stage 3 (Trust Score Bands): Evaluate grounding trust score (ALLOW/STEP_UP/RETRIEVE_MORE/BLOCK).
       Enforce that RETRIEVE_MORE is permitted only on attempt 1; attempt >= 2 escalates to STEP_UP.
    4. Stage 4 (Confirmation): Human approval can resolve STEP_UP to ALLOW, but never overrides
       BLOCK or RETRIEVE_MORE (INV-07).
    """
    fired: list[RuleHit] = []

    # Stage 1: Hard Gates (HG-01 to HG-16). All evaluated, all recorded.
    for rule in hard_gates:
        hit = rule.evaluate(inputs)
        if hit is not None:
            fired.append(hit)

    # Invariant: If any hard gate triggers a BLOCK, return immediately.
    # Hard gate failures cannot be step-up confirmed and trust score is not evaluated.
    if any(h.effect == DecisionOutcome.BLOCK for h in fired):
        return DecisionResult(
            outcome=DecisionOutcome.BLOCK,
            stage=EvaluationStage.HARD_GATE,
            rules_fired=tuple(fired),
            trust_score=None,
        )

    # Stage 2: Step-up rules (SU-01 to SU-07)
    for rule in step_up_rules:
        hit = rule.evaluate(inputs)
        if hit is not None:
            fired.append(hit)

    # Stage 3: Trust bands (advisory, evaluated after all hard gates pass)
    ts = inputs.verification.trust.score
    if ts >= 0.90:
        band_outcome = DecisionOutcome.ALLOW
    elif ts >= 0.70:
        band_outcome = DecisionOutcome.STEP_UP
        fired.append(
            RuleHit(
                rule_id="TS-01",
                code="TRUST_SCORE_STEP_UP",
                effect=DecisionOutcome.STEP_UP,
                detail={"score": ts, "band": "STEP_UP"},
            )
        )
    elif ts >= 0.50:
        if inputs.attempt >= 2:
            band_outcome = DecisionOutcome.STEP_UP
            fired.append(
                RuleHit(
                    rule_id="TS-02",
                    code="RETRIEVE_MORE_EXHAUSTED",
                    effect=DecisionOutcome.STEP_UP,
                    detail={"score": ts, "attempt": inputs.attempt},
                )
            )
        else:
            band_outcome = DecisionOutcome.RETRIEVE_MORE
            fired.append(
                RuleHit(
                    rule_id="TS-01",
                    code="TRUST_SCORE_RETRIEVE_MORE",
                    effect=DecisionOutcome.RETRIEVE_MORE,
                    detail={"score": ts, "band": "RETRIEVE_MORE"},
                )
            )
    else:
        band_outcome = DecisionOutcome.BLOCK
        fired.append(
            RuleHit(
                rule_id="TS-01",
                code="TRUST_SCORE_BLOCK",
                effect=DecisionOutcome.BLOCK,
                detail={"score": ts, "band": "BLOCK"},
            )
        )

    # Determine candidate outcome based on highest severity
    highest_effect = max(
        [h.effect for h in fired] + [band_outcome],
        key=lambda effect: OUTCOME_SEVERITY[effect],
    )

    # Stage 4: Confirmation resolution (INV-07: Confirmation can satisfy STEP_UP only)
    if (
        highest_effect == DecisionOutcome.STEP_UP
        and inputs.confirmation is not None
        and inputs.confirmation.valid_for(inputs.proposal_hash, inputs.evaluated_at)
    ):
        return DecisionResult(
            outcome=DecisionOutcome.ALLOW,
            stage=EvaluationStage.CONFIRMATION,
            rules_fired=tuple(fired),
            trust_score=ts,
        )

    # Determine stage for non-confirmation outcome
    if highest_effect == DecisionOutcome.BLOCK:
        stage = EvaluationStage.TRUST_SCORE
    elif any(h.rule_id.startswith("SU") for h in fired):
        stage = EvaluationStage.RULE
    else:
        stage = EvaluationStage.TRUST_SCORE

    return DecisionResult(
        outcome=highest_effect,
        stage=stage,
        rules_fired=tuple(fired),
        trust_score=ts,
    )


class DefaultPolicyEngine:
    """Configurable pure Policy Engine instance."""

    def __init__(
        self,
        hard_gates: tuple[PolicyRule, ...] = ALL_HARD_GATES,
        step_up_rules: tuple[PolicyRule, ...] = (),
        version: str = DEFAULT_POLICY_VERSION,
    ) -> None:
        self.hard_gates = hard_gates
        self.step_up_rules = step_up_rules
        self.version = version

    def decide(self, inputs: FrozenDecisionInputs) -> DecisionResult:
        """Evaluate decision for the given frozen inputs."""
        return decide(
            inputs=inputs,
            hard_gates=self.hard_gates,
            step_up_rules=self.step_up_rules,
        )
