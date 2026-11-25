"""Hard Gates for Category restrictions, Critical Claims, and Terms (HG-11, HG-12, HG-16).

Enforces Invariants INV-02 and INV-08.
"""

from mandit.policy.schemas import DecisionOutcome, FrozenDecisionInputs, RuleHit


class HG11LineTypeAndCategoryGate:
    """HG-11: Forbidden line type present or product category not allowed by mandate.

    Invariant INV-02: Agent cannot purchase forbidden goods or service types.
    """

    rule_id: str = "HG-11"
    code: str = "FORBIDDEN_LINE_TYPE"
    effect: DecisionOutcome = DecisionOutcome.BLOCK

    def evaluate(self, inputs: FrozenDecisionInputs) -> RuleHit | None:
        violations = inputs.verification.mandate_match.violations

        if "FORBIDDEN_LINE_TYPE" in violations:
            return RuleHit(
                rule_id=self.rule_id,
                code="FORBIDDEN_LINE_TYPE",
                effect=self.effect,
                detail={"violations": violations},
            )

        if "CATEGORY_NOT_ALLOWED" in violations:
            return RuleHit(
                rule_id=self.rule_id,
                code="CATEGORY_NOT_ALLOWED",
                effect=self.effect,
                detail={"violations": violations},
            )

        return None


class HG12CriticalClaimsGate:
    """HG-12: A critical claim (product identity, amount, merchant) is not VERIFIED.

    Invariant INV-08: No decision may ALLOW an action whose critical facts are unverified.
    """

    rule_id: str = "HG-12"
    code: str = "CRITICAL_CLAIMS_UNVERIFIED"
    effect: DecisionOutcome = DecisionOutcome.BLOCK

    def evaluate(self, inputs: FrozenDecisionInputs) -> RuleHit | None:
        unverified = inputs.verification.critical_unverified

        if not unverified:
            return None

        # Return specific code if identified in critical_unverified
        for candidate_code in ("PRODUCT_UNVERIFIED", "AMOUNT_UNVERIFIED", "MERCHANT_UNVERIFIED"):
            if candidate_code in unverified:
                return RuleHit(
                    rule_id=self.rule_id,
                    code=candidate_code,
                    effect=self.effect,
                    detail={"critical_unverified": unverified},
                )

        return RuleHit(
            rule_id=self.rule_id,
            code="PRODUCT_UNVERIFIED",
            effect=self.effect,
            detail={"critical_unverified": unverified},
        )


class HG16DeliveryAndReturnsGate:
    """HG-16: Stated delivery or returns term violates a mandate requirement.

    Invariant INV-02: Terms of sale must meet user's minimum requirements.
    """

    rule_id: str = "HG-16"
    code: str = "DELIVERY_REQUIREMENT_UNMET"
    effect: DecisionOutcome = DecisionOutcome.BLOCK

    def evaluate(self, inputs: FrozenDecisionInputs) -> RuleHit | None:
        violations = inputs.verification.mandate_match.violations

        if "DELIVERY_REQUIREMENT_UNMET" in violations:
            return RuleHit(
                rule_id=self.rule_id,
                code="DELIVERY_REQUIREMENT_UNMET",
                effect=self.effect,
                detail={"violations": violations},
            )

        if "RETURNS_REQUIREMENT_UNMET" in violations:
            return RuleHit(
                rule_id=self.rule_id,
                code="RETURNS_REQUIREMENT_UNMET",
                effect=self.effect,
                detail={"violations": violations},
            )

        return None
