"""Step-Up Rules (SU-01 to SU-07) for Mandit OS Policy Engine.

Enforces advisory heuristics that require human confirmation for risky but in-mandate actions
per docs/REFERENCE.md §11.2 and docs/modules/04-policy-and-payments.md §5.1.
"""
from mandit.policy.schemas import DecisionOutcome, FrozenDecisionInputs, RuleHit


class SU01ApprovalThresholdRule:
    """SU-01: Total >= mandate approval_threshold_minor.

    Per 01-identity-and-mandate.md §6.1, a threshold of 0 means every purchase requires confirmation.
    """
    rule_id: str = "SU-01"
    code: str = "ABOVE_APPROVAL_THRESHOLD"
    effect: DecisionOutcome = DecisionOutcome.STEP_UP

    def evaluate(self, inputs: FrozenDecisionInputs) -> RuleHit | None:
        amount_minor = inputs.verification.checkout.amount_minor
        threshold_minor = inputs.mandate.constraints.approval_threshold_minor
        signals = inputs.verification.mandate_match.signals

        if "ABOVE_APPROVAL_THRESHOLD" in signals or amount_minor >= threshold_minor:
            return RuleHit(
                rule_id=self.rule_id,
                code=self.code,
                effect=self.effect,
                detail={"amount_minor": amount_minor, "threshold_minor": threshold_minor},
            )
        return None


class SU02NewMerchantRule:
    """SU-02: First purchase by this user from this merchant.

    Triggers when user_merchant_history == 0 (no recorded previous purchases).
    """
    rule_id: str = "SU-02"
    code: str = "NEW_MERCHANT_FOR_USER"
    effect: DecisionOutcome = DecisionOutcome.STEP_UP

    def evaluate(self, inputs: FrozenDecisionInputs) -> RuleHit | None:
        if inputs.user_merchant_history == 0:
            return RuleHit(
                rule_id=self.rule_id,
                code=self.code,
                effect=self.effect,
                detail={
                    "merchant_id": inputs.verification.checkout.merchant_id,
                    "user_merchant_history": inputs.user_merchant_history,
                },
            )
        return None


class SU03MediumSiteRiskRule:
    """SU-03: Merchant domain site risk is MEDIUM."""
    rule_id: str = "SU-03"
    code: str = "SITE_RISK_MEDIUM"
    effect: DecisionOutcome = DecisionOutcome.STEP_UP

    def evaluate(self, inputs: FrozenDecisionInputs) -> RuleHit | None:
        if inputs.risk.site_risk_level == "MEDIUM":
            return RuleHit(
                rule_id=self.rule_id,
                code=self.code,
                effect=self.effect,
                detail={
                    "merchant_domain": inputs.risk.merchant_domain,
                    "site_risk_score": inputs.risk.site_risk_score,
                    "site_risk_level": inputs.risk.site_risk_level,
                },
            )
        return None


class SU04MediumInjectionRule:
    """SU-04: Medium-severity injection in a referenced source."""
    rule_id: str = "SU-04"
    code: str = "INJECTION_DETECTED_MEDIUM"
    effect: DecisionOutcome = DecisionOutcome.STEP_UP

    def evaluate(self, inputs: FrozenDecisionInputs) -> RuleHit | None:
        if inputs.risk.max_injection_severity == "MEDIUM":
            content_ids = list(inputs.risk.injection_content_ids)
            detail = {"content_ids": content_ids}
            if content_ids:
                detail["content_id"] = content_ids[0]

            return RuleHit(
                rule_id=self.rule_id,
                code=self.code,
                effect=self.effect,
                detail=detail,
            )
        return None


class SU05PriceUnverifiedRule:
    """SU-05: The displayed (page) price differs from the catalog price, or the price claim is unverifiable."""
    rule_id: str = "SU-05"
    code: str = "PRICE_MISMATCH"
    effect: DecisionOutcome = DecisionOutcome.STEP_UP

    def evaluate(self, inputs: FrozenDecisionInputs) -> RuleHit | None:
        signals = inputs.verification.mandate_match.signals
        if "PRICE_MISMATCH" in signals:
            return RuleHit(rule_id=self.rule_id, code="PRICE_MISMATCH", effect=self.effect)
        if "PRICE_UNVERIFIED" in signals:
            return RuleHit(rule_id=self.rule_id, code="PRICE_UNVERIFIED", effect=self.effect)

        # Inspect structured PRICE claims from Team 3 (03-grounding §7.1 Table 1)
        for claim in inputs.verification.claims:
            if claim.get("claim_type") == "PRICE":
                status = claim.get("status")
                if status == "MISMATCH":
                    return RuleHit(
                        rule_id=self.rule_id,
                        code="PRICE_MISMATCH",
                        effect=self.effect,
                        detail={"claim_id": claim.get("claim_id"), "status": status},
                    )
                if status in ("UNVERIFIABLE", "STALE"):
                    return RuleHit(
                        rule_id=self.rule_id,
                        code="PRICE_UNVERIFIED",
                        effect=self.effect,
                        detail={"claim_id": claim.get("claim_id"), "status": status},
                    )

        return None


class SU06TermsUnverifiedRule:
    """SU-06: Delivery or returns term unverifiable while the mandate requires it."""
    rule_id: str = "SU-06"
    code: str = "DELIVERY_UNVERIFIED"
    effect: DecisionOutcome = DecisionOutcome.STEP_UP

    def evaluate(self, inputs: FrozenDecisionInputs) -> RuleHit | None:
        signals = inputs.verification.mandate_match.signals

        if "DELIVERY_UNVERIFIED" in signals:
            return RuleHit(
                rule_id=self.rule_id,
                code="DELIVERY_UNVERIFIED",
                effect=self.effect,
                detail={"max_delivery_days": inputs.mandate.constraints.max_delivery_days},
            )

        if "RETURNS_UNVERIFIED" in signals:
            return RuleHit(
                rule_id=self.rule_id,
                code="RETURNS_UNVERIFIED",
                effect=self.effect,
                detail={"require_refund_policy": inputs.mandate.constraints.require_refund_policy},
            )

        # Direct check against constraints if signal was not pre-populated
        constraints = inputs.mandate.constraints
        for claim in inputs.verification.claims:
            ctype = claim.get("claim_type")
            cstatus = claim.get("status")
            if ctype == "DELIVERY_TERMS" and constraints.max_delivery_days is not None:
                if cstatus in ("UNVERIFIABLE", "STALE", "MISMATCH"):
                    return RuleHit(
                        rule_id=self.rule_id,
                        code="DELIVERY_UNVERIFIED",
                        effect=self.effect,
                        detail={"claim_id": claim.get("claim_id"), "status": cstatus},
                    )
            if ctype == "RETURNS_POLICY" and constraints.require_refund_policy:
                if cstatus in ("UNVERIFIABLE", "STALE", "MISMATCH"):
                    return RuleHit(
                        rule_id=self.rule_id,
                        code="RETURNS_UNVERIFIED",
                        effect=self.effect,
                        detail={"claim_id": claim.get("claim_id"), "status": cstatus},
                    )

        return None


class SU07PricierAlternativeRule:
    """SU-07: The agent chose a pricier item than a cheaper item it saw that matches every mandate constraint.

    Factual-steering defence per docs/modules/03-grounding-and-verification.md §7.6.
    """
    rule_id: str = "SU-07"
    code: str = "PRICIER_ALTERNATIVE_CHOSEN"
    effect: DecisionOutcome = DecisionOutcome.STEP_UP

    def evaluate(self, inputs: FrozenDecisionInputs) -> RuleHit | None:
        selection = inputs.verification.selection

        if selection.pricier_alternative_chosen:
            return RuleHit(
                rule_id=self.rule_id,
                code=self.code,
                effect=self.effect,
                detail={
                    "cheapest_matching_minor": selection.cheapest_matching_minor,
                    "difference_minor": selection.difference_minor,
                },
            )
        return None
