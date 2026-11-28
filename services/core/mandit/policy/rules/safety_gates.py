"""Hard Gates for Injection Firewall and Site Risk (HG-14, HG-15).

Enforces Invariant INV-10.
"""

from typing import Any

from mandit.policy.schemas import DecisionOutcome, FrozenDecisionInputs, RuleHit


class HG14PromptInjectionGate:
    """HG-14: High-severity injection found in a source referenced by the proposal.

    Invariant INV-10: No transaction may proceed if influenced by hostile prompt injection.
    """

    rule_id: str = "HG-14"
    code: str = "INJECTION_DETECTED_HIGH"
    effect: DecisionOutcome = DecisionOutcome.BLOCK

    def evaluate(self, inputs: FrozenDecisionInputs) -> RuleHit | None:
        risk = inputs.risk

        if risk.max_injection_severity == "HIGH":
            content_ids = list(risk.injection_content_ids)
            detail: dict[str, Any] = {"content_ids": content_ids}
            if content_ids:
                detail["content_id"] = content_ids[0]

            return RuleHit(
                rule_id=self.rule_id,
                code="INJECTION_DETECTED_HIGH",
                effect=self.effect,
                detail=detail,
            )
        return None


class HG15SiteRiskGate:
    """HG-15: Merchant domain site risk is HIGH.

    Invariant INV-10: Transactions with dangerous or high-risk sites are blocked.
    """

    rule_id: str = "HG-15"
    code: str = "SITE_RISK_HIGH"
    effect: DecisionOutcome = DecisionOutcome.BLOCK

    def evaluate(self, inputs: FrozenDecisionInputs) -> RuleHit | None:
        risk = inputs.risk

        if risk.site_risk_level == "HIGH":
            return RuleHit(
                rule_id=self.rule_id,
                code="SITE_RISK_HIGH",
                effect=self.effect,
                detail={
                    "domain": risk.merchant_domain,
                    "site_risk_score": risk.site_risk_score,
                    "site_risk_level": risk.site_risk_level,
                },
            )
        return None
