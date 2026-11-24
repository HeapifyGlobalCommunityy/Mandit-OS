"""Hard Gates for Agent and Mandate identity (HG-01, HG-02).

Enforces Invariants INV-01 and INV-02.
"""
from mandit.policy.schemas import DecisionOutcome, FrozenDecisionInputs, RuleHit


class HG01AgentIdentityGate:
    """HG-01: Agent identity invalid, revoked, key not bound, or operator not verified.

    Invariant INV-01: Every agent action must be attributed to an identified, verified operator.
    """
    rule_id: str = "HG-01"
    code: str = "AGENT_REVOKED"
    effect: DecisionOutcome = DecisionOutcome.BLOCK

    def evaluate(self, inputs: FrozenDecisionInputs) -> RuleHit | None:
        identity = inputs.identity

        if not identity.is_active:
            return RuleHit(
                rule_id=self.rule_id,
                code="AGENT_REVOKED",
                effect=self.effect,
                detail={"agent_id": identity.agent.agent_id, "is_active": False},
            )

        if not identity.operator_verified:
            return RuleHit(
                rule_id=self.rule_id,
                code="OPERATOR_NOT_VERIFIED",
                effect=self.effect,
                detail={"operator_id": identity.agent.operator_id, "operator_verified": False},
            )

        if not identity.kya_token_valid:
            return RuleHit(
                rule_id=self.rule_id,
                code="KYA_TOKEN_INVALID",
                effect=self.effect,
                detail={"agent_id": identity.agent.agent_id, "kya_token_valid": False},
            )

        if not identity.key_bound:
            return RuleHit(
                rule_id=self.rule_id,
                code="KEY_NOT_BOUND",
                effect=self.effect,
                detail={"key_id": identity.agent.key_id, "thumbprint": identity.agent.key_thumbprint},
            )

        return None


class HG02MandateValidityGate:
    """HG-02: Mandate invalid, expired, revoked, superseded, exhausted, or not bound to this agent.

    Invariant INV-02: No agent action can exceed the user's explicit Intent Mandate.
    """
    rule_id: str = "HG-02"
    code: str = "MANDATE_INVALID"
    effect: DecisionOutcome = DecisionOutcome.BLOCK

    def evaluate(self, inputs: FrozenDecisionInputs) -> RuleHit | None:
        mandate = inputs.mandate
        now = inputs.evaluated_at
        agent = inputs.identity.agent

        # Check status
        if mandate.status != "ACTIVE":
            code = f"MANDATE_{mandate.status}"
            return RuleHit(
                rule_id=self.rule_id,
                code=code,
                effect=self.effect,
                detail={"mandate_id": mandate.mandate_id, "status": mandate.status},
            )

        # Check validity window
        if now < mandate.not_before:
            return RuleHit(
                rule_id=self.rule_id,
                code="MANDATE_NOT_YET_VALID",
                effect=self.effect,
                detail={"now": now.isoformat(), "not_before": mandate.not_before.isoformat()},
            )

        if now >= mandate.expires_at:
            return RuleHit(
                rule_id=self.rule_id,
                code="MANDATE_EXPIRED",
                effect=self.effect,
                detail={"now": now.isoformat(), "expires_at": mandate.expires_at.isoformat()},
            )

        # Check agent and key binding
        if mandate.agent_id != agent.agent_id or mandate.agent_key_thumbprint != agent.key_thumbprint:
            return RuleHit(
                rule_id=self.rule_id,
                code="AGENT_NOT_BOUND_TO_MANDATE",
                effect=self.effect,
                detail={
                    "mandate_agent_id": mandate.agent_id,
                    "acting_agent_id": agent.agent_id,
                    "thumbprint_match": mandate.agent_key_thumbprint == agent.key_thumbprint,
                },
            )

        return None
