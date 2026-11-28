"""Canonical schemas for Mandit OS Policy Engine.

Pure, immutable dataclasses representing decision inputs and outcomes.
"""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

# Other teams' published types are used as-is, so `isinstance` checks and snapshots see the
# objects those modules actually return (CONTRIBUTING rule 5: import from the interface only).
from mandit.identity.schemas import AgentContext as AgentContext
from mandit.safety.interface import RiskSignal as RiskSignal
from mandit.safety.interface import RiskSummary as RiskSummary


class DecisionOutcome(StrEnum):
    """Possible outcomes of policy evaluation per REFERENCE §11 and migration 0004."""

    ALLOW = "ALLOW"
    STEP_UP = "STEP_UP"
    RETRIEVE_MORE = "RETRIEVE_MORE"
    BLOCK = "BLOCK"


class EvaluationStage(StrEnum):
    """Evaluation stage recording which layer finalized the decision per migration 0004."""

    HARD_GATE = "HARD_GATE"
    RULE = "RULE"
    TRUST_SCORE = "TRUST_SCORE"
    CONFIRMATION = "CONFIRMATION"


# Severity order for rule resolution: BLOCK (3) > RETRIEVE_MORE (2) > STEP_UP (1) > ALLOW (0)
OUTCOME_SEVERITY: dict[DecisionOutcome, int] = {
    DecisionOutcome.ALLOW: 0,
    DecisionOutcome.STEP_UP: 1,
    DecisionOutcome.RETRIEVE_MORE: 2,
    DecisionOutcome.BLOCK: 3,
}


@dataclass(frozen=True)
class RuleHit:
    """Record of an evaluated rule firing, containing rule_id, code, effect, and details."""

    rule_id: str
    code: str
    effect: DecisionOutcome
    detail: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "rule_id": self.rule_id,
            "code": self.code,
            "effect": str(self.effect.value if hasattr(self.effect, "value") else self.effect),
        }
        if self.detail is not None:
            d["detail"] = self.detail
        return d


# --- Team 1 Contracts (Identity & Mandate) ---


@dataclass(frozen=True)
class IdentityResult:
    """Active identity status of the agent, operator, KYA token, and key binding."""

    agent: AgentContext
    is_active: bool
    operator_verified: bool
    kya_token_valid: bool = True
    key_bound: bool = True


@dataclass(frozen=True)
class MandateConstraints:
    """Structured constraints defined within a signed Intent Mandate."""

    allowed_merchants: tuple[str, ...] = ()
    allowed_domains: tuple[str, ...] = ()
    allowed_categories: tuple[str, ...] = ()
    currency: str = "INR"
    max_amount_per_txn_minor: int = 0
    max_amount_total_minor: int = 0
    max_txn_count: int = 0
    approval_threshold_minor: int = 0
    forbidden_line_types: tuple[str, ...] = ()
    payment_methods: tuple[str, ...] = ("CARD_TOKEN", "UPI")
    require_refund_policy: bool = False
    min_returns_window_days: int | None = None
    max_delivery_days: int | None = None


@dataclass(frozen=True)
class MandateSnapshot:
    """Snapshot of a user-signed mandate at evaluation time."""

    mandate_id: str
    version: int
    user_id: str
    agent_id: str
    agent_key_thumbprint: str
    constraints: MandateConstraints
    not_before: datetime
    expires_at: datetime
    status: Literal["ACTIVE", "EXPIRED", "REVOKED", "SUPERSEDED", "EXHAUSTED", "REJECTED"]
    spent_minor: int
    spend_count: int


# --- Team 2 Contracts (Safety Scanning) ---


# --- Team 3 Contracts (Grounding & Verification) ---


@dataclass(frozen=True)
class CheckoutSnapshot:
    """Merchant-signed checkout snapshot verified by Team 3."""

    checkout_id: str
    checkout_hash: str
    merchant_id: str
    merchant_domain: str
    payee_id: str
    amount_minor: int
    currency: str
    merchant_signature_valid: bool
    expires_at: datetime

    def __post_init__(self) -> None:
        if self.expires_at.tzinfo is None:
            raise ValueError("checkout.expires_at must be timezone-aware")
        if self.amount_minor <= 0:
            raise ValueError(f"checkout.amount_minor must be positive, got {self.amount_minor}")


@dataclass(frozen=True)
class CalculationResult:
    """Deterministic calculation and arithmetic reconciliation from Team 3."""

    computed_total_minor: int
    merchant_total_minor: int
    agent_stated_total_minor: int
    reconciled: bool
    calculator_version: str
    subtotal_minor: int = 0
    # None means Team 3 did not report the amount; the approval screen then shows "unknown".
    fees_minor: int | None = None
    discount_minor: int = 0
    tax_minor: int | None = None
    agent_stated_merchant_id: str | None = None
    agent_stated_currency: str | None = None


@dataclass(frozen=True)
class MandateMatchResult:
    """Mandate matching evaluation result produced by Team 1 / Team 3."""

    satisfied: bool
    violations: tuple[str, ...] = ()
    signals: tuple[str, ...] = ()


@dataclass(frozen=True)
class SelectionResult:
    """Factual steering and price comparison sanity result."""

    pricier_alternative_chosen: bool
    cheapest_matching_minor: int | None = None
    difference_minor: int | None = None


@dataclass(frozen=True)
class TrustResult:
    """Trust Score computation result per REFERENCE §11.3."""

    score: float  # 0.000 .. 1.000
    band: Literal["ALLOW", "STEP_UP", "RETRIEVE_MORE", "BLOCK"]
    components: dict[str, float]
    weights: dict[str, float]
    trust_model_version: str

    def __post_init__(self) -> None:
        if not (0.0 <= self.score <= 1.0):
            raise ValueError(f"trust score must be within [0.0, 1.0], got {self.score}")


@dataclass(frozen=True)
class VerificationReport:
    """Complete claim and facts verification report from Team 3."""

    verification_id: str
    proposal_id: str
    proposal_hash: str
    attempt: int
    checkout: CheckoutSnapshot
    calculation: CalculationResult
    mandate_match: MandateMatchResult
    selection: SelectionResult
    trust: TrustResult
    claims: tuple[dict[str, Any], ...] = ()
    critical_unverified: tuple[str, ...] = ()
    abstentions: tuple[dict[str, Any], ...] = ()
    verifier_version: str = "verify-1.0.0"
    created_at: datetime | None = None

    def __post_init__(self) -> None:
        if self.attempt not in (1, 2):
            raise ValueError(f"attempt must be 1 or 2, got {self.attempt}")


# --- Human Confirmation Snapshot ---


@dataclass(frozen=True)
class ConfirmationSnapshot:
    """Human confirmation record for step-up resolution."""

    confirmation_id: str
    status: Literal["PENDING", "APPROVED", "REJECTED", "EXPIRED", "INVALIDATED"]
    proposal_hash: str
    expires_at: datetime
    response_signature: dict[str, Any] | None = None
    signature_verified: bool = False
    responded_at: datetime | None = None

    def __post_init__(self) -> None:
        if self.expires_at.tzinfo is None:
            raise ValueError("confirmation.expires_at must be timezone-aware")

    def valid_for(self, proposal_hash: str, evaluated_at: datetime) -> bool:
        """INV-07: Valid if APPROVED, verified signature, matching hash, and unexpired."""
        if evaluated_at.tzinfo is None:
            raise ValueError("evaluated_at must be timezone-aware")
        return (
            self.status == "APPROVED"
            and self.signature_verified is True
            and self.response_signature is not None
            and self.proposal_hash == proposal_hash
            and evaluated_at < self.expires_at
        )


# --- Policy Input and Output Contracts ---


@dataclass(frozen=True)
class FrozenDecisionInputs:
    """Immutable frozen inputs snapshot for pure policy evaluation and deterministic replay."""

    evaluated_at: datetime
    attempt: int  # 1 or 2
    proposal_id: str
    proposal_hash: str
    transaction_id: str
    identity: IdentityResult
    mandate: MandateSnapshot
    risk: RiskSummary
    verification: VerificationReport
    user_merchant_history: int  # count of previous purchases from this merchant
    payment_method: str = "CARD_TOKEN"
    confirmation: ConfirmationSnapshot | None = None

    def __post_init__(self) -> None:
        if self.evaluated_at.tzinfo is None:
            raise ValueError("evaluated_at must be timezone-aware")
        if self.attempt not in (1, 2):
            raise ValueError(f"attempt must be 1 or 2, got {self.attempt}")
        if self.user_merchant_history < 0:
            raise ValueError(
                f"user_merchant_history cannot be negative, got {self.user_merchant_history}"
            )


@dataclass(frozen=True)
class DecisionResult:
    """Pure outcome of policy evaluation."""

    outcome: DecisionOutcome
    stage: EvaluationStage
    rules_fired: tuple[RuleHit, ...]
    trust_score: float | None = None


@dataclass(frozen=True)
class Decision:
    """Canonical Policy Decision representation matching migration 0004 and API response."""

    decision_id: str
    proposal_id: str
    proposal_hash: str
    transaction_id: str
    attempt: int
    outcome: DecisionOutcome
    stage: EvaluationStage
    rules_fired: tuple[RuleHit, ...]
    trust_score: float | None
    policy_version: str
    trust_model_version: str | None
    inputs_snapshot_id: str
    inputs_hash: str
    confirmation_id: str | None
    expires_at: datetime
    signature: dict[str, Any]
    created_at: datetime

    def __post_init__(self) -> None:
        if self.expires_at.tzinfo is None:
            raise ValueError("decision.expires_at must be timezone-aware")
        if self.created_at.tzinfo is None:
            raise ValueError("decision.created_at must be timezone-aware")

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision_id": self.decision_id,
            "proposal_id": self.proposal_id,
            "proposal_hash": self.proposal_hash,
            "transaction_id": self.transaction_id,
            "attempt": self.attempt,
            "outcome": str(self.outcome.value if hasattr(self.outcome, "value") else self.outcome),
            "stage": str(self.stage.value if hasattr(self.stage, "value") else self.stage),
            "rules_fired": [r.to_dict() for r in self.rules_fired],
            "trust_score": float(self.trust_score) if self.trust_score is not None else None,
            "policy_version": self.policy_version,
            "trust_model_version": self.trust_model_version,
            "inputs_snapshot_id": self.inputs_snapshot_id,
            "inputs_hash": self.inputs_hash,
            "confirmation_id": self.confirmation_id,
            "expires_at": self.expires_at.isoformat(),
            "signature": self.signature,
            "created_at": self.created_at.isoformat(),
        }


def to_snapshot_dict(inputs: FrozenDecisionInputs) -> dict[str, Any]:
    """Serialize inputs to a plain JSON-compatible dictionary for Evidence snapshotting."""
    return {
        "evaluated_at": inputs.evaluated_at.isoformat(),
        "attempt": inputs.attempt,
        "proposal_id": inputs.proposal_id,
        "proposal_hash": inputs.proposal_hash,
        "transaction_id": inputs.transaction_id,
        "payment_method": inputs.payment_method,
        "user_merchant_history": inputs.user_merchant_history,
        "identity": {
            "agent": {
                "agent_id": inputs.identity.agent.agent_id,
                "operator_id": inputs.identity.agent.operator_id,
                "key_id": inputs.identity.agent.key_id,
                "key_thumbprint": inputs.identity.agent.key_thumbprint,
                "scopes": sorted(list(inputs.identity.agent.scopes)),
                "credential_id": inputs.identity.agent.credential_id,
                "verified_at": inputs.identity.agent.verified_at.isoformat(),
            },
            "is_active": inputs.identity.is_active,
            "operator_verified": inputs.identity.operator_verified,
            "kya_token_valid": inputs.identity.kya_token_valid,
            "key_bound": inputs.identity.key_bound,
        },
        "mandate": {
            "mandate_id": inputs.mandate.mandate_id,
            "user_id": inputs.mandate.user_id,
            "version": inputs.mandate.version,
            "agent_id": inputs.mandate.agent_id,
            "agent_key_thumbprint": inputs.mandate.agent_key_thumbprint,
            "status": inputs.mandate.status,
            "spent_minor": inputs.mandate.spent_minor,
            "spend_count": inputs.mandate.spend_count,
            "not_before": inputs.mandate.not_before.isoformat(),
            "expires_at": inputs.mandate.expires_at.isoformat(),
            "constraints": {
                "approval_threshold_minor": inputs.mandate.constraints.approval_threshold_minor,
                "max_amount_per_txn_minor": inputs.mandate.constraints.max_amount_per_txn_minor,
                "max_amount_total_minor": inputs.mandate.constraints.max_amount_total_minor,
                "max_txn_count": inputs.mandate.constraints.max_txn_count,
                "allowed_merchants": sorted(list(inputs.mandate.constraints.allowed_merchants)),
                "allowed_domains": sorted(list(inputs.mandate.constraints.allowed_domains)),
                "allowed_categories": sorted(list(inputs.mandate.constraints.allowed_categories)),
                "forbidden_line_types": sorted(
                    list(inputs.mandate.constraints.forbidden_line_types)
                ),
                "payment_methods": sorted(list(inputs.mandate.constraints.payment_methods)),
                "currency": inputs.mandate.constraints.currency,
                "require_refund_policy": inputs.mandate.constraints.require_refund_policy,
                "min_returns_window_days": inputs.mandate.constraints.min_returns_window_days,
                "max_delivery_days": inputs.mandate.constraints.max_delivery_days,
            },
        },
        "risk": {
            "merchant_domain": inputs.risk.merchant_domain,
            "site_risk_score": inputs.risk.site_risk_score,
            "site_risk_level": inputs.risk.site_risk_level,
            "max_injection_severity": inputs.risk.max_injection_severity,
            "injection_content_ids": list(inputs.risk.injection_content_ids),
            "scanner_version": inputs.risk.scanner_version,
            "signals": [
                {"code": s.code, "weight": s.weight, "detail": s.detail, "source": s.source}
                for s in inputs.risk.signals
            ],
        },
        "verification": {
            "verification_id": inputs.verification.verification_id,
            "proposal_id": inputs.verification.proposal_id,
            "proposal_hash": inputs.verification.proposal_hash,
            "attempt": inputs.verification.attempt,
            "checkout": {
                "checkout_id": inputs.verification.checkout.checkout_id,
                "checkout_hash": inputs.verification.checkout.checkout_hash,
                "merchant_id": inputs.verification.checkout.merchant_id,
                "merchant_domain": inputs.verification.checkout.merchant_domain,
                "payee_id": inputs.verification.checkout.payee_id,
                "amount_minor": inputs.verification.checkout.amount_minor,
                "currency": inputs.verification.checkout.currency,
                "merchant_signature_valid": inputs.verification.checkout.merchant_signature_valid,
                "expires_at": inputs.verification.checkout.expires_at.isoformat(),
            },
            "calculation": {
                "computed_total_minor": inputs.verification.calculation.computed_total_minor,
                "merchant_total_minor": inputs.verification.calculation.merchant_total_minor,
                "agent_stated_total_minor": (
                    inputs.verification.calculation.agent_stated_total_minor
                ),
                "reconciled": inputs.verification.calculation.reconciled,
                "calculator_version": inputs.verification.calculation.calculator_version,
                "subtotal_minor": inputs.verification.calculation.subtotal_minor,
                "fees_minor": inputs.verification.calculation.fees_minor,
                "discount_minor": inputs.verification.calculation.discount_minor,
                "tax_minor": inputs.verification.calculation.tax_minor,
                "agent_stated_merchant_id": (
                    inputs.verification.calculation.agent_stated_merchant_id
                ),
                "agent_stated_currency": inputs.verification.calculation.agent_stated_currency,
            },
            "mandate_match": {
                "satisfied": inputs.verification.mandate_match.satisfied,
                "violations": list(inputs.verification.mandate_match.violations),
                "signals": list(inputs.verification.mandate_match.signals),
            },
            "selection": {
                "pricier_alternative_chosen": (
                    inputs.verification.selection.pricier_alternative_chosen
                ),
                "cheapest_matching_minor": inputs.verification.selection.cheapest_matching_minor,
                "difference_minor": inputs.verification.selection.difference_minor,
            },
            "trust": {
                "score": inputs.verification.trust.score,
                "band": inputs.verification.trust.band,
                "components": inputs.verification.trust.components,
                "weights": inputs.verification.trust.weights,
                "trust_model_version": inputs.verification.trust.trust_model_version,
            },
            "claims": list(inputs.verification.claims),
            "critical_unverified": list(inputs.verification.critical_unverified),
            "abstentions": list(inputs.verification.abstentions),
            "verifier_version": inputs.verification.verifier_version,
            "created_at": inputs.verification.created_at.isoformat()
            if inputs.verification.created_at
            else None,
        },
        "confirmation": (
            {
                "confirmation_id": inputs.confirmation.confirmation_id,
                "status": inputs.confirmation.status,
                "proposal_hash": inputs.confirmation.proposal_hash,
                "expires_at": inputs.confirmation.expires_at.isoformat(),
                "response_signature": inputs.confirmation.response_signature,
                "signature_verified": inputs.confirmation.signature_verified,
                "responded_at": inputs.confirmation.responded_at.isoformat()
                if inputs.confirmation.responded_at
                else None,
            }
            if inputs.confirmation
            else None
        ),
    }
