"""Canonical schemas for Mandit OS Policy Engine.

Pure, immutable dataclasses representing decision inputs and outcomes.
"""
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Literal


class DecisionOutcome(str, Enum):
    """Possible outcomes of policy evaluation per REFERENCE §11 and migration 0004."""
    ALLOW = "ALLOW"
    STEP_UP = "STEP_UP"
    RETRIEVE_MORE = "RETRIEVE_MORE"
    BLOCK = "BLOCK"


class EvaluationStage(str, Enum):
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
    """Record of an evaluated rule firing, containing the rule identifier, reason code, effect, and details."""
    rule_id: str
    code: str
    effect: DecisionOutcome
    detail: dict[str, Any] | None = None


# --- Team 1 Contracts (Identity & Mandate) ---

@dataclass(frozen=True)
class AgentContext:
    """Agent execution context verified from KYA JWT and RFC 9421 signature."""
    agent_id: str
    operator_id: str
    key_id: str
    key_thumbprint: str  # RFC 7638 JWK thumbprint (base64url)
    scopes: frozenset[str]
    credential_id: str   # jti of KYA JWT
    verified_at: datetime


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

@dataclass(frozen=True)
class RiskSignal:
    """Signal produced by safety scanner (e.g. site reputation or TLS anomalies)."""
    signal_id: str
    code: str
    severity: Literal["LOW", "MEDIUM", "HIGH"]
    detail: dict[str, Any] | None = None


@dataclass(frozen=True)
class RiskSummary:
    """Aggregated safety risk summary for referenced sources and target merchant."""
    merchant_domain: str
    site_risk_score: float  # 0.0 (safe) .. 1.0 (risky)
    site_risk_level: Literal["LOW", "MEDIUM", "HIGH"]
    max_injection_severity: Literal["NONE", "LOW", "MEDIUM", "HIGH"]
    injection_content_ids: tuple[str, ...]
    signals: tuple[RiskSignal, ...]
    scanner_version: str

    def __post_init__(self) -> None:
        if not (0.0 <= self.site_risk_score <= 1.0):
            raise ValueError(f"site_risk_score must be within [0.0, 1.0], got {self.site_risk_score}")


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
    fees_minor: int = 0
    discount_minor: int = 0
    tax_minor: int = 0
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
        """INV-07: Valid if APPROVED, verified signature, matching proposal hash, and not expired."""
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
    """Immutable, frozen inputs snapshot required for pure policy evaluation and deterministic replay."""
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
            raise ValueError(f"user_merchant_history cannot be negative, got {self.user_merchant_history}")


@dataclass(frozen=True)
class DecisionResult:
    """Pure outcome of policy evaluation."""
    outcome: DecisionOutcome
    stage: EvaluationStage
    rules_fired: tuple[RuleHit, ...]
    trust_score: float | None = None
