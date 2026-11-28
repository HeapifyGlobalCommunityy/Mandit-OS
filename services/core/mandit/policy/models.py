"""SQLAlchemy models for Policy decisions and Confirmations.

Matches migration 0004_policy_and_payments.py exactly.
"""

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    DateTime,
    Integer,
    Numeric,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column

from mandit.common.models import Base
from mandit.policy.schemas import (
    Decision,
    DecisionOutcome,
    EvaluationStage,
    RuleHit,
)


def now_utc() -> datetime:
    return datetime.now(UTC)


def ensure_tz(dt: Any) -> datetime | None:
    if isinstance(dt, datetime):
        if dt.tzinfo is None:
            return dt.replace(tzinfo=UTC)
        return dt
    return None


class DecisionModel(Base):
    """SQLAlchemy model for decisions table matching migration 0004."""

    __tablename__ = "decisions"

    decision_id: Mapped[str] = mapped_column(Text, primary_key=True)
    proposal_id: Mapped[str] = mapped_column(Text, nullable=False)
    proposal_hash: Mapped[str] = mapped_column(Text, nullable=False)
    transaction_id: Mapped[str] = mapped_column(Text, nullable=False)
    attempt: Mapped[int] = mapped_column(Integer, nullable=False)
    outcome: Mapped[str] = mapped_column(Text, nullable=False)
    stage: Mapped[str] = mapped_column(Text, nullable=False)
    rules_fired: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False)
    trust_score: Mapped[float | None] = mapped_column(Numeric(4, 3), nullable=True)
    policy_version: Mapped[str] = mapped_column(Text, nullable=False)
    trust_model_version: Mapped[str | None] = mapped_column(Text, nullable=True)
    inputs_snapshot_id: Mapped[str] = mapped_column(Text, nullable=False)
    inputs_hash: Mapped[str] = mapped_column(Text, nullable=False)
    confirmation_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    signature: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=now_utc
    )

    def to_schema(self) -> Decision:
        """Convert SQLAlchemy model to canonical Decision dataclass."""
        raw_rules = self.rules_fired or []
        rules = tuple(
            RuleHit(
                rule_id=str(r["rule_id"]),
                code=str(r["code"]),
                effect=DecisionOutcome(str(r["effect"])),
                detail=r.get("detail"),
            )
            for r in raw_rules
        )
        return Decision(
            decision_id=self.decision_id,
            proposal_id=self.proposal_id,
            proposal_hash=self.proposal_hash,
            transaction_id=self.transaction_id,
            attempt=self.attempt,
            outcome=DecisionOutcome(self.outcome),
            stage=EvaluationStage(self.stage),
            rules_fired=rules,
            trust_score=float(self.trust_score) if self.trust_score is not None else None,
            policy_version=self.policy_version,
            trust_model_version=self.trust_model_version,
            inputs_snapshot_id=self.inputs_snapshot_id,
            inputs_hash=self.inputs_hash,
            confirmation_id=self.confirmation_id,
            expires_at=ensure_tz(self.expires_at) or self.expires_at,
            signature=self.signature,
            created_at=ensure_tz(self.created_at) or self.created_at,
        )

    @classmethod
    def from_schema(cls, d: Decision) -> "DecisionModel":
        """Create SQLAlchemy model from canonical Decision dataclass."""
        return cls(
            decision_id=d.decision_id,
            proposal_id=d.proposal_id,
            proposal_hash=d.proposal_hash,
            transaction_id=d.transaction_id,
            attempt=d.attempt,
            outcome=d.outcome.value if hasattr(d.outcome, "value") else str(d.outcome),
            stage=d.stage.value if hasattr(d.stage, "value") else str(d.stage),
            rules_fired=[r.to_dict() for r in d.rules_fired],
            trust_score=d.trust_score,
            policy_version=d.policy_version,
            trust_model_version=d.trust_model_version,
            inputs_snapshot_id=d.inputs_snapshot_id,
            inputs_hash=d.inputs_hash,
            confirmation_id=d.confirmation_id,
            expires_at=d.expires_at,
            signature=d.signature,
            created_at=d.created_at,
        )


class ConfirmationModel(Base):
    """SQLAlchemy model for confirmations table matching migration 0004."""

    __tablename__ = "confirmations"

    confirmation_id: Mapped[str] = mapped_column(Text, primary_key=True)
    decision_id: Mapped[str] = mapped_column(Text, nullable=False)
    proposal_id: Mapped[str] = mapped_column(Text, nullable=False)
    proposal_hash: Mapped[str] = mapped_column(Text, nullable=False)
    user_id: Mapped[str] = mapped_column(Text, nullable=False)
    display: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    challenge: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False)
    response_signature: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    responded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    def to_dict(self) -> dict[str, Any]:
        exp = ensure_tz(self.expires_at)
        resp = ensure_tz(self.responded_at)
        return {
            "confirmation_id": self.confirmation_id,
            "decision_id": self.decision_id,
            "proposal_id": self.proposal_id,
            "proposal_hash": self.proposal_hash,
            "user_id": self.user_id,
            "display": self.display,
            "challenge": self.challenge,
            "status": self.status,
            "response_signature": self.response_signature,
            "responded_at": resp.isoformat() if resp else None,
            "expires_at": exp.isoformat() if exp else None,
        }
