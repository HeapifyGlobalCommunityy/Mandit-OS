"""SQLAlchemy models for Payments, PSP Webhook Events, and Idempotency Keys.

Matches migration 0004_policy_and_payments.py exactly (REFERENCE §4, §8, §13).
"""

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    DateTime,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column

from mandit.common.models import Base
from mandit.payments.schemas import Payment, PaymentRail, PaymentStatus


def now_utc() -> datetime:
    return datetime.now(UTC)


def ensure_tz(dt: Any) -> datetime | None:
    if isinstance(dt, datetime):
        if dt.tzinfo is None:
            return dt.replace(tzinfo=UTC)
        return dt
    return None


class PaymentModel(Base):
    """SQLAlchemy model for payments table matching migration 0004."""

    __tablename__ = "payments"

    payment_id: Mapped[str] = mapped_column(Text, primary_key=True)
    proposal_id: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    token_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    rail: Mapped[str] = mapped_column(Text, nullable=False)
    psp_payment_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(Text, nullable=False)
    amount_minor: Mapped[int] = mapped_column(BigInteger, nullable=False)
    currency: Mapped[str] = mapped_column(String(3), nullable=False)
    failure_code: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=now_utc
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=now_utc, onupdate=now_utc
    )

    def to_schema(self) -> Payment:
        """Convert SQLAlchemy model to canonical domain Payment dataclass."""
        created = ensure_tz(self.created_at) or self.created_at
        updated = ensure_tz(self.updated_at) or self.updated_at
        return Payment(
            payment_id=self.payment_id,
            proposal_id=self.proposal_id,
            token_id=self.token_id,
            rail=PaymentRail(self.rail),
            psp_payment_id=self.psp_payment_id,
            status=PaymentStatus(self.status),
            amount_minor=self.amount_minor,
            currency=self.currency,
            failure_code=self.failure_code,
            created_at=created,
            updated_at=updated,
        )


class PspWebhookEventModel(Base):
    """SQLAlchemy model for psp_webhook_events table matching migration 0004."""

    __tablename__ = "psp_webhook_events"

    psp_event_id: Mapped[str] = mapped_column(Text, primary_key=True)
    payment_id: Mapped[str] = mapped_column(Text, nullable=False)
    body_hash: Mapped[str] = mapped_column(Text, nullable=False)
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=now_utc
    )


class IdempotencyKeyModel(Base):
    """SQLAlchemy model for idempotency_keys table matching migration 0004."""

    __tablename__ = "idempotency_keys"

    key: Mapped[str] = mapped_column(Text, primary_key=True)
    route: Mapped[str] = mapped_column(Text, nullable=False)
    request_hash: Mapped[str] = mapped_column(Text, nullable=False)
    response_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    response_body: Mapped[dict[str, Any] | list[Any] | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=now_utc
    )
