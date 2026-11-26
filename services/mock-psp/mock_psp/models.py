"""SQLAlchemy models for Mock PSP Service.

Maintains an independent database schema strictly isolated from Mandit Core (REFERENCE §3.3).
"""

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, BigInteger, DateTime, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def now_utc() -> datetime:
    return datetime.now(UTC)


def ensure_tz(dt: Any) -> datetime | None:
    if isinstance(dt, datetime):
        if dt.tzinfo is None:
            return dt.replace(tzinfo=UTC)
        return dt
    return None


class PspBase(DeclarativeBase):
    """Declarative base exclusively for Mock PSP tables."""

    pass


class PspScopedCredentialModel(PspBase):
    """Persisted seller-bound, amount-capped, expiring credentials from Mandit tokens."""

    __tablename__ = "psp_scoped_credentials"

    credential_id: Mapped[str] = mapped_column(Text, primary_key=True)
    token_id: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    merchant_id: Mapped[str] = mapped_column(Text, nullable=False)
    max_amount_minor: Mapped[int] = mapped_column(BigInteger, nullable=False)
    currency: Mapped[str] = mapped_column(String(3), nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False, default="ACTIVE")
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=now_utc
    )


class PspPaymentModel(PspBase):
    """Authoritative persistent record of synthetic card and UPI payments."""

    __tablename__ = "psp_payments"

    psp_payment_id: Mapped[str] = mapped_column(Text, primary_key=True)
    credential_id: Mapped[str | None] = mapped_column(Text, nullable=True, index=True)
    intent_id: Mapped[str | None] = mapped_column(Text, nullable=True, index=True)
    merchant_id: Mapped[str] = mapped_column(Text, nullable=False)
    amount_minor: Mapped[int] = mapped_column(BigInteger, nullable=False)
    currency: Mapped[str] = mapped_column(String(3), nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False, default="CREATED")
    idempotency_key: Mapped[str | None] = mapped_column(Text, nullable=True, unique=True)
    decline_code: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=now_utc
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=now_utc, onupdate=now_utc
    )


class PspUpiIntentModel(PspBase):
    """Persisted UPI-style collect intent bound to a payee VPA."""

    __tablename__ = "psp_upi_intents"

    intent_id: Mapped[str] = mapped_column(Text, primary_key=True)
    psp_payment_id: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    token_id: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    payee_vpa: Mapped[str] = mapped_column(Text, nullable=False)
    payer_vpa: Mapped[str | None] = mapped_column(Text, nullable=True)
    amount_minor: Mapped[int] = mapped_column(BigInteger, nullable=False)
    currency: Mapped[str] = mapped_column(String(3), nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False, default="PENDING")
    idempotency_key: Mapped[str | None] = mapped_column(Text, nullable=True, unique=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=now_utc
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=now_utc, onupdate=now_utc
    )


class PspWebhookOutboxModel(PspBase):
    """Transactional webhook outbox for reliable delivery to Mandit Core."""

    __tablename__ = "psp_webhook_outbox"

    event_id: Mapped[str] = mapped_column(Text, primary_key=True)
    event_type: Mapped[str] = mapped_column(Text, nullable=False)
    psp_payment_id: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    payment_ref: Mapped[str | None] = mapped_column(Text, nullable=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    signature_header: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False, default="PENDING")
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=now_utc
    )
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
