"""SQLAlchemy models for Payment Tokens.

Matches migration 0004_policy_and_payments.py exactly.
"""

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import BigInteger, DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from mandit.common.models import Base
from mandit.tokens.schemas import PaymentToken, TokenStatus


def now_utc() -> datetime:
    return datetime.now(UTC)


def ensure_tz(dt: Any) -> datetime | None:
    if isinstance(dt, datetime):
        if dt.tzinfo is None:
            return dt.replace(tzinfo=UTC)
        return dt
    return None


class PaymentTokenModel(Base):
    """SQLAlchemy model for payment_tokens table matching migration 0004."""

    __tablename__ = "payment_tokens"

    token_id: Mapped[str] = mapped_column(Text, primary_key=True)
    proposal_id: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    decision_id: Mapped[str] = mapped_column(Text, nullable=False)
    mandate_id: Mapped[str] = mapped_column(Text, nullable=False)
    reservation_id: Mapped[str] = mapped_column(Text, nullable=False)
    merchant_id: Mapped[str] = mapped_column(Text, nullable=False)
    payee_id: Mapped[str] = mapped_column(Text, nullable=False)
    amount_minor: Mapped[int] = mapped_column(BigInteger, nullable=False)
    currency: Mapped[str] = mapped_column(String(3), nullable=False)
    checkout_hash: Mapped[str] = mapped_column(Text, nullable=False)
    rail: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False, default="ISSUED")
    idem_key: Mapped[str | None] = mapped_column(Text, nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    issued_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=now_utc
    )
    redeemed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    def to_schema(self) -> PaymentToken:
        """Convert SQLAlchemy model to canonical domain PaymentToken dataclass."""
        exp = ensure_tz(self.expires_at) or self.expires_at
        iss = ensure_tz(self.issued_at) or self.issued_at
        red = ensure_tz(self.redeemed_at)
        return PaymentToken(
            token_id=self.token_id,
            proposal_id=self.proposal_id,
            decision_id=self.decision_id,
            mandate_id=self.mandate_id,
            reservation_id=self.reservation_id,
            merchant_id=self.merchant_id,
            payee_id=self.payee_id,
            amount_minor=self.amount_minor,
            currency=self.currency,
            checkout_hash=self.checkout_hash,
            rail=self.rail,
            status=TokenStatus(self.status),
            idem_key=self.idem_key,
            expires_at=exp,
            issued_at=iss,
            redeemed_at=red,
        )

    @classmethod
    def from_schema(cls, token: PaymentToken) -> "PaymentTokenModel":
        """Create SQLAlchemy model from canonical domain PaymentToken dataclass."""
        return cls(
            token_id=token.token_id,
            proposal_id=token.proposal_id,
            decision_id=token.decision_id,
            mandate_id=token.mandate_id,
            reservation_id=token.reservation_id,
            merchant_id=token.merchant_id,
            payee_id=token.payee_id,
            amount_minor=token.amount_minor,
            currency=token.currency,
            checkout_hash=token.checkout_hash,
            rail=token.rail,
            status=token.status.value if hasattr(token.status, "value") else str(token.status),
            idem_key=token.idem_key,
            expires_at=token.expires_at,
            issued_at=token.issued_at,
            redeemed_at=token.redeemed_at,
        )
