"""Models for Human Confirmation and User Keys."""

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, Text
from sqlalchemy.orm import Mapped, mapped_column

from mandit.common.models import Base
from mandit.policy.models import ConfirmationModel, ensure_tz, now_utc


class UserKeyModel(Base):
    """SQLAlchemy model for user_keys table matching migration 0001_identity_and_mandates.py."""

    __tablename__ = "user_keys"

    key_id: Mapped[str] = mapped_column(Text, primary_key=True)
    user_id: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    alg: Mapped[str] = mapped_column(Text, nullable=False)
    jwk: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=now_utc
    )


__all__ = ["ConfirmationModel", "UserKeyModel", "ensure_tz", "now_utc"]
