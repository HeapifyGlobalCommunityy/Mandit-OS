"""Models for Human Confirmation and User Keys."""
from sqlalchemy import Column, DateTime, JSON, Text
from mandit.common.models import Base
from mandit.policy.models import ConfirmationModel, ensure_tz, now_utc


class UserKeyModel(Base):
    """SQLAlchemy model for user_keys table matching migration 0001_identity_and_mandates.py."""
    __tablename__ = "user_keys"

    key_id = Column(Text, primary_key=True)
    user_id = Column(Text, nullable=False, index=True)
    alg = Column(Text, nullable=False)
    jwk = Column(JSON, nullable=False)
    status = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, default=now_utc)


__all__ = ["ConfirmationModel", "UserKeyModel", "ensure_tz", "now_utc"]
