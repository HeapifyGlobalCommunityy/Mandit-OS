"""SQLAlchemy mappings of the identity registry tables created by migration 0001.

The migration is the source of truth for the schema; these classes only map onto it, and
tests/identity/test_registration_postgres.py checks that they still agree. Mappings for
agent_challenges and agent_credentials arrive with the challenge and token branch.
"""

from datetime import datetime
from typing import Any

from sqlalchemy import ForeignKey, Text
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.types import DateTime


class IdentityBase(DeclarativeBase):
    type_annotation_map = {datetime: DateTime(timezone=True), str: Text()}


class OperatorRow(IdentityBase):
    __tablename__ = "operators"

    operator_id: Mapped[str] = mapped_column(primary_key=True)
    legal_name: Mapped[str]
    domain: Mapped[str]
    contact_email: Mapped[str]
    status: Mapped[str]
    verified_at: Mapped[datetime | None]
    created_at: Mapped[datetime]


class AgentRow(IdentityBase):
    __tablename__ = "agents"

    agent_id: Mapped[str] = mapped_column(primary_key=True)
    operator_id: Mapped[str] = mapped_column(ForeignKey("operators.operator_id"))
    name: Mapped[str]
    version: Mapped[str]
    model_declared: Mapped[str | None]
    scopes: Mapped[list[str]] = mapped_column(ARRAY(Text))
    status: Mapped[str]
    created_at: Mapped[datetime]
    revoked_at: Mapped[datetime | None]
    revoked_reason: Mapped[str | None]


class AgentKeyRow(IdentityBase):
    __tablename__ = "agent_keys"

    key_id: Mapped[str] = mapped_column(primary_key=True)
    agent_id: Mapped[str] = mapped_column(ForeignKey("agents.agent_id"))
    jwk: Mapped[dict[str, Any]] = mapped_column(JSONB)
    thumbprint: Mapped[str] = mapped_column(unique=True)
    status: Mapped[str]
    created_at: Mapped[datetime]
    retired_at: Mapped[datetime | None]
