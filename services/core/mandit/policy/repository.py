"""Repository for Decision and Confirmation persistence.

Provides DB operations using SQLAlchemy sessions conforming to migration 0004.
"""
from typing import Any
from sqlalchemy import select
from sqlalchemy.orm import Session
from sqlalchemy.ext.asyncio import AsyncSession

from mandit.policy.models import ConfirmationModel, DecisionModel


class DecisionRepository:
    """Repository handling persistence of decisions and confirmations."""

    def save_decision_sync(self, session: Session, decision: DecisionModel) -> None:
        """Persist a decision record synchronously."""
        session.add(decision)
        session.flush()

    def get_decision_sync(self, session: Session, decision_id: str) -> DecisionModel | None:
        """Retrieve a decision record by decision_id synchronously."""
        return session.get(DecisionModel, decision_id)

    def save_confirmation_sync(self, session: Session, confirmation: ConfirmationModel) -> None:
        """Persist a confirmation record synchronously."""
        session.add(confirmation)
        session.flush()

    def get_confirmation_sync(self, session: Session, confirmation_id: str) -> ConfirmationModel | None:
        """Retrieve a confirmation record by confirmation_id synchronously."""
        return session.get(ConfirmationModel, confirmation_id)

    async def save_decision(self, session: Any, decision: DecisionModel) -> None:
        """Persist a decision record asynchronously (or synchronously if sync session)."""
        session.add(decision)
        if hasattr(session, "flush"):
            res = session.flush()
            if hasattr(res, "__await__"):
                await res

    async def get_decision(self, session: Any, decision_id: str) -> DecisionModel | None:
        """Retrieve a decision record by decision_id."""
        if hasattr(session, "get"):
            res = session.get(DecisionModel, decision_id)
            if hasattr(res, "__await__"):
                return await res
            return res
        # Fallback using select
        stmt = select(DecisionModel).where(DecisionModel.decision_id == decision_id)
        result = await session.execute(stmt)
        return result.scalar_one_or_none()

    async def save_confirmation(self, session: Any, confirmation: ConfirmationModel) -> None:
        """Persist a confirmation record."""
        session.add(confirmation)
        if hasattr(session, "flush"):
            res = session.flush()
            if hasattr(res, "__await__"):
                await res

    async def get_confirmation(self, session: Any, confirmation_id: str) -> ConfirmationModel | None:
        """Retrieve a confirmation record by confirmation_id."""
        if hasattr(session, "get"):
            res = session.get(ConfirmationModel, confirmation_id)
            if hasattr(res, "__await__"):
                return await res
            return res
        stmt = select(ConfirmationModel).where(ConfirmationModel.confirmation_id == confirmation_id)
        result = await session.execute(stmt)
        return result.scalar_one_or_none()
