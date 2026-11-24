"""Protocols and interfaces for Human Confirmation service."""
from typing import Any, Protocol

from mandit.confirmation.schemas import (
    ConfirmationRespondRequest,
    ConfirmationRespondResponse,
    UserKeyRecord,
)
from mandit.policy.models import ConfirmationModel


class UserKeyService(Protocol):
    """Protocol for accessing user signing keys (Team 1 contract)."""

    async def get_key(self, key_id: str) -> UserKeyRecord | None:
        """Retrieve user key record by key_id."""
        ...

    async def get_active_key(self, user_id: str) -> UserKeyRecord | None:
        """Retrieve active key for user_id."""
        ...


class ConfirmationService(Protocol):
    """Protocol for Human Confirmation lifecycle per docs/modules/04 §6."""

    async def respond(
        self,
        session: Any,
        confirmation_id: str,
        caller_user_id: str,
        req: ConfirmationRespondRequest,
    ) -> ConfirmationRespondResponse:
        """Process user approval or rejection with atomic validation and event emission."""
        ...

    async def get(
        self,
        session: Any,
        confirmation_id: str,
    ) -> ConfirmationModel | None:
        """Retrieve confirmation model by ID."""
        ...

    async def expire_if_needed(
        self,
        session: Any,
        confirmation_id: str,
    ) -> ConfirmationModel | None:
        """Check expiry and transition to EXPIRED if past expiry time."""
        ...
