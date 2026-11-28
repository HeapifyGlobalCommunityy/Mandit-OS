"""Interfaces and dependency protocols for the Scoped Payment Token Service.

Strictly preserves cross-team boundaries per docs/REFERENCE.md §6 and §7.
"""

from typing import Any, Protocol

from mandit.tokens.schemas import (
    IssuedToken,
    PaymentToken,
    TokenRedeemRequest,
    TokenRedeemResponse,
    TokenRevokeResponse,
    TokenValidateRequest,
    TokenValidateResponse,
)


class DecisionProvider(Protocol):
    """Protocol for fetching policy decisions from Team 4 Policy Engine."""

    async def get(self, decision_id: str, session: Any = None) -> Any: ...


class IdentityProvider(Protocol):
    """Protocol for checking agent identity status per Team 1 KYA service."""

    async def is_active(self, agent_id: str, key_id: str | None = None) -> bool: ...


class MandateSpendProvider(Protocol):
    """Protocol for verifying mandate usability and reservations per Team 1."""

    async def assert_usable(self, mandate_id: str) -> Any: ...

    async def get_reservation(self, reservation_id: str) -> Any: ...


class GroundingProvider(Protocol):
    """Protocol for proposal lookup and TOCTOU checkout refetch per Team 3."""

    async def get_proposal(self, proposal_id: str) -> Any: ...

    async def refetch_checkout(self, checkout_id: str) -> Any: ...


class TokenService(Protocol):
    """Core interface for Scoped Payment Token lifecycle operations."""

    async def issue(
        self,
        decision_id: str,
        reservation_id: str,
        session: Any = None,
    ) -> IssuedToken:
        """Issue a single-use payment token for an unexpired ALLOW decision."""
        ...

    async def redeem(
        self,
        req: TokenRedeemRequest,
        session: Any = None,
    ) -> TokenRedeemResponse:
        """Atomically validate and redeem an issued payment token (mock PSP)."""
        ...

    async def validate(
        self,
        req: TokenValidateRequest,
        session: Any = None,
    ) -> TokenValidateResponse:
        """Validate token claims and database binding without consuming it."""
        ...

    async def get(
        self,
        token_id: str,
        session: Any = None,
    ) -> PaymentToken | None:
        """Retrieve token record metadata by ID (never returns JWS)."""
        ...

    async def revoke(
        self,
        token_id: str,
        reason: str,
        session: Any = None,
    ) -> TokenRevokeResponse:
        """Revoke an unredeemed payment token."""
        ...
