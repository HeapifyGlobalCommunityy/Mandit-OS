"""Dependency protocols and service interfaces for Payment Orchestration.

Maintains strict modular monolith boundaries per docs/REFERENCE.md §6, §7, and §14.
"""

from typing import Any, Protocol, runtime_checkable

from mandit.payments.schemas import (
    PaymentExecuteResponse,
    PaymentStatusResponse,
)


class DecisionProvider(Protocol):
    """Protocol for fetching policy decisions from Team 4 Policy Engine."""

    async def get(self, decision_id: str, session: Any = None) -> Any: ...

    async def get_latest_for_proposal(self, proposal_id: str, session: Any = None) -> Any: ...


class MandateClient(Protocol):
    """Protocol for mandate spend reservation and lifecycle per Team 1 contract."""

    async def reserve_spend(
        self,
        mandate_id: str,
        proposal_id: str,
        amount_minor: int,
        currency: str,
        session: Any = None,
    ) -> Any: ...

    async def commit_spend(self, reservation_id: str, session: Any = None) -> Any: ...

    async def release_spend(self, reservation_id: str, session: Any = None) -> Any: ...

    async def assert_usable(self, mandate_id: str, session: Any = None) -> Any: ...


class GroundingClient(Protocol):
    """Protocol for proposal lookup and merchant checkout operations per Team 3 contract."""

    async def get_proposal(self, proposal_id: str, session: Any = None) -> Any: ...

    async def refetch_checkout(self, checkout_id: str, session: Any = None) -> Any: ...

    async def complete_checkout(
        self,
        checkout_id: str,
        psp_payment_id: str,
        session: Any = None,
    ) -> Any: ...


@runtime_checkable
class TokenClient(Protocol):
    """Protocol for token issuance and lifecycle transitions required by Payment Orchestrator."""

    async def issue(
        self,
        decision_id: str,
        reservation_id: str,
        session: Any = None,
    ) -> Any: ...

    async def mark_redeemed(
        self,
        token_id: str,
        session: Any = None,
    ) -> None: ...

    async def mark_failed(
        self,
        token_id: str,
        session: Any = None,
    ) -> None: ...

    async def mark_unknown(
        self,
        token_id: str,
        session: Any = None,
    ) -> None: ...


class PspClient(Protocol):
    """Protocol for communication with Payment Service Provider (Mock PSP)."""

    async def create_scoped_credential(self, req: Any) -> Any: ...

    async def authorize_card(self, req: Any) -> Any: ...

    async def capture_card(self, req: Any) -> Any: ...

    async def create_upi_intent(self, req: Any) -> Any: ...

    async def get_payment_status(self, psp_payment_id: str) -> Any: ...

    async def get_public_jwks(self) -> Any: ...


class PaymentOrchestrator(Protocol):
    """Core payment execution and lifecycle orchestrator interface (modules/04 §3)."""

    async def execute(
        self,
        proposal_id: str,
        idempotency_key: str,
        session: Any = None,
    ) -> PaymentExecuteResponse: ...

    async def get(
        self,
        payment_id: str,
        session: Any = None,
    ) -> PaymentStatusResponse | None: ...

    async def get_by_proposal(
        self,
        proposal_id: str,
        session: Any = None,
    ) -> PaymentStatusResponse | None: ...

    async def process_webhook(
        self,
        payload: dict[str, Any] | bytes | str,
        signature_header: str | None,
        session: Any = None,
    ) -> dict[str, Any]: ...

    async def reconcile(
        self,
        timeout_threshold_seconds: int = 15,
        session: Any = None,
    ) -> list[PaymentStatusResponse]: ...
