"""Ledger events produced by identity registration (modules/05 section 12).

The identity module emits events through an `EventSink` bound to the caller's database session,
so an event commits atomically with the registry write it describes (REFERENCE 7.7). The sink
has the same keyword arguments as `common.events.emit()` (modules/05 section 3). Until Team 5
publishes that function, the application supplies the sink; with no sink configured the
registration service cannot be built, and the endpoints fail closed with 503.
"""

from typing import Any, Literal, Protocol, TypedDict

PRODUCER = "identity"

OPERATOR_REGISTERED = "OPERATOR_REGISTERED"
OPERATOR_VERIFIED = "OPERATOR_VERIFIED"
AGENT_REGISTERED = "AGENT_REGISTERED"


class Actor(TypedDict):
    type: Literal["AGENT", "USER", "SERVICE"]
    id: str


class EventSink(Protocol):
    async def emit(
        self,
        *,
        transaction_id: str | None,
        event_type: str,
        producer: str,
        actor: Actor,
        refs: dict[str, str],
        payload: dict[str, Any],
    ) -> str:
        """Record the event in the caller's transaction and return its event_id."""
        ...
