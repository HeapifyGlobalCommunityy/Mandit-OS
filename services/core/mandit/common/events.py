"""Shared event emission client maintained per docs/modules/05-evidence-and-experience.md."""
from datetime import datetime, timezone
from typing import Any
import uuid


class EventEmitter:
    """Event emitter managing transactional event emission."""

    def __init__(self) -> None:
        self.emitted_events: list[dict[str, Any]] = []

    async def emit(
        self,
        session: Any,
        *,
        transaction_id: str | None,
        event_type: str,
        producer: str,
        actor: dict[str, str],
        refs: dict[str, str],
        payload: dict[str, Any],
    ) -> str:
        event_id = f"evt_{uuid.uuid4().hex}"
        event_record = {
            "event_id": event_id,
            "transaction_id": transaction_id,
            "event_type": event_type,
            "producer": producer,
            "actor": actor,
            "refs": refs,
            "payload": payload,
            "created_at": datetime.now(timezone.utc),
        }
        self.emitted_events.append(event_record)
        return event_id

    def clear(self) -> None:
        self.emitted_events.clear()


# Default singleton instance
_default_emitter = EventEmitter()


async def emit(
    session: Any,
    *,
    transaction_id: str | None,
    event_type: str,
    producer: str,
    actor: dict[str, str],
    refs: dict[str, str],
    payload: dict[str, Any],
) -> str:
    """Global emit function matching docs/modules/05-evidence-and-experience.md §3."""
    return await _default_emitter.emit(
        session,
        transaction_id=transaction_id,
        event_type=event_type,
        producer=producer,
        actor=actor,
        refs=refs,
        payload=payload,
    )
