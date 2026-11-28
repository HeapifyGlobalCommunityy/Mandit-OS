"""Database wiring for the standalone Mock PSP.

`MockPspService` awaits its session calls (`await session.execute(...)`), so the app hands it
an awaitable adapter over a synchronous SQLAlchemy session. The simulator needs no async
driver, and the adapter is the same one the unit tests use.
"""

from typing import Any

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool


class AwaitableSession:
    """Synchronous `Session` exposing the awaitable methods `MockPspService` calls."""

    def __init__(self, sync_session: Session) -> None:
        self._sync = sync_session

    async def execute(self, statement: Any, *args: Any, **kwargs: Any) -> Any:
        return self._sync.execute(statement, *args, **kwargs)

    async def flush(self) -> None:
        self._sync.flush()

    def add(self, instance: Any) -> None:
        self._sync.add(instance)

    async def commit(self) -> None:
        self._sync.commit()

    async def rollback(self) -> None:
        self._sync.rollback()

    def close(self) -> None:
        self._sync.close()


def build_engine(database_url: str) -> Engine:
    """Create the engine; an in-memory SQLite database is shared by every request."""
    if database_url.startswith("sqlite") and ":memory:" in database_url:
        # One shared connection: otherwise each pooled connection sees an empty database.
        return create_engine(
            database_url,
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
    return create_engine(database_url)
