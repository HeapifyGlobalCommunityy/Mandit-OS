"""Registry storage behind the registration service.

`RegistrationService` talks to a `UnitOfWork`: one database transaction that exposes the
registry store and an event sink bound to the same session. The service calls `commit()` only
after every write and event in the operation succeeded; leaving the block without committing
rolls everything back, so a registry change never exists without its ledger event.
"""

from collections.abc import Callable
from types import TracebackType
from typing import Literal, Protocol, Self, cast

from sqlalchemy import select, update
from sqlalchemy.exc import DBAPIError, IntegrityError, InterfaceError, OperationalError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from .events import EventSink
from .models import AgentKeyRow, AgentRow, OperatorRow
from .schemas import (
    AgentKeyRecord,
    AgentKeyStatus,
    AgentRecord,
    AgentStatus,
    AgentView,
    IdentityError,
    OperatorRecord,
    OperatorStatus,
)

LockMode = Literal["share", "update"] | None

UNIQUE_VIOLATION = "23505"


class RegistrationStore(Protocol):
    async def add_operator(self, operator: OperatorRecord) -> None: ...

    async def get_operator(
        self, operator_id: str, *, lock: LockMode = None
    ) -> OperatorRecord | None: ...

    async def save_operator_status(self, operator: OperatorRecord) -> None: ...

    async def add_agent(self, agent: AgentRecord, key: AgentKeyRecord) -> None:
        """Raises IdentityError("CONFLICT") if the key thumbprint is already registered."""
        ...

    async def get_agent(self, agent_id: str) -> AgentView | None: ...


class UnitOfWork(Protocol):
    store: RegistrationStore
    events: EventSink

    async def __aenter__(self) -> Self: ...

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None: ...

    async def commit(self) -> None: ...


# --- PostgreSQL implementation -----------------------------------------------------------


def _operator(row: OperatorRow) -> OperatorRecord:
    return OperatorRecord(
        operator_id=row.operator_id,
        legal_name=row.legal_name,
        domain=row.domain,
        contact_email=row.contact_email,
        status=cast(OperatorStatus, row.status),
        verified_at=row.verified_at,
        created_at=row.created_at,
    )


def _agent(row: AgentRow) -> AgentRecord:
    return AgentRecord(
        agent_id=row.agent_id,
        operator_id=row.operator_id,
        name=row.name,
        version=row.version,
        model_declared=row.model_declared,
        scopes=tuple(row.scopes),
        status=cast(AgentStatus, row.status),
        created_at=row.created_at,
        revoked_at=row.revoked_at,
        revoked_reason=row.revoked_reason,
    )


def _key(row: AgentKeyRow) -> AgentKeyRecord:
    return AgentKeyRecord(
        key_id=row.key_id,
        agent_id=row.agent_id,
        jwk={str(k): str(v) for k, v in row.jwk.items()},
        thumbprint=row.thumbprint,
        status=cast(AgentKeyStatus, row.status),
        created_at=row.created_at,
        retired_at=row.retired_at,
    )


class SqlRegistrationStore:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add_operator(self, operator: OperatorRecord) -> None:
        self._session.add(OperatorRow(**operator.__dict__))
        await self._session.flush()

    async def get_operator(
        self, operator_id: str, *, lock: LockMode = None
    ) -> OperatorRecord | None:
        query = select(OperatorRow).where(OperatorRow.operator_id == operator_id)
        if lock is not None:
            # FOR SHARE keeps the operator from changing status until this transaction ends;
            # FOR UPDATE serializes concurrent status changes of the same operator.
            query = query.with_for_update(read=lock == "share")
        row = (await self._session.execute(query)).scalar_one_or_none()
        return None if row is None else _operator(row)

    async def save_operator_status(self, operator: OperatorRecord) -> None:
        await self._session.execute(
            update(OperatorRow)
            .where(OperatorRow.operator_id == operator.operator_id)
            .values(status=operator.status, verified_at=operator.verified_at)
        )

    async def add_agent(self, agent: AgentRecord, key: AgentKeyRecord) -> None:
        try:
            # Two flushes: the mappings declare no relationship, so the unit of work would not
            # otherwise order the agent row before the key row that references it.
            self._session.add(AgentRow(**{**agent.__dict__, "scopes": list(agent.scopes)}))
            await self._session.flush()
            self._session.add(AgentKeyRow(**key.__dict__))
            await self._session.flush()
        except IntegrityError as exc:
            # The UNIQUE constraint on agent_keys.thumbprint is the authority; a check-then-
            # insert in application code alone would race with a concurrent registration.
            if getattr(exc.orig, "sqlstate", None) == UNIQUE_VIOLATION:
                raise IdentityError("CONFLICT", "Public key is already registered") from exc
            raise

    async def get_agent(self, agent_id: str) -> AgentView | None:
        row = await self._session.get(AgentRow, agent_id)
        if row is None:
            return None
        keys = await self._session.execute(
            select(AgentKeyRow)
            .where(AgentKeyRow.agent_id == agent_id)
            .order_by(AgentKeyRow.created_at, AgentKeyRow.key_id)
        )
        return AgentView(_agent(row), tuple(_key(k) for k in keys.scalars()))


class SqlUnitOfWork:
    """One session and one transaction per registry operation."""

    store: RegistrationStore
    events: EventSink

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        event_sink_factory: Callable[[AsyncSession], EventSink],
    ) -> None:
        self._session_factory = session_factory
        self._event_sink_factory = event_sink_factory

    async def __aenter__(self) -> Self:
        self._session = self._session_factory()
        self._committed = False
        self.store = SqlRegistrationStore(self._session)
        self.events = self._event_sink_factory(self._session)
        return self

    async def commit(self) -> None:
        await self._session.commit()
        self._committed = True

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        try:
            if not self._committed:
                await self._session.rollback()
            await self._session.close()
        except DBAPIError as cleanup_exc:
            # A dead connection also fails the rollback. Report the original failure if there
            # is one; an uncommitted operation without one still fails closed.
            if exc is None and not self._committed:
                raise IdentityError(
                    "DEPENDENCY_UNAVAILABLE", "Identity storage unavailable"
                ) from cleanup_exc
        if _is_unavailable(exc):
            # Fail closed: the caller gets 503 and nothing was committed.
            raise IdentityError("DEPENDENCY_UNAVAILABLE", "Identity storage unavailable") from exc


def _is_unavailable(exc: BaseException | None) -> bool:
    return isinstance(exc, OperationalError | InterfaceError) or (
        isinstance(exc, DBAPIError) and exc.connection_invalidated
    )
