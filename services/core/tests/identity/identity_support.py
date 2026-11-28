"""Identity test helpers: an in-memory registry with real transaction semantics.

The module has a unique name (not `conftest`) so that test files can import it without
colliding with other teams' conftest.py files on sys.path.

`MemoryRegistry` mimics what the PostgreSQL store guarantees: writes and events become visible
only on commit, the thumbprint is unique, and leaving a unit of work without committing
discards everything. That lets the service tests prove "no registry change without its event"
without a database; test_registration_postgres.py checks the same against PostgreSQL.
"""

import asyncio
import dataclasses
import sys
from collections.abc import Callable, Coroutine
from datetime import UTC, datetime, timedelta
from types import TracebackType
from typing import Any, Self

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from mandit.identity.events import Actor
from mandit.identity.keys import base64url
from mandit.identity.repository import LockMode
from mandit.identity.schemas import (
    AgentKeyRecord,
    AgentRecord,
    AgentView,
    IdentityError,
    OperatorRecord,
    Principal,
)
from mandit.identity.service import RegistrationService

ADMIN = Principal(kind="USER", id="usr_mandit_admin", mandit_admin=True)
SERVICE = Principal(kind="SERVICE", id="svc_gateway")
STRANGER = Principal(kind="USER", id="usr_stranger", operator_ids=frozenset({"op_OTHER"}))

ALL_SCOPES = [
    "transaction:open",
    "merchant:read",
    "web:fetch",
    "checkout:create",
    "purchase:propose",
    "purchase:read",
    "purchase:execute",
]


def run[T](coro: Coroutine[Any, Any, T]) -> T:
    # psycopg's async mode cannot use Windows' default Proactor loop; Linux is unaffected.
    factory = asyncio.SelectorEventLoop if sys.platform == "win32" else None
    return asyncio.run(coro, loop_factory=factory)


def public_jwk(signer: Ed25519PrivateKey | None = None) -> dict[str, str]:
    key = signer or Ed25519PrivateKey.generate()
    return {"kty": "OKP", "crv": "Ed25519", "x": base64url(key.public_key().public_bytes_raw())}


def operator_admin(operator_id: str) -> Principal:
    return Principal(kind="USER", id="usr_operator_admin", operator_ids=frozenset({operator_id}))


def operator_request(**overrides: Any) -> dict[str, Any]:
    return {
        "legal_name": "Acme Agents Pvt Ltd (synthetic)",
        "domain": "acme-agents.example",
        "contact_email": "ops@acme-agents.example",
        **overrides,
    }


def agent_request(operator_id: str, **overrides: Any) -> dict[str, Any]:
    return {
        "operator_id": operator_id,
        "name": "acme-shopper",
        "version": "3.0.0",
        "model_declared": "demo-llm",
        "public_key": public_jwk(),
        "requested_scopes": list(ALL_SCOPES),
        **overrides,
    }


class FixedClock:
    def __init__(self) -> None:
        self.now = datetime(2026, 11, 23, 10, 0, 0, 123456, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: int) -> None:
        self.now += timedelta(seconds=seconds)


@dataclasses.dataclass
class Event:
    event_type: str
    producer: str
    actor: Actor
    refs: dict[str, str]
    payload: dict[str, Any]
    transaction_id: str | None


class MemoryDatabase:
    def __init__(self) -> None:
        self.operators: dict[str, OperatorRecord] = {}
        self.agents: dict[str, AgentRecord] = {}
        self.keys: dict[str, AgentKeyRecord] = {}
        self.events: list[Event] = []
        self.commits = 0
        self.locks: list[tuple[str, LockMode]] = []
        self.fail_on_emit = False


class _Sink:
    def __init__(self, staged: list[Event], db: MemoryDatabase) -> None:
        self._staged = staged
        self._db = db

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
        if self._db.fail_on_emit:
            raise RuntimeError("ledger unavailable")
        self._staged.append(Event(event_type, producer, actor, refs, payload, transaction_id))
        return f"evt_{len(self._db.events) + len(self._staged)}"


class _Store:
    def __init__(self, db: MemoryDatabase, staged: dict[str, dict[str, Any]]) -> None:
        self._db = db
        self._staged = staged

    def _view(self, table: str) -> dict[str, Any]:
        return {**getattr(self._db, table), **self._staged[table]}

    async def add_operator(self, operator: OperatorRecord) -> None:
        self._staged["operators"][operator.operator_id] = operator

    async def get_operator(
        self, operator_id: str, *, lock: LockMode = None
    ) -> OperatorRecord | None:
        self._db.locks.append((operator_id, lock))
        result: OperatorRecord | None = self._view("operators").get(operator_id)
        return result

    async def save_operator_status(self, operator: OperatorRecord) -> None:
        self._staged["operators"][operator.operator_id] = operator

    async def add_agent(self, agent: AgentRecord, key: AgentKeyRecord) -> None:
        if any(k.thumbprint == key.thumbprint for k in self._view("keys").values()):
            raise IdentityError("CONFLICT", "Public key is already registered")
        self._staged["agents"][agent.agent_id] = agent
        self._staged["keys"][key.key_id] = key

    async def get_agent(self, agent_id: str) -> AgentView | None:
        agent = self._view("agents").get(agent_id)
        if agent is None:
            return None
        keys = sorted(
            (k for k in self._view("keys").values() if k.agent_id == agent_id),
            key=lambda k: (k.created_at, k.key_id),
        )
        return AgentView(agent, tuple(keys))


class MemoryUnitOfWork:
    def __init__(self, db: MemoryDatabase) -> None:
        self._db = db

    async def __aenter__(self) -> Self:
        self._tables: dict[str, dict[str, Any]] = {"operators": {}, "agents": {}, "keys": {}}
        self._events: list[Event] = []
        self.store = _Store(self._db, self._tables)
        self.events = _Sink(self._events, self._db)
        return self

    async def commit(self) -> None:
        for table, rows in self._tables.items():
            getattr(self._db, table).update(rows)
        self._db.events.extend(self._events)
        self._db.commits += 1

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        return None


@dataclasses.dataclass
class Registry:
    db: MemoryDatabase
    clock: FixedClock
    service: RegistrationService

    def operator(self, *, status: str = "VERIFIED") -> OperatorRecord:
        """Insert an operator directly, bypassing the service, in the given status."""
        operator = OperatorRecord(
            operator_id=f"op_TEST{len(self.db.operators):04d}",
            legal_name="Acme Agents Pvt Ltd (synthetic)",
            domain="acme-agents.example",
            contact_email="ops@acme-agents.example",
            status=status,  # type: ignore[arg-type]
            verified_at=self.clock.now if status == "VERIFIED" else None,
            created_at=self.clock.now,
        )
        self.db.operators[operator.operator_id] = operator
        return operator

    def event_types(self) -> list[str]:
        return [e.event_type for e in self.db.events]


def make_registry() -> Registry:
    db = MemoryDatabase()
    clock = FixedClock()
    unit_of_work: Callable[[], MemoryUnitOfWork] = lambda: MemoryUnitOfWork(db)  # noqa: E731
    return Registry(db, clock, RegistrationService(unit_of_work, clock=clock))
