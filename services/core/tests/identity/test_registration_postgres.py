"""Registration against PostgreSQL: the schema of migration 0001, constraints and locking.

Runs only when TEST_DATABASE_URL points at a database whose name contains "test" (see
.env.example); otherwise skipped. Each test builds the migration 0001 tables in a fresh,
randomly named schema and drops that schema afterwards, so the tables of `mandit_test` that
other teams' tests rely on are never touched.
"""

import asyncio
import dataclasses
import importlib.util
import os
import secrets
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import pytest
from identity_support import ADMIN, agent_request, operator_admin, operator_request, public_jwk, run
from sqlalchemy import inspect, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool

from mandit.identity.events import Actor
from mandit.identity.keys import jwk_thumbprint
from mandit.identity.models import IdentityBase
from mandit.identity.repository import SqlRegistrationStore, SqlUnitOfWork
from mandit.identity.schemas import (
    AgentRegistration,
    IdentityError,
    OperatorRegistration,
)
from mandit.identity.service import RegistrationService

URL = os.environ.get("TEST_DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    "test" not in URL.rsplit("/", 1)[-1], reason="TEST_DATABASE_URL (a *test* database) not set"
)

MIGRATION = (
    Path(__file__).resolve().parents[2]
    / "migrations"
    / "versions"
    / "0001_identity_and_mandates.py"
)


def _migration() -> Any:
    spec = importlib.util.spec_from_file_location("migration_0001", MIGRATION)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TableSink:
    """Writes events into a table through the caller's session, like the outbox will."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

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
        await self._session.execute(
            text("INSERT INTO test_identity_events (event_type, operator_id) VALUES (:t, :o)"),
            {"t": event_type, "o": refs["operator_id"]},
        )
        return "evt_test"


@asynccontextmanager
async def _database() -> AsyncIterator[AsyncEngine]:
    schema = f"identity_test_{secrets.token_hex(6)}"
    admin = create_async_engine(URL, poolclass=NullPool)
    async with admin.begin() as conn:
        await conn.execute(text(f"CREATE SCHEMA {schema}"))
    engine = create_async_engine(
        URL, poolclass=NullPool, connect_args={"options": f"-csearch_path={schema}"}
    )
    try:
        async with engine.begin() as conn:
            for statement in _migration().STATEMENTS:
                await conn.execute(text(statement))
            await conn.execute(
                text("CREATE TABLE test_identity_events (event_type TEXT, operator_id TEXT)")
            )
        yield engine
    finally:
        await engine.dispose()
        async with admin.begin() as conn:
            await conn.execute(text(f"DROP SCHEMA {schema} CASCADE"))
        await admin.dispose()


def _service(engine: AsyncEngine) -> RegistrationService:
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    return RegistrationService(lambda: SqlUnitOfWork(sessions, TableSink))


async def _events(engine: AsyncEngine) -> list[str]:
    async with engine.connect() as conn:
        rows = await conn.execute(text("SELECT event_type FROM test_identity_events"))
        return [r[0] for r in rows]


async def _verified_operator(service: RegistrationService) -> str:
    request = OperatorRegistration.model_validate(operator_request())
    operator = await service.register_operator(ADMIN, request)
    await service.verify_operator(ADMIN, operator.operator_id)
    return operator.operator_id


def _agent(operator_id: str, **overrides: Any) -> AgentRegistration:
    return AgentRegistration.model_validate(agent_request(operator_id, **overrides))


def test_models_match_migration():
    async def scenario() -> None:
        async with _database() as engine:
            async with engine.connect() as conn:

                def columns(sync_conn: Any) -> dict[str, dict[str, bool]]:
                    inspector = inspect(sync_conn)
                    return {
                        table: {c["name"]: c["nullable"] for c in inspector.get_columns(table)}
                        for table in IdentityBase.metadata.tables
                    }

                database = await conn.run_sync(columns)
        for name, table in IdentityBase.metadata.tables.items():
            assert {c.name: c.nullable for c in table.columns} == database[name], name

    run(scenario())


def test_full_registration_round_trip():
    async def scenario() -> None:
        async with _database() as engine:
            service = _service(engine)
            operator_id = await _verified_operator(service)
            jwk = public_jwk()
            created = await service.register_agent(
                operator_admin(operator_id), _agent(operator_id, public_key=jwk)
            )
            read = await service.get_agent(ADMIN, created.agent.agent_id)
            assert read == created  # timestamps, ARRAY scopes and JSONB jwk survive storage
            assert read.keys[0].jwk == jwk
            with pytest.raises(IdentityError) as err:
                await service.get_agent(ADMIN, "agt_MISSING")
            assert err.value.code == "NOT_FOUND"
            operator = await service.get_operator(ADMIN, operator_id)
            assert operator.status == "VERIFIED" and operator.verified_at is not None
            assert await _events(engine) == [
                "OPERATOR_REGISTERED",
                "OPERATOR_VERIFIED",
                "AGENT_REGISTERED",
            ]

    run(scenario())


def test_unique_thumbprint_is_enforced_by_the_database():
    async def scenario() -> None:
        async with _database() as engine:
            service = _service(engine)
            operator_id = await _verified_operator(service)
            jwk = public_jwk()
            await service.register_agent(ADMIN, _agent(operator_id, public_key=jwk))
            with pytest.raises(IdentityError) as err:
                await service.register_agent(ADMIN, _agent(operator_id, public_key=jwk))
            assert err.value.code == "CONFLICT"
            # The failed registration left neither rows nor an event behind.
            async with engine.connect() as conn:
                assert (await conn.execute(text("SELECT count(*) FROM agents"))).scalar() == 1
            assert (await _events(engine)).count("AGENT_REGISTERED") == 1

    run(scenario())


def test_concurrent_registrations_of_one_key():
    async def scenario() -> None:
        async with _database() as engine:
            service = _service(engine)
            operator_id = await _verified_operator(service)
            jwk = public_jwk()
            results = await asyncio.gather(
                *(
                    service.register_agent(ADMIN, _agent(operator_id, public_key=jwk))
                    for _ in range(5)
                ),
                return_exceptions=True,
            )
            errors = [r for r in results if isinstance(r, BaseException)]
            assert len(results) - len(errors) == 1
            assert all(isinstance(e, IdentityError) and e.code == "CONFLICT" for e in errors)

    run(scenario())


def test_concurrent_verification_emits_one_event():
    async def scenario() -> None:
        async with _database() as engine:
            service = _service(engine)
            request = OperatorRegistration.model_validate(operator_request())
            operator = await service.register_operator(ADMIN, request)
            await asyncio.gather(
                *(service.verify_operator(ADMIN, operator.operator_id) for _ in range(5))
            )
            assert (await _events(engine)).count("OPERATOR_VERIFIED") == 1

    run(scenario())


def test_other_integrity_errors_are_not_reported_as_conflicts():
    async def scenario() -> None:
        async with _database() as engine:
            service = _service(engine)
            created = await service.register_agent(ADMIN, _agent(await _verified_operator(service)))
            jwk = public_jwk()
            orphan = dataclasses.replace(
                created.agent, agent_id="agt_ORPHAN", operator_id="op_MISSING"
            )
            key = dataclasses.replace(
                created.keys[0],
                key_id="akey_ORPHAN",
                agent_id="agt_ORPHAN",
                jwk=jwk,
                thumbprint=jwk_thumbprint(jwk),
            )
            async with async_sessionmaker(engine)() as session:
                with pytest.raises(IntegrityError):  # a foreign key, not a duplicate key
                    await SqlRegistrationStore(session).add_agent(orphan, key)

    run(scenario())
