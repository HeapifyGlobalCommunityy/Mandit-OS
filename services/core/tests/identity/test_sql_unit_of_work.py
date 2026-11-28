"""SqlUnitOfWork failure handling. Runs without a database, so CI always covers these paths."""

from typing import Any

import pytest
from identity_support import ADMIN, run
from sqlalchemy.exc import DBAPIError, OperationalError
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from mandit.identity.repository import SqlUnitOfWork
from mandit.identity.schemas import IdentityError
from mandit.identity.service import RegistrationService


class Sink:
    def __init__(self, session: Any) -> None:
        pass

    async def emit(self, **kwargs: Any) -> str:
        return "evt_x"


class StubSession:
    def __init__(self, fail_rollback: bool = False) -> None:
        self.fail_rollback = fail_rollback
        self.calls: list[str] = []

    async def rollback(self) -> None:
        self.calls.append("rollback")
        if self.fail_rollback:
            raise OperationalError("ROLLBACK", {}, Exception("connection lost"))

    async def commit(self) -> None:
        self.calls.append("commit")

    async def close(self) -> None:
        self.calls.append("close")


def _uow(session: StubSession) -> SqlUnitOfWork:
    return SqlUnitOfWork(lambda: session, Sink)  # type: ignore[arg-type, return-value]


async def _body(uow: SqlUnitOfWork, *, commit: bool, error: BaseException | None) -> None:
    async with uow:
        if commit:
            await uow.commit()
        if error is not None:
            raise error


def test_uncommitted_work_is_rolled_back_and_closed():
    session = StubSession()
    run(_body(_uow(session), commit=False, error=None))
    assert session.calls == ["rollback", "close"]


def test_committed_work_is_only_closed():
    session = StubSession()
    run(_body(_uow(session), commit=True, error=None))
    assert session.calls == ["commit", "close"]


def test_connection_errors_fail_closed():
    lost = OperationalError("SELECT 1", {}, Exception("server closed the connection"))
    with pytest.raises(IdentityError) as err:
        run(_body(_uow(StubSession()), commit=False, error=lost))
    assert err.value.code == "DEPENDENCY_UNAVAILABLE"
    assert err.value.__cause__ is lost


def test_invalidated_connection_fails_closed():
    invalidated = DBAPIError("SELECT 1", {}, Exception("gone"), connection_invalidated=True)
    with pytest.raises(IdentityError) as err:
        run(_body(_uow(StubSession()), commit=False, error=invalidated))
    assert err.value.code == "DEPENDENCY_UNAVAILABLE"


def test_failed_rollback_without_another_error_fails_closed():
    with pytest.raises(IdentityError) as err:
        run(_body(_uow(StubSession(fail_rollback=True)), commit=False, error=None))
    assert err.value.code == "DEPENDENCY_UNAVAILABLE"


def test_failed_rollback_keeps_the_original_error():
    original = IdentityError("CONFLICT", "Public key is already registered")
    with pytest.raises(IdentityError) as err:
        run(_body(_uow(StubSession(fail_rollback=True)), commit=False, error=original))
    assert err.value is original


def test_other_errors_pass_through():
    with pytest.raises(ValueError):
        run(_body(_uow(StubSession()), commit=False, error=ValueError("bug")))


def test_unreachable_database_fails_closed():
    async def scenario() -> None:
        # Nothing listens on port 1, so the connection is refused immediately.
        engine = create_async_engine(
            "postgresql+psycopg://postgres@127.0.0.1:1/mandit_test?connect_timeout=2",
            poolclass=NullPool,
        )
        sessions = async_sessionmaker(engine)
        service = RegistrationService(lambda: SqlUnitOfWork(sessions, Sink))
        try:
            with pytest.raises(IdentityError) as err:
                await service.get_agent(ADMIN, "agt_X")
            assert err.value.code == "DEPENDENCY_UNAVAILABLE"
            assert isinstance(err.value.__cause__, OperationalError)  # refused, not misconfigured
        finally:
            await engine.dispose()

    run(scenario())
