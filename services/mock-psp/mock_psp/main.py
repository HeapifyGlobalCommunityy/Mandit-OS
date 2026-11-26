"""Main FastAPI application entry point for Mock PSP Service.

Base URL: http://mock-psp:8200 (REFERENCE §9.4).
"""

from collections.abc import AsyncGenerator, Generator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from mock_psp.api import get_psp_db_session, get_psp_service, router
from mock_psp.config import SETTINGS
from mock_psp.crypto import PspKeyManager
from mock_psp.models import PspBase
from mock_psp.service import MockPspService
from mock_psp.token_client import HttpTokenClient
from mock_psp.webhook_dispatcher import WebhookDispatcher

# Authoritative database engine and sessionmaker
engine = create_engine(SETTINGS.database_url, echo=False)
SessionLocal = sessionmaker(bind=engine)

# Singleton service instances
key_manager = PspKeyManager(key_id=SETTINGS.key_id)
token_client = HttpTokenClient(base_url=SETTINGS.core_base_url)
webhook_dispatcher = WebhookDispatcher(
    key_manager=key_manager,
    core_base_url=SETTINGS.core_base_url,
)
psp_service = MockPspService(
    key_manager=key_manager,
    token_client=token_client,
    webhook_dispatcher=webhook_dispatcher,
)


def get_db() -> Generator[Session, None, None]:
    """Provide transactional database session."""
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Initialize database tables on service startup."""
    PspBase.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title="Mandit OS Mock PSP",
    description="Simulated Payment Service Provider for Card and UPI synthetic flows",
    version="1.0.0",
    lifespan=lifespan,
)

# Wire default dependencies
app.dependency_overrides[get_psp_service] = lambda: psp_service
app.dependency_overrides[get_psp_db_session] = get_db

app.include_router(router)


@app.get("/health", status_code=200)
async def health_check() -> dict[str, Any]:
    """Health check endpoint for Docker / orchestration."""
    return {"status": "HEALTHY", "service": "mock-psp", "profile": SETTINGS.profile}
