"""HTTP API tests for Scoped Payment Token endpoints.

Tests FastAPI router:
- POST /v1/payment-tokens/redeem
- POST /v1/payment-tokens/validate
- GET /v1/payment-tokens/{token_id}
- POST /v1/payment-tokens/{token_id}/revoke
"""

from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from mandit.common.models import Base
from mandit.tokens.api import get_db_session, get_token_service, router
from mandit.tokens.schemas import (
    PaymentToken,
    TokenErrorCode,
    TokenRedeemResponse,
    TokenRevokeResponse,
    TokenStatus,
    TokenValidateResponse,
)
from mandit.tokens.service import (
    TokenRedemptionRejected,
    TokenServiceImpl,
)
from mandit.tokens.service_auth import ServiceAuthClaims, require_service_auth


class AsyncSessionWrapper:
    def __init__(self, sync_session: Any) -> None:
        self._sync = sync_session

    async def execute(self, statement: Any, *args: Any, **kwargs: Any) -> Any:
        return self._sync.execute(statement, *args, **kwargs)

    async def flush(self) -> None:
        self._sync.flush()

    def add(self, instance: Any) -> None:
        self._sync.add(instance)

    def close(self) -> None:
        self._sync.close()


@pytest.fixture
def mock_token_service():
    return AsyncMock(spec=TokenServiceImpl)


@pytest.fixture
def client(mock_token_service):
    app = FastAPI()
    app.include_router(router)

    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = AsyncSessionWrapper(Session())

    app.dependency_overrides[get_token_service] = lambda: mock_token_service
    app.dependency_overrides[get_db_session] = lambda: session
    app.dependency_overrides[require_service_auth] = lambda: ServiceAuthClaims(
        iss="mock-psp",
        aud="mandit-core",
        iat=int(datetime.now(UTC).timestamp()),
        exp=int(datetime.now(UTC).timestamp()) + 300,
        jti="test_jti",
        key_id="test_kid",
    )

    test_client = TestClient(app)
    try:
        yield test_client
    finally:
        session.close()


def test_api_redeem_success(client, mock_token_service):
    """Test successful redemption via HTTP API returns 200."""
    mock_token_service.redeem.return_value = TokenRedeemResponse(
        token_id="ptok_01JD4B",
        result="ACCEPTED",
        status="REDEEMING",
    )

    resp = client.post(
        "/v1/payment-tokens/redeem",
        json={
            "token": "eyJhbGciOiJFZERTQSIs...",
            "merchant_id": "mer_croma",
            "payee_id": "acq_croma_001",
            "amount_minor": 500000,
            "currency": "INR",
            "checkout_hash": "sha256:hash123",
            "idempotency_key": "idem_123",
        },
    )

    assert resp.status_code == 200
    data = resp.json()
    assert data["token_id"] == "ptok_01JD4B"
    assert data["result"] == "ACCEPTED"
    assert data["status"] == "REDEEMING"


def test_api_redeem_rejection(client, mock_token_service):
    """Test rejected redemption returns 409 Conflict with structured error detail."""
    mock_token_service.redeem.side_effect = TokenRedemptionRejected(
        code=TokenErrorCode.TOKEN_ALREADY_REDEEMED,
        message="Token has already been redeemed",
        status_code=409,
    )

    resp = client.post(
        "/v1/payment-tokens/redeem",
        json={
            "token": "eyJhbGciOiJFZERTQSIs...",
            "merchant_id": "mer_croma",
            "payee_id": "acq_croma_001",
            "amount_minor": 500000,
            "currency": "INR",
            "checkout_hash": "sha256:hash123",
            "idempotency_key": "idem_different",
        },
    )

    assert resp.status_code == 409
    data = resp.json()
    assert data["detail"]["code"] == "TOKEN_ALREADY_REDEEMED"


def test_api_validate(client, mock_token_service):
    """Test validation endpoint returns 200 with validity status."""
    mock_token_service.validate.return_value = TokenValidateResponse(
        token_id="ptok_01JD4B",
        valid=True,
        status="ISSUED",
    )

    resp = client.post(
        "/v1/payment-tokens/validate",
        json={
            "token": "eyJhbGciOiJFZERTQSIs...",
            "merchant_id": "mer_croma",
            "payee_id": "acq_croma_001",
            "amount_minor": 500000,
            "currency": "INR",
            "checkout_hash": "sha256:hash123",
        },
    )

    assert resp.status_code == 200
    data = resp.json()
    assert data["valid"] is True
    assert data["status"] == "ISSUED"


def test_api_get_metadata_success(client, mock_token_service):
    """Test GET metadata returns 200 and excludes signed token (INV-09)."""
    now = datetime.now(UTC)
    mock_token_service.get.return_value = PaymentToken(
        token_id="ptok_01JD4B",
        proposal_id="prop_01",
        decision_id="dec_01",
        mandate_id="man_01",
        reservation_id="res_01",
        merchant_id="mer_croma",
        payee_id="acq_croma_001",
        amount_minor=500000,
        currency="INR",
        checkout_hash="sha256:abc",
        rail="CARD",
        status=TokenStatus.ISSUED,
        idem_key=None,
        expires_at=now + timedelta(minutes=10),
        issued_at=now,
        redeemed_at=None,
    )

    resp = client.get("/v1/payment-tokens/ptok_01JD4B")
    assert resp.status_code == 200
    data = resp.json()
    assert data["token_id"] == "ptok_01JD4B"
    assert data["status"] == "ISSUED"
    assert "signed_token" not in data
    assert "token" not in data


def test_api_get_metadata_not_found(client, mock_token_service):
    """Test GET metadata for non-existent token returns 404."""
    mock_token_service.get.return_value = None

    resp = client.get("/v1/payment-tokens/ptok_nonexistent")
    assert resp.status_code == 404
    data = resp.json()
    assert data["detail"]["code"] == "TOKEN_NOT_FOUND"


def test_api_revoke_success(client, mock_token_service):
    """Test token revocation returns 200 with REVOKED status."""
    mock_token_service.revoke.return_value = TokenRevokeResponse(
        token_id="ptok_01JD4B",
        status="REVOKED",
        reason="Order cancelled",
    )

    resp = client.post(
        "/v1/payment-tokens/ptok_01JD4B/revoke",
        json={"reason": "Order cancelled"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "REVOKED"
    assert data["reason"] == "Order cancelled"
