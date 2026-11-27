"""Comprehensive test suite for internal Service-to-Service Authentication.

Per docs/REFERENCE.md §7.5, §8.3, §9.4 and docs/modules/04-policy-and-payments.md §7.3:
- Protocol: 'Authorization: Service <jwt>'
- JWS: RFC 8037 EdDSA (Ed25519)
- Headers: alg='EdDSA', typ='JWT', kid='<key_id>'
- Claims: iss='mock-psp', aud='mandit-core', iat, exp, jti
- Lifetime: strictly at most 300 seconds (5 minutes)
- Rejection: Fails closed with 401 UNAUTHORIZED before any mutation.
"""

import asyncio
import json
import uuid
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi import FastAPI
from fastapi.testclient import TestClient

from mandit.common.crypto import b64url_encode
from mandit.tokens.api import get_db_session, get_token_service, router
from mandit.tokens.schemas import (
    TokenRedeemRequest,
    TokenRedeemResponse,
)
from mandit.tokens.service import TokenServiceImpl
from mandit.tokens.service_auth import (
    ServiceAuthError,
    ServiceAuthVerifier,
    get_service_auth_verifier,
)
from mock_psp.crypto import PspKeyManager
from mock_psp.token_client import HttpTokenClient


def create_raw_service_jwt(
    private_key: ed25519.Ed25519PrivateKey,
    key_id: str,
    header_overrides: dict[str, Any] | None = None,
    claims_overrides: dict[str, Any] | None = None,
) -> str:
    """Helper creating a test service JWT with arbitrary overrides."""
    now = int(datetime.now(UTC).timestamp())
    header: dict[str, Any] = {
        "alg": "EdDSA",
        "kid": key_id,
        "typ": "JWT",
    }
    if header_overrides:
        header.update(header_overrides)

    claims: dict[str, Any] = {
        "iss": "mock-psp",
        "aud": "mandit-core",
        "iat": now,
        "exp": now + 300,
        "jti": str(uuid.uuid4()),
    }
    if claims_overrides:
        claims.update(claims_overrides)

    header_json = json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8")
    claims_json = json.dumps(claims, separators=(",", ":"), sort_keys=True).encode("utf-8")
    header_b64 = b64url_encode(header_json)
    claims_b64 = b64url_encode(claims_json)
    signing_input = f"{header_b64}.{claims_b64}".encode("ascii")
    sig_bytes = private_key.sign(signing_input)
    sig_b64 = b64url_encode(sig_bytes)
    return f"{header_b64}.{claims_b64}.{sig_b64}"


@pytest.fixture
def test_keys():
    """Generate ephemeral Ed25519 keypair for tests."""
    priv = ed25519.Ed25519PrivateKey.generate()
    kid = "psp-test-2026-11"
    return {"priv": priv, "pub": priv.public_key(), "kid": kid}


@pytest.fixture
def mock_token_service():
    mock = AsyncMock(spec=TokenServiceImpl)
    mock.redeem.return_value = TokenRedeemResponse(
        token_id="ptok_service_auth_test",
        result="ACCEPTED",
        status="REDEEMING",
    )
    return mock


@pytest.fixture
def auth_test_app(test_keys, mock_token_service):
    """FastAPI test app wired with ServiceAuthVerifier containing the test key."""
    app = FastAPI()
    app.include_router(router)

    verifier = ServiceAuthVerifier(
        trusted_keys={test_keys["kid"]: test_keys["pub"]},
        default_issuer="mock-psp",
        default_audience="mandit-core",
    )

    app.dependency_overrides[get_service_auth_verifier] = lambda: verifier
    app.dependency_overrides[get_token_service] = lambda: mock_token_service
    app.dependency_overrides[get_db_session] = lambda: AsyncMock()

    return app, verifier, mock_token_service


# --- ServiceAuthVerifier Unit Tests ---


def test_verifier_valid_token_parses_claims(test_keys):
    verifier = ServiceAuthVerifier(trusted_keys={test_keys["kid"]: test_keys["pub"]})
    jwt = create_raw_service_jwt(test_keys["priv"], test_keys["kid"])
    claims = verifier.verify_service_jwt(f"Service {jwt}")

    assert claims.iss == "mock-psp"
    assert claims.aud == "mandit-core"
    assert claims.key_id == test_keys["kid"]
    assert claims.exp > claims.iat
    assert claims.jti


def test_verifier_missing_header_fails():
    verifier = ServiceAuthVerifier()
    with pytest.raises(ServiceAuthError) as exc_info:
        verifier.verify_service_jwt(None)
    assert exc_info.value.status_code == 401
    assert "Missing Authorization header" in exc_info.value.message


def test_verifier_invalid_scheme_fails(test_keys):
    verifier = ServiceAuthVerifier(trusted_keys={test_keys["kid"]: test_keys["pub"]})
    jwt = create_raw_service_jwt(test_keys["priv"], test_keys["kid"])
    with pytest.raises(ServiceAuthError) as exc_info:
        verifier.verify_service_jwt(f"Bearer {jwt}")
    assert exc_info.value.status_code == 401
    assert "Invalid authorization scheme" in exc_info.value.message


def test_verifier_malformed_jwt_parts_fails():
    verifier = ServiceAuthVerifier()
    with pytest.raises(ServiceAuthError) as exc_info:
        verifier.verify_service_jwt("Service not.enough.parts.extra")
    assert exc_info.value.status_code == 401
    assert "expected 3 parts" in exc_info.value.message


def test_verifier_invalid_signature_fails(test_keys):
    verifier = ServiceAuthVerifier(trusted_keys={test_keys["kid"]: test_keys["pub"]})
    other_priv = ed25519.Ed25519PrivateKey.generate()
    jwt = create_raw_service_jwt(other_priv, test_keys["kid"])

    with pytest.raises(ServiceAuthError) as exc_info:
        verifier.verify_service_jwt(f"Service {jwt}")
    assert exc_info.value.status_code == 401
    assert "Invalid service JWT signature" in exc_info.value.message


def test_verifier_untrusted_kid_fails(test_keys):
    verifier = ServiceAuthVerifier(trusted_keys={test_keys["kid"]: test_keys["pub"]})
    jwt = create_raw_service_jwt(test_keys["priv"], "unknown-kid")

    with pytest.raises(ServiceAuthError) as exc_info:
        verifier.verify_service_jwt(f"Service {jwt}")
    assert exc_info.value.status_code == 401
    assert "Untrusted or unregistered service key ID" in exc_info.value.message


def test_verifier_no_keys_configured_fails_closed(test_keys):
    verifier = ServiceAuthVerifier(trusted_keys={})
    jwt = create_raw_service_jwt(test_keys["priv"], test_keys["kid"])

    with pytest.raises(ServiceAuthError) as exc_info:
        verifier.verify_service_jwt(f"Service {jwt}")
    assert exc_info.value.status_code == 401
    assert "No trusted service keys configured (fail-closed)" in exc_info.value.message


def test_verifier_incorrect_issuer_fails(test_keys):
    verifier = ServiceAuthVerifier(trusted_keys={test_keys["kid"]: test_keys["pub"]})
    jwt = create_raw_service_jwt(
        test_keys["priv"],
        test_keys["kid"],
        claims_overrides={"iss": "rogue-service"},
    )
    with pytest.raises(ServiceAuthError) as exc_info:
        verifier.verify_service_jwt(f"Service {jwt}")
    assert exc_info.value.status_code == 401
    assert "Invalid issuer 'rogue-service'" in exc_info.value.message


def test_verifier_incorrect_audience_fails(test_keys):
    verifier = ServiceAuthVerifier(trusted_keys={test_keys["kid"]: test_keys["pub"]})
    jwt = create_raw_service_jwt(
        test_keys["priv"],
        test_keys["kid"],
        claims_overrides={"aud": "other-target"},
    )
    with pytest.raises(ServiceAuthError) as exc_info:
        verifier.verify_service_jwt(f"Service {jwt}")
    assert exc_info.value.status_code == 401
    assert "Invalid audience 'other-target'" in exc_info.value.message


def test_verifier_expired_jwt_fails(test_keys):
    verifier = ServiceAuthVerifier(trusted_keys={test_keys["kid"]: test_keys["pub"]})
    now = int(datetime.now(UTC).timestamp())
    jwt = create_raw_service_jwt(
        test_keys["priv"],
        test_keys["kid"],
        claims_overrides={"iat": now - 400, "exp": now - 100},
    )
    with pytest.raises(ServiceAuthError) as exc_info:
        verifier.verify_service_jwt(f"Service {jwt}")
    assert exc_info.value.status_code == 401
    assert "Service JWT has expired" in exc_info.value.message


def test_verifier_lifetime_exceeding_300s_fails(test_keys):
    verifier = ServiceAuthVerifier(trusted_keys={test_keys["kid"]: test_keys["pub"]})
    now = int(datetime.now(UTC).timestamp())
    jwt = create_raw_service_jwt(
        test_keys["priv"],
        test_keys["kid"],
        claims_overrides={"iat": now, "exp": now + 301},
    )
    with pytest.raises(ServiceAuthError) as exc_info:
        verifier.verify_service_jwt(f"Service {jwt}")
    assert exc_info.value.status_code == 401
    assert "exceeds maximum allowed duration of 300s" in exc_info.value.message


def test_verifier_future_dated_iat_fails(test_keys):
    verifier = ServiceAuthVerifier(trusted_keys={test_keys["kid"]: test_keys["pub"]})
    now = int(datetime.now(UTC).timestamp())
    jwt = create_raw_service_jwt(
        test_keys["priv"],
        test_keys["kid"],
        claims_overrides={"iat": now + 60, "exp": now + 300},
    )
    with pytest.raises(ServiceAuthError) as exc_info:
        verifier.verify_service_jwt(f"Service {jwt}")
    assert exc_info.value.status_code == 401
    assert "Service JWT iat is in the future" in exc_info.value.message


def test_verifier_unsupported_alg_fails(test_keys):
    verifier = ServiceAuthVerifier(trusted_keys={test_keys["kid"]: test_keys["pub"]})
    jwt = create_raw_service_jwt(
        test_keys["priv"],
        test_keys["kid"],
        header_overrides={"alg": "RS256"},
    )
    with pytest.raises(ServiceAuthError) as exc_info:
        verifier.verify_service_jwt(f"Service {jwt}")
    assert exc_info.value.status_code == 401
    assert "Unsupported alg 'RS256'" in exc_info.value.message


# --- End-to-End HTTP Route Tests for POST /v1/payment-tokens/redeem ---


def test_http_redeem_valid_service_auth_succeeds(auth_test_app, test_keys):
    app, verifier, mock_svc = auth_test_app
    client = TestClient(app)

    jwt = create_raw_service_jwt(test_keys["priv"], test_keys["kid"])
    payload = {
        "token": "eyJhbGciOiJFZERTQSIs...",
        "merchant_id": "mer_croma",
        "payee_id": "acq_croma_001",
        "amount_minor": 500000,
        "currency": "INR",
        "checkout_hash": "sha256:hash123",
        "idempotency_key": "idem_123",
    }

    resp = client.post(
        "/v1/payment-tokens/redeem",
        json=payload,
        headers={"Authorization": f"Service {jwt}"},
    )

    assert resp.status_code == 200
    assert resp.json()["status"] == "REDEEMING"
    assert mock_svc.redeem.call_count == 1


def test_http_redeem_missing_auth_header_fails_and_no_mutation(auth_test_app):
    app, verifier, mock_svc = auth_test_app
    client = TestClient(app)

    resp = client.post(
        "/v1/payment-tokens/redeem",
        json={"token": "ptok_dummy"},
    )

    assert resp.status_code == 401
    assert resp.json()["detail"]["code"] == "UNAUTHORIZED"
    assert "Missing Authorization header" in resp.json()["detail"]["message"]
    # Guarantee: token service is never invoked, no mutation occurs
    assert mock_svc.redeem.call_count == 0


def test_http_redeem_invalid_bearer_scheme_fails_and_no_mutation(auth_test_app, test_keys):
    app, verifier, mock_svc = auth_test_app
    client = TestClient(app)

    jwt = create_raw_service_jwt(test_keys["priv"], test_keys["kid"])
    resp = client.post(
        "/v1/payment-tokens/redeem",
        json={"token": "ptok_dummy"},
        headers={"Authorization": f"Bearer {jwt}"},
    )

    assert resp.status_code == 401
    assert resp.json()["detail"]["code"] == "UNAUTHORIZED"
    assert "Invalid authorization scheme" in resp.json()["detail"]["message"]
    assert mock_svc.redeem.call_count == 0


def test_http_redeem_expired_jwt_fails_and_no_mutation(auth_test_app, test_keys):
    app, verifier, mock_svc = auth_test_app
    client = TestClient(app)

    now = int(datetime.now(UTC).timestamp())
    jwt = create_raw_service_jwt(
        test_keys["priv"],
        test_keys["kid"],
        claims_overrides={"iat": now - 400, "exp": now - 100},
    )
    resp = client.post(
        "/v1/payment-tokens/redeem",
        json={"token": "ptok_dummy"},
        headers={"Authorization": f"Service {jwt}"},
    )

    assert resp.status_code == 401
    assert resp.json()["detail"]["code"] == "UNAUTHORIZED"
    assert "expired" in resp.json()["detail"]["message"]
    assert mock_svc.redeem.call_count == 0


# --- Mock PSP HttpTokenClient Tests ---


def test_mock_psp_http_token_client_sends_service_jwt(test_keys):
    """Verify HttpTokenClient generates and sends valid Service <jwt> signed with key_manager."""

    async def _run() -> None:
        key_manager = PspKeyManager(
            private_key=test_keys["priv"],
            key_id=test_keys["kid"],
        )

        captured_headers: dict[str, str] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured_headers.update(dict(request.headers))
            return httpx.Response(
                status_code=200,
                json={"token_id": "ptok_123", "result": "ACCEPTED", "status": "REDEEMING"},
            )

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            http_client = HttpTokenClient(
                base_url="http://mock-core:8000",
                http_client=client,
                key_manager=key_manager,
            )
            req = TokenRedeemRequest(
                token="ptok_jws_abc",
                merchant_id="mer_croma",
                payee_id="acq_001",
                amount_minor=1000,
                currency="INR",
                checkout_hash="sha256:abc",
                idempotency_key="idem_test_1",
            )
            resp = await http_client.redeem(req)

            assert resp.result == "ACCEPTED"
            assert resp.status == "REDEEMING"

            # Check captured auth header
            auth = captured_headers.get("authorization")
            assert auth is not None
            assert auth.startswith("Service ")

            # Validate that Core verifier accepts the header produced by HttpTokenClient
            verifier = ServiceAuthVerifier(trusted_keys={test_keys["kid"]: test_keys["pub"]})
            claims = verifier.verify_service_jwt(auth)
            assert claims.iss == "mock-psp"
            assert claims.aud == "mandit-core"
            assert claims.key_id == test_keys["kid"]

    asyncio.run(_run())
