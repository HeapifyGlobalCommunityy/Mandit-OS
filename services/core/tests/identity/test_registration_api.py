"""HTTP contract of the registration routes (modules/01 sections 6.1 and 6.2)."""

import json
import re

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from identity_support import ADMIN, ALL_SCOPES, SERVICE, Registry, agent_request, operator_request

from mandit.identity import api
from mandit.identity.api import MAX_BODY_BYTES, timestamp
from mandit.identity.schemas import Principal

TS = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z")


class Caller:
    principal: Principal | None = ADMIN


@pytest.fixture
def caller() -> Caller:
    return Caller()


@pytest.fixture
def client(registry: Registry, caller: Caller) -> TestClient:
    app = FastAPI()
    app.include_router(api.router)
    app.dependency_overrides[api.get_principal] = lambda: caller.principal
    app.dependency_overrides[api.get_registration_service] = lambda: registry.service
    return TestClient(app, raise_server_exceptions=False)


def _error(response, status: int, code: str) -> dict:
    assert response.status_code == status, response.text
    body = response.json()
    assert set(body) == {"error"}
    error = body["error"]
    assert set(error) == {"code", "message", "request_id", "details"}
    assert error["code"] == code
    assert response.headers["x-request-id"] == error["request_id"]
    return error


def _register_verified_operator(client: TestClient) -> str:
    operator_id = client.post("/v1/operators", json=operator_request()).json()["operator_id"]
    assert client.post(f"/v1/operators/{operator_id}/verify").status_code == 200
    return operator_id


# --- Happy path ----------------------------------------------------------------------------


def test_operator_lifecycle(client, registry):
    response = client.post("/v1/operators", json=operator_request())
    assert response.status_code == 201
    body = response.json()
    assert set(body) == {"operator_id", "status", "created_at"}
    assert body["status"] == "PENDING"
    assert body["created_at"] == "2026-11-23T10:00:00.123Z"

    operator_id = body["operator_id"]
    verified = client.post(f"/v1/operators/{operator_id}/verify")
    assert verified.status_code == 200
    assert verified.json() == {
        "operator_id": operator_id,
        "status": "VERIFIED",
        "verified_at": "2026-11-23T10:00:00.123Z",
    }
    assert client.post(f"/v1/operators/{operator_id}/verify").json() == verified.json()

    read = client.get(f"/v1/operators/{operator_id}").json()
    assert read == {
        "operator_id": operator_id,
        "legal_name": "Acme Agents Pvt Ltd (synthetic)",
        "domain": "acme-agents.example",
        "contact_email": "ops@acme-agents.example",
        "status": "VERIFIED",
        "created_at": "2026-11-23T10:00:00.123Z",
        "verified_at": "2026-11-23T10:00:00.123Z",
    }
    assert registry.event_types() == ["OPERATOR_REGISTERED", "OPERATOR_VERIFIED"]


def test_pending_operator_body_has_no_verified_at(client):
    operator_id = client.post("/v1/operators", json=operator_request()).json()["operator_id"]
    assert "verified_at" not in client.get(f"/v1/operators/{operator_id}").json()


def test_register_and_read_agent(client, caller):
    operator_id = _register_verified_operator(client)
    response = client.post("/v1/agents/register", json=agent_request(operator_id))
    assert response.status_code == 201
    body = response.json()
    assert set(body) == {
        "agent_id",
        "key_id",
        "key_thumbprint",
        "scopes",
        "status",
        "directory_url",
    }
    agent_id = body["agent_id"]
    assert body["status"] == "ACTIVE"
    assert body["scopes"] == sorted(ALL_SCOPES)
    assert body["directory_url"] == f"/.well-known/mandit/agents/{agent_id}.jwks"
    assert re.fullmatch(r"[A-Za-z0-9_-]{43}", body["key_thumbprint"])

    caller.principal = SERVICE
    read = client.get(f"/v1/agents/{agent_id}")
    assert read.status_code == 200
    agent = read.json()
    assert agent["operator_id"] == operator_id
    assert agent["name"] == "acme-shopper" and agent["revoked_at"] is None
    assert TS.fullmatch(agent["created_at"])
    assert agent["keys"] == [
        {
            "key_id": body["key_id"],
            "key_thumbprint": body["key_thumbprint"],
            "status": "ACTIVE",
            "created_at": agent["created_at"],
        }
    ]
    # The registry read exposes thumbprints, not key material; the directory serves the keys.
    assert "jwk" not in agent and all(
        set(k) == {"key_id", "key_thumbprint", "status", "created_at"} for k in agent["keys"]
    )


def test_request_id_is_echoed_when_well_formed(client):
    response = client.get("/v1/operators/op_MISSING", headers={"X-Request-ID": "req_abc-123"})
    assert _error(response, 404, "NOT_FOUND")["request_id"] == "req_abc-123"
    hostile = client.get("/v1/operators/op_MISSING", headers={"X-Request-ID": "a\tb"})
    assert re.fullmatch(r"req_[0-9A-Z]{26}", _error(hostile, 404, "NOT_FOUND")["request_id"])


# --- Error paths ---------------------------------------------------------------------------


def test_unauthenticated_by_default(registry):
    app = FastAPI()
    app.include_router(api.router)
    app.dependency_overrides[api.get_registration_service] = lambda: registry.service
    client = TestClient(app)
    _error(client.post("/v1/operators", json=operator_request()), 401, "UNAUTHENTICATED")
    _error(client.get("/v1/agents/agt_X"), 401, "UNAUTHENTICATED")
    assert registry.db.events == []


def test_fails_closed_without_a_configured_registry():
    app = FastAPI()
    app.include_router(api.router)
    app.dependency_overrides[api.get_principal] = lambda: ADMIN
    client = TestClient(app)
    _error(client.post("/v1/operators", json=operator_request()), 503, "DEPENDENCY_UNAVAILABLE")


def test_forbidden(client, caller):
    caller.principal = SERVICE
    _error(client.post("/v1/operators", json=operator_request()), 403, "FORBIDDEN")


def test_operator_not_verified(client):
    operator_id = client.post("/v1/operators", json=operator_request()).json()["operator_id"]
    response = client.post("/v1/agents/register", json=agent_request(operator_id))
    _error(response, 403, "OPERATOR_NOT_VERIFIED")


def test_scope_denied(client):
    operator_id = _register_verified_operator(client)
    request = agent_request(operator_id, requested_scopes=["user:ask"])
    _error(client.post("/v1/agents/register", json=request), 403, "SCOPE_DENIED")


def test_duplicate_key_conflict(client):
    operator_id = _register_verified_operator(client)
    request = agent_request(operator_id)
    assert client.post("/v1/agents/register", json=request).status_code == 201
    _error(client.post("/v1/agents/register", json=request), 409, "CONFLICT")


def test_verify_suspended_operator_conflict(client, registry):
    operator = registry.operator(status="SUSPENDED")
    _error(client.post(f"/v1/operators/{operator.operator_id}/verify"), 409, "CONFLICT")


@pytest.mark.parametrize(
    "path", ["/v1/operators/op_MISSING", "/v1/operators/not-an-id", "/v1/agents/agt_MISSING"]
)
def test_not_found(client, path):
    _error(client.get(path), 404, "NOT_FOUND")


def test_malformed_ids_skip_the_database(client, registry):
    _error(client.post("/v1/operators/op_%27%3B--/verify"), 404, "NOT_FOUND")
    assert registry.db.locks == []


def test_invalid_public_key_is_a_validation_error(client):
    operator_id = _register_verified_operator(client)
    small_order = {"kty": "OKP", "crv": "Ed25519", "x": "AQ" + "A" * 41}
    request = agent_request(operator_id, public_key=small_order)
    _error(client.post("/v1/agents/register", json=request), 400, "VALIDATION_ERROR")


@pytest.mark.parametrize(
    "overrides, field",
    [
        ({"domain": "acme.com"}, "domain"),  # a real domain: synthetic data only
        ({"domain": "example"}, "domain"),
        ({"domain": "-bad-.example"}, "domain"),
        ({"domain": "a" * 64 + ".example"}, "domain"),
        ({"contact_email": "ops@gmail.com"}, "contact_email"),
        ({"contact_email": "no-at-sign.example"}, "contact_email"),
        ({"legal_name": ""}, "legal_name"),
        ({"legal_name": "Acme\u202eevil"}, "legal_name"),  # bidi override
        ({"legal_name": " padded"}, "legal_name"),
        ({"legal_name": 42}, "legal_name"),
        ({"status": "VERIFIED"}, "status"),  # callers cannot choose their own status
    ],
)
def test_operator_validation(client, overrides, field):
    error = _error(
        client.post("/v1/operators", json=operator_request(**overrides)), 400, "VALIDATION_ERROR"
    )
    assert [f["field"] for f in error["details"]["fields"]] == [field]
    # The rejected value is never echoed back.
    assert all("input" not in f for f in error["details"]["fields"])


@pytest.mark.parametrize(
    "overrides, field",
    [
        ({"operator_id": "acme"}, "operator_id"),
        ({"name": "has space"}, "name"),
        ({"version": ""}, "version"),
        ({"model_declared": "x" * 65}, "model_declared"),
        ({"requested_scopes": []}, "requested_scopes"),
        ({"requested_scopes": ["PURCHASE:EXECUTE"]}, "requested_scopes.0"),
        ({"requested_scopes": "purchase:execute"}, "requested_scopes"),
        ({"public_key": {}}, "public_key"),
        ({"agent_id": "agt_chosen"}, "agent_id"),
    ],
)
def test_agent_validation(client, overrides, field):
    request = {**agent_request("op_TEST0000"), **overrides}
    error = _error(client.post("/v1/agents/register", json=request), 400, "VALIDATION_ERROR")
    assert [f["field"] for f in error["details"]["fields"]] == [field]


def test_normalizes_domain_and_email_case(client):
    request = operator_request(domain="Acme.EXAMPLE", contact_email="Ops@Acme.Example")
    operator_id = client.post("/v1/operators", json=request).json()["operator_id"]
    body = client.get(f"/v1/operators/{operator_id}").json()
    assert body["domain"] == "acme.example"
    assert body["contact_email"] == "Ops@acme.example"


@pytest.mark.parametrize(
    "content, content_type",
    [
        (b'{"legal_name": "a", "legal_name": "b"}', "application/json"),  # duplicate member
        (b'{"legal_name": NaN}', "application/json"),
        (b"[1, 2]", "application/json"),
        (b"not json", "application/json"),
        (b"\xff\xfe", "application/json"),
        (json.dumps(operator_request()).encode(), "text/plain"),  # CSRF-safe content type only
        (json.dumps(operator_request()).encode(), ""),
        (b" " * (MAX_BODY_BYTES + 1), "application/json"),
    ],
    ids=["duplicate", "nan", "array", "garbage", "bad-utf8", "text-plain", "none", "too-large"],
)
def test_malformed_bodies(client, registry, content, content_type):
    headers = {"Content-Type": content_type} if content_type else {}
    response = client.post("/v1/operators", content=content, headers=headers)
    _error(response, 400, "VALIDATION_ERROR")
    assert registry.db.operators == {}


def test_content_type_parameters_are_allowed(client):
    response = client.post(
        "/v1/operators",
        content=json.dumps(operator_request()),
        headers={"Content-Type": "application/json; charset=utf-8"},
    )
    assert response.status_code == 201


def test_unexpected_failure_is_internal_error_without_detail(client, registry):
    operator_id = _register_verified_operator(client)
    registry.db.fail_on_emit = True
    error = _error(
        client.post("/v1/agents/register", json=agent_request(operator_id)),
        500,
        "INTERNAL_ERROR",
    )
    assert error["message"] == "Internal error" and error["details"] == {}
    assert "ledger" not in json.dumps(error)


def test_unregistered_code_is_not_emitted():
    response = api._error("req_x", "MADE_UP_CODE", "secret detail", {"x": 1})
    body = json.loads(response.body)
    assert response.status_code == 500
    assert body["error"] == {
        "code": "INTERNAL_ERROR",
        "message": "Internal error",
        "request_id": "req_x",
        "details": {},
    }


def test_status_codes_are_registered_in_appendix_b():
    from pathlib import Path

    reference = Path(__file__).resolve().parents[4] / "docs" / "REFERENCE.md"
    appendix = reference.read_text(encoding="utf-8").split("## Appendix B")[1]
    for code, status in api.STATUS.items():
        assert re.search(rf"\| `{code}` \| {status} \|", appendix), code


def test_timestamp_format():
    from datetime import datetime, timedelta, timezone

    ist = timezone(timedelta(hours=5, minutes=30))
    assert timestamp(datetime(2026, 11, 23, 15, 45, 30, 123999, tzinfo=ist)) == (
        "2026-11-23T10:15:30.123Z"
    )
