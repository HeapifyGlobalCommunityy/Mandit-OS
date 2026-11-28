"""RegistrationService: authorization, operator lifecycle, agent registration and events."""

import re

import pytest
from identity_support import (
    ADMIN,
    ALL_SCOPES,
    SERVICE,
    STRANGER,
    Registry,
    agent_request,
    operator_admin,
    operator_request,
    public_jwk,
    run,
)

from mandit.identity.keys import base64url, jwk_thumbprint
from mandit.identity.schemas import AgentRegistration, IdentityError, OperatorRegistration
from mandit.identity.service import GRANTABLE_SCOPES, directory_url


def _code(call) -> str:
    with pytest.raises(IdentityError) as err:
        run(call)
    return err.value.code


def _agent(registry: Registry, operator_id: str, **overrides):
    request = AgentRegistration.model_validate(agent_request(operator_id, **overrides))
    return registry.service.register_agent(operator_admin(operator_id), request)


# --- Operators ---------------------------------------------------------------------------


def test_register_operator_is_pending_and_emits_event(registry):
    request = OperatorRegistration.model_validate(operator_request())
    operator = run(registry.service.register_operator(ADMIN, request))

    assert re.fullmatch(r"op_[0-9A-Z]{26}", operator.operator_id)
    assert operator.status == "PENDING" and operator.verified_at is None
    assert operator.created_at == registry.clock.now
    assert registry.db.operators[operator.operator_id] == operator
    [event] = registry.db.events
    assert event.event_type == "OPERATOR_REGISTERED"
    assert event.producer == "identity" and event.transaction_id is None
    assert event.actor == {"type": "USER", "id": ADMIN.id}
    assert event.refs == {"operator_id": operator.operator_id}
    # The contact email is personal data and must not reach the append-only ledger.
    assert event.payload == {"legal_name": request.legal_name, "domain": "acme-agents.example"}


@pytest.mark.parametrize("principal", [operator_admin("op_TEST0000"), SERVICE, STRANGER])
def test_only_mandit_admin_registers_operators(registry, principal):
    request = OperatorRegistration.model_validate(operator_request())
    assert _code(registry.service.register_operator(principal, request)) == "FORBIDDEN"
    assert registry.db.operators == {} and registry.db.events == []


def test_verify_operator(registry):
    pending = registry.operator(status="PENDING")
    registry.clock.advance(30)
    operator = run(registry.service.verify_operator(ADMIN, pending.operator_id))

    assert operator.status == "VERIFIED" and operator.verified_at == registry.clock.now
    assert registry.db.operators[pending.operator_id] == operator
    assert (pending.operator_id, "update") in registry.db.locks
    [event] = registry.db.events
    assert event.event_type == "OPERATOR_VERIFIED"
    assert event.refs == {"operator_id": pending.operator_id}
    assert event.payload == {"verified_by": ADMIN.id, "method": "MANUAL"}


def test_verify_is_idempotent_without_a_second_event(registry):
    pending = registry.operator(status="PENDING")
    first = run(registry.service.verify_operator(ADMIN, pending.operator_id))
    registry.clock.advance(60)
    again = run(registry.service.verify_operator(ADMIN, pending.operator_id))
    assert again == first
    assert registry.event_types() == ["OPERATOR_VERIFIED"]


def test_suspended_operator_cannot_be_verified(registry):
    suspended = registry.operator(status="SUSPENDED")
    assert _code(registry.service.verify_operator(ADMIN, suspended.operator_id)) == "CONFLICT"
    assert registry.db.operators[suspended.operator_id].status == "SUSPENDED"
    assert registry.db.events == []


def test_verify_unknown_operator(registry):
    assert _code(registry.service.verify_operator(ADMIN, "op_MISSING")) == "NOT_FOUND"


@pytest.mark.parametrize("principal", [operator_admin("op_TEST0000"), SERVICE])
def test_only_mandit_admin_verifies(registry, principal):
    pending = registry.operator(status="PENDING")
    assert _code(registry.service.verify_operator(principal, pending.operator_id)) == "FORBIDDEN"
    assert registry.db.operators[pending.operator_id].status == "PENDING"


def test_get_operator_visibility(registry):
    operator = registry.operator()
    assert run(registry.service.get_operator(ADMIN, operator.operator_id)) == operator
    own = operator_admin(operator.operator_id)
    assert run(registry.service.get_operator(own, operator.operator_id)) == operator
    # Hidden and missing look the same, so operator IDs cannot be enumerated.
    assert _code(registry.service.get_operator(STRANGER, operator.operator_id)) == "NOT_FOUND"
    assert _code(registry.service.get_operator(SERVICE, operator.operator_id)) == "NOT_FOUND"
    assert _code(registry.service.get_operator(ADMIN, "op_MISSING")) == "NOT_FOUND"


# --- Agents ------------------------------------------------------------------------------


def test_register_agent(registry):
    operator = registry.operator()
    jwk = public_jwk()
    view = run(_agent(registry, operator.operator_id, public_key={**jwk, "kid": "client-label"}))
    agent, (key,) = view.agent, view.keys

    assert re.fullmatch(r"agt_[0-9A-Z]{26}", agent.agent_id)
    assert re.fullmatch(r"akey_[0-9A-Z]{26}", key.key_id)
    assert agent.operator_id == operator.operator_id
    assert agent.status == "ACTIVE" and key.status == "ACTIVE"
    assert agent.scopes == tuple(sorted(ALL_SCOPES))
    assert key.agent_id == agent.agent_id
    assert key.thumbprint == jwk_thumbprint(jwk)
    assert key.jwk == jwk  # the client's kid label is not stored
    assert registry.db.agents[agent.agent_id] == agent
    assert registry.db.keys[key.key_id] == key
    assert (operator.operator_id, "share") in registry.db.locks

    [event] = registry.db.events
    assert event.event_type == "AGENT_REGISTERED"
    assert event.actor == {"type": "USER", "id": "usr_operator_admin"}
    assert event.refs == {"agent_id": agent.agent_id, "operator_id": operator.operator_id}
    assert event.payload == {
        "key_id": key.key_id,
        "key_thumbprint": key.thumbprint,
        "scopes": sorted(ALL_SCOPES),
        "version": "3.0.0",
        "model_declared": "demo-llm",
    }


def test_mandit_admin_may_register_for_any_operator(registry):
    operator = registry.operator()
    request = AgentRegistration.model_validate(agent_request(operator.operator_id))
    view = run(registry.service.register_agent(ADMIN, request))
    assert view.agent.operator_id == operator.operator_id


def test_scopes_are_deduplicated_and_sorted(registry):
    operator = registry.operator()
    scopes = ["purchase:read", "merchant:read", "purchase:read"]
    view = run(_agent(registry, operator.operator_id, requested_scopes=scopes))
    assert view.agent.scopes == ("merchant:read", "purchase:read")


@pytest.mark.parametrize("status", ["PENDING", "SUSPENDED"])
def test_unverified_operator_cannot_register_agents(registry, status):
    operator = registry.operator(status=status)
    assert _code(_agent(registry, operator.operator_id)) == "OPERATOR_NOT_VERIFIED"
    assert registry.db.agents == {} and registry.db.events == []


def test_unknown_operator(registry):
    request = AgentRegistration.model_validate(agent_request("op_MISSING"))
    assert _code(registry.service.register_agent(ADMIN, request)) == "NOT_FOUND"


@pytest.mark.parametrize("principal", [STRANGER, SERVICE])
def test_cannot_register_for_another_operator(registry, principal):
    operator = registry.operator()
    request = AgentRegistration.model_validate(agent_request(operator.operator_id))
    assert _code(registry.service.register_agent(principal, request)) == "NOT_FOUND"
    assert registry.db.locks == []  # refused before touching the registry


@pytest.mark.parametrize("scope", ["user:ask", "admin:all", "payment:raw_card"])
def test_ungrantable_scope_is_denied_not_dropped(registry, scope):
    operator = registry.operator()
    with pytest.raises(IdentityError) as err:
        run(_agent(registry, operator.operator_id, requested_scopes=["merchant:read", scope]))
    assert err.value.code == "SCOPE_DENIED"
    assert scope in err.value.message
    assert registry.db.agents == {} and registry.db.events == []


def test_grantable_scopes_are_the_phase_1_tool_scopes():
    assert set(ALL_SCOPES) == GRANTABLE_SCOPES
    assert "user:ask" not in GRANTABLE_SCOPES


@pytest.mark.parametrize(
    "jwk",
    [
        {"kty": "EC", "crv": "P-256", "x": "AAAA", "y": "AAAA"},
        {"kty": "OKP", "crv": "X25519", "x": base64url(bytes(32))},
        {"kty": "OKP", "crv": "Ed25519", "x": "short"},
        {**public_jwk(), "d": base64url(bytes(32))},  # a private key must never be accepted
        {"kty": "OKP", "crv": "Ed25519", "x": base64url(bytes([1]) + bytes(31))},  # small order
    ],
    ids=["ec-key", "x25519", "bad-length", "private-key", "small-order"],
)
def test_invalid_public_key(registry, jwk):
    operator = registry.operator()
    assert _code(_agent(registry, operator.operator_id, public_key=jwk)) == "VALIDATION_ERROR"
    assert registry.db.agents == {} and registry.db.events == []


def test_key_cannot_be_registered_twice(registry):
    operator = registry.operator()
    jwk = public_jwk()
    first = run(_agent(registry, operator.operator_id, public_key=jwk))
    # The same key with a different label is still the same key (RFC 7638 thumbprint).
    again = _agent(registry, operator.operator_id, name="other", public_key={**jwk, "kid": "x"})
    assert _code(again) == "CONFLICT"
    assert list(registry.db.agents) == [first.agent.agent_id]
    assert registry.event_types() == ["AGENT_REGISTERED"]


def test_failed_event_rolls_back_the_registration(registry):
    operator = registry.operator()
    registry.db.fail_on_emit = True
    with pytest.raises(RuntimeError):
        run(_agent(registry, operator.operator_id))
    assert registry.db.agents == {} and registry.db.keys == {} and registry.db.commits == 0


def test_get_agent_visibility(registry):
    operator = registry.operator()
    view = run(_agent(registry, operator.operator_id))
    agent_id = view.agent.agent_id

    for principal in (ADMIN, SERVICE, operator_admin(operator.operator_id)):
        assert run(registry.service.get_agent(principal, agent_id)) == view
    assert _code(registry.service.get_agent(STRANGER, agent_id)) == "NOT_FOUND"
    assert _code(registry.service.get_agent(ADMIN, "agt_MISSING")) == "NOT_FOUND"


def test_directory_url():
    assert directory_url("agt_X") == "/.well-known/mandit/agents/agt_X.jwks"
