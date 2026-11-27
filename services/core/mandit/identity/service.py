"""Operator and agent registration (modules/01 responsibilities R1 and R2).

Every check runs here rather than in the HTTP layer, so any future caller (CLI, seed script,
another transport) gets the same authorization and validation:

1. Authorization uses only the caller `Principal`, before any database access.
2. Inputs that need no database (the public key and the requested scopes) are validated next.
3. Registry state is read under a row lock and the write plus its ledger event commit together.

Callers that may not see a resource get NOT_FOUND, the same as for a missing one, so the
registry cannot be enumerated by probing identifiers.
"""

import dataclasses
from collections.abc import Callable
from datetime import UTC, datetime

from . import events
from .events import Actor
from .ids import new_id
from .keys import base64url, jwk_thumbprint, public_key_from_jwk
from .repository import UnitOfWork
from .schemas import (
    AgentKeyRecord,
    AgentRecord,
    AgentRegistration,
    AgentView,
    IdentityError,
    OperatorRecord,
    OperatorRegistration,
    Principal,
)

# The KYA scopes of the tool surface (REFERENCE section 10). `user:ask` is a Phase 2 tool, so
# it is not grantable yet. A scope outside this set is refused, never silently dropped: the
# operator must see that the agent will not get the access it asked for.
GRANTABLE_SCOPES = frozenset(
    {
        "transaction:open",
        "merchant:read",
        "web:fetch",
        "checkout:create",
        "purchase:propose",
        "purchase:read",
        "purchase:execute",
    }
)

VERIFICATION_METHOD = "MANUAL"  # Phase 1 KYB stand-in; domain-control proof is I-1.4


def utc_now() -> datetime:
    return datetime.now(UTC)


def directory_url(agent_id: str) -> str:
    return f"/.well-known/mandit/agents/{agent_id}.jwks"


def _actor(principal: Principal) -> Actor:
    return {"type": principal.kind, "id": principal.id}


def _require_mandit_admin(principal: Principal) -> None:
    if principal.kind != "USER" or not principal.mandit_admin:
        raise IdentityError("FORBIDDEN", "Mandit administrator role required")


def _not_found(kind: str) -> IdentityError:
    return IdentityError("NOT_FOUND", f"{kind} not found")


class RegistrationService:
    def __init__(
        self, unit_of_work: Callable[[], UnitOfWork], *, clock: Callable[[], datetime] = utc_now
    ) -> None:
        self._unit_of_work = unit_of_work
        self._clock = clock

    # --- Operators ---------------------------------------------------------------------

    async def register_operator(
        self, principal: Principal, request: OperatorRegistration
    ) -> OperatorRecord:
        _require_mandit_admin(principal)
        operator = OperatorRecord(
            operator_id=new_id("op"),
            legal_name=request.legal_name,
            domain=request.domain,
            contact_email=request.contact_email,
            status="PENDING",
            verified_at=None,
            created_at=self._clock(),
        )
        async with self._unit_of_work() as uow:
            await uow.store.add_operator(operator)
            await uow.events.emit(
                transaction_id=None,
                event_type=events.OPERATOR_REGISTERED,
                producer=events.PRODUCER,
                actor=_actor(principal),
                refs={"operator_id": operator.operator_id},
                # contact_email is personal data and stays out of the append-only ledger.
                payload={"legal_name": operator.legal_name, "domain": operator.domain},
            )
            await uow.commit()
        return operator

    async def get_operator(self, principal: Principal, operator_id: str) -> OperatorRecord:
        if principal.kind != "USER" or not principal.acts_for(operator_id):
            raise _not_found("Operator")
        async with self._unit_of_work() as uow:
            operator = await uow.store.get_operator(operator_id)
        if operator is None:
            raise _not_found("Operator")
        return operator

    async def verify_operator(self, principal: Principal, operator_id: str) -> OperatorRecord:
        """PENDING -> VERIFIED. Repeating it is a no-op; a SUSPENDED operator is not revived."""
        _require_mandit_admin(principal)
        async with self._unit_of_work() as uow:
            operator = await uow.store.get_operator(operator_id, lock="update")
            if operator is None:
                raise _not_found("Operator")
            if operator.status == "VERIFIED":
                return operator
            if operator.status != "PENDING":
                raise IdentityError("CONFLICT", f"Operator is {operator.status}")
            operator = dataclasses.replace(operator, status="VERIFIED", verified_at=self._clock())
            await uow.store.save_operator_status(operator)
            await uow.events.emit(
                transaction_id=None,
                event_type=events.OPERATOR_VERIFIED,
                producer=events.PRODUCER,
                actor=_actor(principal),
                refs={"operator_id": operator_id},
                payload={"verified_by": principal.id, "method": VERIFICATION_METHOD},
            )
            await uow.commit()
        return operator

    # --- Agents ------------------------------------------------------------------------

    async def register_agent(self, principal: Principal, request: AgentRegistration) -> AgentView:
        if principal.kind != "USER" or not principal.acts_for(request.operator_id):
            raise _not_found("Operator")

        # Raises VALIDATION_ERROR for anything but a valid public Ed25519 key, including
        # small-order points and JWKs that carry a private key ("d").
        public_key = public_key_from_jwk(request.public_key)
        jwk = {"kty": "OKP", "crv": "Ed25519", "x": base64url(public_key.public_bytes_raw())}
        thumbprint = jwk_thumbprint(jwk)

        denied = sorted(set(request.requested_scopes) - GRANTABLE_SCOPES)
        if denied:
            raise IdentityError("SCOPE_DENIED", f"Scopes not grantable: {', '.join(denied)}")

        now = self._clock()
        agent = AgentRecord(
            agent_id=new_id("agt"),
            operator_id=request.operator_id,
            name=request.name,
            version=request.version,
            model_declared=request.model_declared,
            scopes=tuple(sorted(set(request.requested_scopes))),
            status="ACTIVE",
            created_at=now,
        )
        key = AgentKeyRecord(
            key_id=new_id("akey"),
            agent_id=agent.agent_id,
            jwk=jwk,  # only the public members; client labels such as kid are not stored
            thumbprint=thumbprint,
            status="ACTIVE",
            created_at=now,
        )
        async with self._unit_of_work() as uow:
            # FOR SHARE: a concurrent suspension waits until this registration commits.
            operator = await uow.store.get_operator(request.operator_id, lock="share")
            if operator is None:
                raise _not_found("Operator")
            if operator.status != "VERIFIED":
                raise IdentityError("OPERATOR_NOT_VERIFIED", "Operator is not verified")
            await uow.store.add_agent(agent, key)
            await uow.events.emit(
                transaction_id=None,
                event_type=events.AGENT_REGISTERED,
                producer=events.PRODUCER,
                actor=_actor(principal),
                refs={"agent_id": agent.agent_id, "operator_id": agent.operator_id},
                payload={
                    "key_id": key.key_id,
                    "key_thumbprint": key.thumbprint,
                    "scopes": list(agent.scopes),
                    "version": agent.version,
                    "model_declared": agent.model_declared,
                },
            )
            await uow.commit()
        return AgentView(agent, (key,))

    async def get_agent(self, principal: Principal, agent_id: str) -> AgentView:
        async with self._unit_of_work() as uow:
            view = await uow.store.get_agent(agent_id)
        if view is None or not (
            principal.kind == "SERVICE" or principal.acts_for(view.agent.operator_id)
        ):
            raise _not_found("Agent")
        return view
