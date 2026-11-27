"""HTTP routes for operator and agent registration (modules/01 sections 6.1 and 6.2).

The application mounts `router` and overrides two dependencies:

- `get_principal`: the authenticated console or service caller. The default denies (401).
- `get_registration_service`: the configured service. The default fails closed (503).

Request bodies are parsed here instead of by FastAPI so that every failure uses the error
envelope of REFERENCE 7.6, bodies are size-limited before parsing, and JSON with duplicate
keys or non-finite numbers is refused instead of being resolved one way by this parser and
another way by a proxy or log pipeline.
"""

import json
import logging
import re
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ValidationError
from ulid import ULID

from .schemas import (
    ID_PATTERN,
    AgentRegistration,
    AgentView,
    IdentityError,
    OperatorRecord,
    OperatorRegistration,
    Principal,
)
from .service import RegistrationService, directory_url

logger = logging.getLogger(__name__)

router = APIRouter(tags=["identity"])

MAX_BODY_BYTES = 16_384
REQUEST_ID = re.compile(r"[A-Za-z0-9_-]{1,64}")

# HTTP status of every code these routes emit (REFERENCE Appendix B).
STATUS = {
    "VALIDATION_ERROR": 400,
    "UNAUTHENTICATED": 401,
    "FORBIDDEN": 403,
    "OPERATOR_NOT_VERIFIED": 403,
    "SCOPE_DENIED": 403,
    "NOT_FOUND": 404,
    "CONFLICT": 409,
    "INTERNAL_ERROR": 500,
    "DEPENDENCY_UNAVAILABLE": 503,
}


def get_principal() -> Principal | None:
    """Overridden by the application's console and service authentication."""
    return None


def get_registration_service() -> RegistrationService | None:
    """Overridden by the application once storage and the event sink are configured."""
    return None


PrincipalDep = Annotated[Principal | None, Depends(get_principal)]
ServiceDep = Annotated[RegistrationService | None, Depends(get_registration_service)]


def timestamp(value: datetime) -> str:
    """RFC 3339, UTC, millisecond precision, Z suffix (REFERENCE 7.3)."""
    return value.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _request_id(request: Request) -> str:
    supplied = request.headers.get("x-request-id", "")
    return supplied if REQUEST_ID.fullmatch(supplied) else f"req_{ULID()}"


def _error(
    request_id: str, code: str, message: str, details: dict[str, Any] | None = None
) -> JSONResponse:
    if code not in STATUS:
        code, message, details = "INTERNAL_ERROR", "Internal error", None
    return JSONResponse(
        status_code=STATUS[code],
        content={
            "error": {
                "code": code,
                "message": message,
                "request_id": request_id,
                "details": details or {},
            }
        },
        headers={"X-Request-ID": request_id},
    )


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate member {key!r}")
        result[key] = value
    return result


def _reject_constant(name: str) -> Any:
    raise ValueError(f"non-finite number {name}")


async def _parse[Model: BaseModel](request: Request, model: type[Model]) -> Model:
    content_type = request.headers.get("content-type", "").split(";")[0].strip().lower()
    if content_type != "application/json":
        # Also a CSRF defence: an HTML form cannot send application/json cross-site.
        raise IdentityError("VALIDATION_ERROR", "Content-Type must be application/json")
    body = bytearray()
    async for chunk in request.stream():
        body += chunk
        if len(body) > MAX_BODY_BYTES:
            raise IdentityError("VALIDATION_ERROR", "Request body too large")
    try:
        data = json.loads(
            body.decode("utf-8"),
            object_pairs_hook=_reject_duplicates,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise IdentityError("VALIDATION_ERROR", "Body must be one JSON object") from exc
    try:
        return model.model_validate(data)
    except ValidationError as exc:
        # Field locations and reasons only: input values are not echoed back or logged.
        fields = [
            {"field": ".".join(str(p) for p in e["loc"]) or "body", "reason": e["msg"]}
            for e in exc.errors(include_input=False, include_url=False)
        ]
        raise IdentityError(
            "VALIDATION_ERROR", "Request body failed validation", {"fields": fields}
        ) from exc


async def _handle(
    request: Request,
    principal: Principal | None,
    service: RegistrationService | None,
    action: Callable[[RegistrationService, Principal], Awaitable[tuple[int, dict[str, Any]]]],
) -> JSONResponse:
    request_id = _request_id(request)
    try:
        if principal is None:
            raise IdentityError("UNAUTHENTICATED", "Authentication required")
        if service is None:
            raise IdentityError("DEPENDENCY_UNAVAILABLE", "Identity registry is not configured")
        status, content = await action(service, principal)
    except IdentityError as exc:
        return _error(request_id, exc.code, exc.message, exc.details)
    except Exception:
        logger.exception("identity request failed", extra={"request_id": request_id})
        return _error(request_id, "INTERNAL_ERROR", "Internal error")
    return JSONResponse(status_code=status, content=content, headers={"X-Request-ID": request_id})


ID_KIND = {"op": "Operator", "agt": "Agent"}


def _checked_id(kind: str, value: str) -> str:
    # A malformed identifier cannot exist, so it is NOT_FOUND without a database lookup.
    if not ID_PATTERN[kind].fullmatch(value):
        raise IdentityError("NOT_FOUND", f"{ID_KIND[kind]} not found")
    return value


def operator_body(operator: OperatorRecord) -> dict[str, Any]:
    body: dict[str, Any] = {
        "operator_id": operator.operator_id,
        "legal_name": operator.legal_name,
        "domain": operator.domain,
        "contact_email": operator.contact_email,
        "status": operator.status,
        "created_at": timestamp(operator.created_at),
    }
    if operator.verified_at is not None:
        body["verified_at"] = timestamp(operator.verified_at)
    return body


def agent_body(view: AgentView) -> dict[str, Any]:
    agent = view.agent
    return {
        "agent_id": agent.agent_id,
        "operator_id": agent.operator_id,
        "name": agent.name,
        "version": agent.version,
        "model_declared": agent.model_declared,
        "scopes": list(agent.scopes),
        "status": agent.status,
        "created_at": timestamp(agent.created_at),
        "revoked_at": None if agent.revoked_at is None else timestamp(agent.revoked_at),
        "keys": [
            {
                "key_id": key.key_id,
                "key_thumbprint": key.thumbprint,
                "status": key.status,
                "created_at": timestamp(key.created_at),
            }
            for key in view.keys
        ],
        "directory_url": directory_url(agent.agent_id),
    }


@router.post("/v1/operators")
async def register_operator(
    request: Request, principal: PrincipalDep, service: ServiceDep
) -> JSONResponse:
    async def action(svc: RegistrationService, who: Principal) -> tuple[int, dict[str, Any]]:
        operator = await svc.register_operator(who, await _parse(request, OperatorRegistration))
        return 201, {
            "operator_id": operator.operator_id,
            "status": operator.status,
            "created_at": timestamp(operator.created_at),
        }

    return await _handle(request, principal, service, action)


@router.get("/v1/operators/{operator_id}")
async def get_operator(
    operator_id: str, request: Request, principal: PrincipalDep, service: ServiceDep
) -> JSONResponse:
    async def action(svc: RegistrationService, who: Principal) -> tuple[int, dict[str, Any]]:
        operator = await svc.get_operator(who, _checked_id("op", operator_id))
        return 200, operator_body(operator)

    return await _handle(request, principal, service, action)


@router.post("/v1/operators/{operator_id}/verify")
async def verify_operator(
    operator_id: str, request: Request, principal: PrincipalDep, service: ServiceDep
) -> JSONResponse:
    async def action(svc: RegistrationService, who: Principal) -> tuple[int, dict[str, Any]]:
        operator = await svc.verify_operator(who, _checked_id("op", operator_id))
        return 200, {
            "operator_id": operator.operator_id,
            "status": operator.status,
            "verified_at": operator_body(operator)["verified_at"],
        }

    return await _handle(request, principal, service, action)


@router.post("/v1/agents/register")
async def register_agent(
    request: Request, principal: PrincipalDep, service: ServiceDep
) -> JSONResponse:
    async def action(svc: RegistrationService, who: Principal) -> tuple[int, dict[str, Any]]:
        view = await svc.register_agent(who, await _parse(request, AgentRegistration))
        key = view.keys[0]
        return 201, {
            "agent_id": view.agent.agent_id,
            "key_id": key.key_id,
            "key_thumbprint": key.thumbprint,
            "scopes": list(view.agent.scopes),
            "status": view.agent.status,
            "directory_url": directory_url(view.agent.agent_id),
        }

    return await _handle(request, principal, service, action)


@router.get("/v1/agents/{agent_id}")
async def get_agent(
    agent_id: str, request: Request, principal: PrincipalDep, service: ServiceDep
) -> JSONResponse:
    async def action(svc: RegistrationService, who: Principal) -> tuple[int, dict[str, Any]]:
        return 200, agent_body(await svc.get_agent(who, _checked_id("agt", agent_id)))

    return await _handle(request, principal, service, action)
