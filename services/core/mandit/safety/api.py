"""HTTP routes of the safety module (modules/02 sections 6-8)."""

from __future__ import annotations

import secrets
from typing import Annotated, Any

from fastapi import APIRouter, Body, Depends, Header, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from mandit.grounding.api import get_directory, merchant_body
from mandit.grounding.interface import MerchantDirectory

from .service import (
    ABLATION_PROFILES,
    build_reputation_store,
    build_site_scanner,
    current_profile,
)
from .site_scan import DomainReputationStore, InvalidScanTarget, SiteScanner
from .site_scan.config import SIGNAL_CODES
from .site_scan.domains import parse_target
from .site_scan.scanner import Profile

router = APIRouter(prefix="/v1/safety", tags=["safety"])

MAX_HTML_CHARS = 5_000_000


class SiteScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: Annotated[str, Field(min_length=1, max_length=2048)]
    html: Annotated[str | None, Field(max_length=MAX_HTML_CHARS)] = None
    transaction_id: Annotated[str | None, Field(pattern=r"^txn_[0-9A-Z]{26}$")] = None


def get_profile() -> Profile:
    return current_profile()


def get_site_scanner(profile: Annotated[Profile, Depends(get_profile)]) -> SiteScanner:
    return build_site_scanner(profile)


def get_reputation_store() -> DomainReputationStore:
    return build_reputation_store()


def _error(
    status: int,
    code: str,
    message: str,
    request_id: str | None,
    details: dict[str, Any] | None = None,
) -> JSONResponse:
    # Error envelope from REFERENCE.md section 7.6. Swap for mandit.common's helper once it exists.
    return JSONResponse(
        status_code=status,
        content={
            "error": {
                "code": code,
                "message": message,
                "request_id": request_id or "req_" + secrets.token_hex(13).upper(),
                "details": details or {},
            }
        },
    )


def parse_ablation(header: str) -> frozenset[str]:
    """'domain_lookalike=off,tls_invalid=off' -> {'DOMAIN_LOOKALIKE', 'TLS_INVALID'}.

    Only switching signals off is supported; a signal disabled in the config cannot be forced on.
    """
    disabled = set()
    for part in filter(None, (p.strip() for p in header.split(","))):
        name, _, value = part.partition("=")
        code = name.strip().upper()
        if code not in SIGNAL_CODES or value.strip().lower() != "off":
            raise ValueError(f"invalid ablation entry {part!r}")
        disabled.add(code)
    return frozenset(disabled)


@router.post("/site-scan")
async def site_scan(
    body: Annotated[dict[str, Any], Body()],
    scanner: Annotated[SiteScanner, Depends(get_site_scanner)],
    profile: Annotated[Profile, Depends(get_profile)],
    x_mandit_ablation: Annotated[str | None, Header()] = None,
    x_request_id: Annotated[str | None, Header()] = None,
) -> JSONResponse:
    # Validated by hand so failures use the shared error envelope (400), not FastAPI's 422.
    try:
        req = SiteScanRequest.model_validate(body)
    except ValidationError as exc:
        return _error(
            400, "VALIDATION_ERROR", "Request body failed validation", x_request_id,
            {"errors": exc.errors(include_url=False, include_context=False, include_input=False)},
        )  # fmt: skip

    disabled: frozenset[str] = frozenset()
    if x_mandit_ablation:
        if profile not in ABLATION_PROFILES:
            return _error(
                403, "ABLATION_NOT_PERMITTED",
                f"Detector overrides are refused in the {profile} profile", x_request_id,
            )  # fmt: skip
        try:
            disabled = parse_ablation(x_mandit_ablation)
        except ValueError as exc:
            return _error(400, "VALIDATION_ERROR", str(exc), x_request_id)

    try:
        result = await scanner.scan(req.url, req.html, disabled=disabled)
    except InvalidScanTarget as exc:
        return _error(400, "VALIDATION_ERROR", f"URL cannot be scanned: {exc}", x_request_id)
    return JSONResponse(status_code=200, content=result.to_dict())


@router.get("/domain-info")
async def domain_info(
    domain: Annotated[str, Query(min_length=1, max_length=253)],
    directory: Annotated[MerchantDirectory, Depends(get_directory)],
    reputation: Annotated[DomainReputationStore, Depends(get_reputation_store)],
    x_request_id: Annotated[str | None, Header()] = None,
) -> JSONResponse:
    """Who is behind a domain: the registered merchant (if any), registration data, reputation."""
    try:
        if any(c in domain for c in "/?#@:"):
            raise InvalidScanTarget("expected a bare host name")
        _, host = parse_target(f"https://{domain}")
    except InvalidScanTarget as exc:
        return _error(400, "VALIDATION_ERROR", f"Invalid domain: {exc}", x_request_id)
    merchant = await directory.resolve_domain(host.ascii)
    rep = await reputation.get(host.ascii)
    return JSONResponse(
        status_code=200,
        content={
            "domain": host.ascii,
            "merchant": merchant_body(merchant) if merchant else None,
            "registration": {
                "registered_on": rep.first_seen.isoformat() if rep and rep.first_seen else None,
                "registrar": rep.registrar if rep else None,
            },
            "reputation": rep.reputation if rep else "UNKNOWN",
            "source": rep.source if rep else None,
            "lookups": [
                {"provider": c.provider, "status": c.status, "detail": c.detail}
                for c in (rep.checks if rep else ())
            ],
        },
    )
