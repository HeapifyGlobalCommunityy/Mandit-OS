"""HTTP routes of the safety module (modules/02 sections 6-8).

Every route is SERVICE-authenticated in the spec (REFERENCE section 9.2). Service authentication is
not implemented in the repository yet (Team 1); until it is, ``service.py`` refuses the cloud
profile, so these routes are never served outside local/test/demo.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Header, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from mandit.grounding.api import get_directory, merchant_body
from mandit.grounding.interface import MerchantDirectory

from .content import MAX_RAW_BYTES, SafetyServiceImpl
from .http import BodyError, error_response, read_json_body
from .injection import DETECTORS, InjectionFirewall, UnsupportedContent
from .interface import ContentNotFound, InspectRequest
from .service import (
    ABLATION_PROFILES,
    build_firewall,
    build_reputation_store,
    build_safety_service,
    build_site_scanner,
    current_profile,
)
from .site_scan import DomainReputationStore, InvalidScanTarget, SiteScanner
from .site_scan.config import SIGNAL_CODES
from .site_scan.domains import parse_target
from .site_scan.scanner import Profile

router = APIRouter(prefix="/v1/safety", tags=["safety"])
content_router = APIRouter(prefix="/v1/content", tags=["safety"])

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


def get_firewall() -> InjectionFirewall:
    return build_firewall()


def get_safety_service(profile: Annotated[Profile, Depends(get_profile)]) -> SafetyServiceImpl:
    return build_safety_service(profile)


_error = error_response


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


def parse_detector_ablation(header: str) -> tuple[frozenset[str], frozenset[str]]:
    """Split an ablation header into (site signal codes, injection detector names).

    Accepts both vocabularies: 'hidden_text=off' (section 8) and 'domain_new=off' (section 6.2).
    """
    site, detectors = set(), set()
    for part in filter(None, (p.strip() for p in header.split(","))):
        name, _, value = part.partition("=")
        key = name.strip().lower()
        if value.strip().lower() != "off":
            raise ValueError(f"invalid ablation entry {part!r}")
        if key in DETECTORS:
            detectors.add(key)
        elif key.upper() in SIGNAL_CODES:
            site.add(key.upper())
        else:
            raise ValueError(f"invalid ablation entry {part!r}")
    return frozenset(site), frozenset(detectors)


def _validation_error(exc: ValidationError, request_id: str | None) -> JSONResponse:
    return _error(
        400, "VALIDATION_ERROR", "Request body failed validation", request_id,
        {"errors": exc.errors(include_url=False, include_context=False, include_input=False)},
    )  # fmt: skip


async def _body(request: Request, request_id: str | None) -> dict[str, Any] | JSONResponse:
    try:
        return await read_json_body(request)
    except BodyError as exc:
        return _error(exc.status, exc.code, exc.message, request_id)


def _ablation(
    header: str | None, profile: Profile, request_id: str | None
) -> tuple[frozenset[str], frozenset[str]] | JSONResponse:
    if not header:
        return frozenset(), frozenset()
    if profile not in ABLATION_PROFILES:
        return _error(
            403, "ABLATION_NOT_PERMITTED",
            f"Detector overrides are refused in the {profile} profile", request_id,
        )  # fmt: skip
    try:
        return parse_detector_ablation(header)
    except ValueError as exc:
        return _error(400, "VALIDATION_ERROR", str(exc), request_id)


class InjectionScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    content_id: Annotated[str | None, Field(pattern=r"^cnt_[0-9A-Za-z_]{1,64}$")] = None
    html: Annotated[str, Field(min_length=0, max_length=MAX_HTML_CHARS)]
    mime_type: Annotated[str, Field(min_length=1, max_length=100)] = "text/html"


class InspectBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    transaction_id: Annotated[str, Field(pattern=r"^txn_[0-9A-Za-z_]{1,64}$")]
    tool_call_id: Annotated[str | None, Field(pattern=r"^tc_[0-9A-Za-z_]{1,64}$")] = None
    source_type: Literal["MERCHANT_API", "WEB_PAGE", "SEARCH_RESULT", "TOOL_RESPONSE"]
    url: Annotated[str, Field(min_length=1, max_length=2048)]
    raw: Annotated[str, Field(max_length=MAX_HTML_CHARS * 2)]
    # Additive to section 7.3: the spec says "<base64 or text>" without saying how to tell them
    # apart. Default "text" keeps the documented example working.
    raw_encoding: Literal["text", "base64"] = "text"
    mime_type: Annotated[str, Field(min_length=1, max_length=100)]


@router.post("/site-scan")
async def site_scan(
    request: Request,
    scanner: Annotated[SiteScanner, Depends(get_site_scanner)],
    profile: Annotated[Profile, Depends(get_profile)],
    x_mandit_ablation: Annotated[str | None, Header()] = None,
    x_request_id: Annotated[str | None, Header()] = None,
) -> JSONResponse:
    body = await _body(request, x_request_id)
    if isinstance(body, JSONResponse):
        return body
    try:
        req = SiteScanRequest.model_validate(body)
    except ValidationError as exc:
        return _validation_error(exc, x_request_id)

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


@router.post("/injection-scan")
async def injection_scan(
    request: Request,
    firewall: Annotated[InjectionFirewall, Depends(get_firewall)],
    profile: Annotated[Profile, Depends(get_profile)],
    x_mandit_ablation: Annotated[str | None, Header()] = None,
    x_request_id: Annotated[str | None, Header()] = None,
) -> JSONResponse:
    body = await _body(request, x_request_id)
    if isinstance(body, JSONResponse):
        return body
    try:
        req = InjectionScanRequest.model_validate(body)
    except ValidationError as exc:
        return _validation_error(exc, x_request_id)
    ablation = _ablation(x_mandit_ablation, profile, x_request_id)
    if isinstance(ablation, JSONResponse):
        return ablation
    try:
        # CPU-bound on hostile input: run it off the event loop.
        report = await asyncio.to_thread(
            firewall.scan, req.html, req.mime_type, disabled=ablation[1]
        )
    except UnsupportedContent as exc:
        return _error(415, "UNSUPPORTED_MEDIA_TYPE", str(exc), x_request_id)
    out = report.to_dict()
    out["content_id"] = req.content_id
    return JSONResponse(status_code=200, content=out)


@router.get("/risk")
async def risk(
    service: Annotated[SafetyServiceImpl, Depends(get_safety_service)],
    content_ids: Annotated[str, Query(max_length=4096)] = "",
    merchant_domain: Annotated[str, Query(min_length=1, max_length=253)] = "",
    x_request_id: Annotated[str | None, Header()] = None,
) -> JSONResponse:
    ids = [c.strip() for c in content_ids.split(",") if c.strip()]
    if not merchant_domain or len(ids) > 100 or any(not c.startswith("cnt_") for c in ids):
        return _error(400, "VALIDATION_ERROR", "Invalid content_ids or merchant_domain",
                      x_request_id)  # fmt: skip
    try:
        summary = await service.get_risk(ids, merchant_domain)
    except ContentNotFound:
        return _error(404, "CONTENT_NOT_FOUND", "Unknown content_id", x_request_id)
    except ValueError as exc:
        return _error(400, "VALIDATION_ERROR", str(exc), x_request_id)
    return JSONResponse(status_code=200, content=summary.to_dict())


@content_router.post("/inspect")
async def inspect(
    request: Request,
    service: Annotated[SafetyServiceImpl, Depends(get_safety_service)],
    profile: Annotated[Profile, Depends(get_profile)],
    x_mandit_ablation: Annotated[str | None, Header()] = None,
    x_request_id: Annotated[str | None, Header()] = None,
) -> JSONResponse:
    body = await _body(request, x_request_id)
    if isinstance(body, JSONResponse):
        return body
    try:
        req = InspectBody.model_validate(body)
    except ValidationError as exc:
        return _validation_error(exc, x_request_id)
    ablation = _ablation(x_mandit_ablation, profile, x_request_id)
    if isinstance(ablation, JSONResponse):
        return ablation
    try:
        raw = (
            base64.b64decode(req.raw, validate=True)
            if req.raw_encoding == "base64"
            else req.raw.encode("utf-8")
        )
    except (binascii.Error, ValueError):
        return _error(400, "VALIDATION_ERROR", "raw is not valid base64", x_request_id)
    if len(raw) > MAX_RAW_BYTES:
        return _error(413, "PAYLOAD_TOO_LARGE", f"raw exceeds {MAX_RAW_BYTES} bytes", x_request_id)
    try:
        report = await service.inspect(
            InspectRequest(
                transaction_id=req.transaction_id,
                source_type=req.source_type,
                url=req.url,
                raw=raw,
                mime_type=req.mime_type,
                tool_call_id=req.tool_call_id,
            ),
            disabled_site=ablation[0],
            disabled_detectors=ablation[1],
        )
    except InvalidScanTarget as exc:
        return _error(400, "VALIDATION_ERROR", f"URL cannot be scanned: {exc}", x_request_id)
    except UnsupportedContent as exc:
        return _error(415, "UNSUPPORTED_MEDIA_TYPE", str(exc), x_request_id)
    return JSONResponse(status_code=200, content=report.to_dict())


@content_router.get("/{content_id}")
async def get_content(
    content_id: str,
    service: Annotated[SafetyServiceImpl, Depends(get_safety_service)],
    x_request_id: Annotated[str | None, Header()] = None,
) -> JSONResponse:
    if not content_id.startswith("cnt_") or len(content_id) > 70:
        return _error(400, "VALIDATION_ERROR", "Invalid content_id", x_request_id)
    try:
        record = await service.get_content(content_id)
    except ContentNotFound:
        return _error(404, "CONTENT_NOT_FOUND", "Unknown content_id", x_request_id)
    return JSONResponse(
        status_code=200,
        content={
            **record.provenance(),
            "classification": record.classification,
            "domain": record.domain,
            "source_type": record.source_type,
            "transaction_id": record.transaction_id,
            "fetched_at": record.fetched_at.isoformat().replace("+00:00", "Z"),
            "scan_id": record.scan_id,
        },
    )
