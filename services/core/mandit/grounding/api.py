"""HTTP routes of the grounding module: the merchant registry (REFERENCE section 9).

SERVICE/USER authentication is not enforced yet (no identity middleware); run on localhost only.
"""

from __future__ import annotations

import secrets
from dataclasses import asdict
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, Query
from fastapi.responses import JSONResponse

from .interface import Merchant, MerchantDirectory
from .service import build_merchant_directory

router = APIRouter(prefix="/v1/merchants", tags=["merchants"])


def get_directory() -> MerchantDirectory:
    return build_merchant_directory()


def merchant_body(m: Merchant) -> dict[str, Any]:
    body = asdict(m)
    body["payees"] = {
        "card_acquirer_id": body.pop("card_acquirer_id"),
        "upi_vpas": list(body.pop("upi_vpas")),
    }
    body["domains"] = list(m.domains)
    body["categories"] = list(m.categories)
    body["onboarded_at"] = m.onboarded_at.isoformat()
    return body


def _respond(merchant: Merchant | None, request_id: str | None) -> JSONResponse:
    if merchant is not None:
        return JSONResponse(status_code=200, content=merchant_body(merchant))
    return JSONResponse(
        status_code=404,
        content={
            "error": {
                "code": "MERCHANT_NOT_IN_REGISTRY",
                "message": "No registered merchant matches",
                "request_id": request_id or "req_" + secrets.token_hex(13).upper(),
                "details": {},
            }
        },
    )


@router.get("")
async def resolve_merchant(
    domain: Annotated[str, Query(min_length=1, max_length=253)],
    directory: Annotated[MerchantDirectory, Depends(get_directory)],
    x_request_id: Annotated[str | None, Header()] = None,
) -> JSONResponse:
    return _respond(await directory.resolve_domain(domain), x_request_id)


@router.get("/{merchant_id}")
async def get_merchant(
    merchant_id: str,
    directory: Annotated[MerchantDirectory, Depends(get_directory)],
    x_request_id: Annotated[str | None, Header()] = None,
) -> JSONResponse:
    return _respond(await directory.get_merchant(merchant_id), x_request_id)
