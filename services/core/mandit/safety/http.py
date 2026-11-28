"""HTTP helpers shared by the safety routes (Starlette-level, so they are testable without FastAPI).

``read_json_body`` enforces a byte limit **while streaming**. Declaring the body as a FastAPI
``dict`` parameter would buffer and JSON-parse the whole request before any length check, so a
single large request could exhaust memory. Requests above the limit get 413 without being parsed.
"""

from __future__ import annotations

import json
import secrets
from typing import Any

from starlette.requests import Request
from starlette.responses import JSONResponse

# 5 MB of page HTML, JSON-escaped (up to ~2x) plus the envelope.
MAX_BODY_BYTES = 12 * 1024 * 1024


class BodyError(Exception):
    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


async def read_json_body(request: Request, max_bytes: int = MAX_BODY_BYTES) -> dict[str, Any]:
    declared = request.headers.get("content-length")
    if declared is not None:
        try:
            if int(declared) > max_bytes:
                raise BodyError(413, "PAYLOAD_TOO_LARGE", f"Body exceeds {max_bytes} bytes")
        except ValueError as exc:
            raise BodyError(400, "VALIDATION_ERROR", "Invalid Content-Length") from exc
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > max_bytes:
            raise BodyError(413, "PAYLOAD_TOO_LARGE", f"Body exceeds {max_bytes} bytes")
        chunks.append(chunk)
    try:
        body = json.loads(b"".join(chunks))
    except (
        ValueError,
        UnicodeDecodeError,
        RecursionError,
    ) as exc:  # deep nesting -> RecursionError
        raise BodyError(400, "VALIDATION_ERROR", "Body is not valid JSON") from exc
    if not isinstance(body, dict):
        raise BodyError(400, "VALIDATION_ERROR", "Body must be a JSON object")
    return body


def error_response(
    status: int,
    code: str,
    message: str,
    request_id: str | None,
    details: dict[str, Any] | None = None,
) -> JSONResponse:
    """Error envelope (REFERENCE.md section 7.6). Swap for mandit.common's helper once it exists."""
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
