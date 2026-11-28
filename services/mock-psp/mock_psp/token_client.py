"""Token Service client for Mock PSP.

Communicates with Mandit Core Scoped Payment Token Service per REFERENCE §3.2 and §8.3.
"""

import json
from typing import Any, Protocol

import httpx

from mandit.common.crypto import b64url_decode
from mandit.tokens.schemas import (
    TokenRedeemRequest,
    TokenRedeemResponse,
)


class TokenRedemptionFailed(Exception):
    """Raised when Mandit Core Token Service rejects redemption."""

    def __init__(self, code: str, message: str, status_code: int = 409) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


class TokenServiceUnavailable(Exception):
    """Raised when Mandit Core Token Service cannot be reached."""

    pass


class TokenClient(Protocol):
    """Protocol for communicating with Mandit Core Token Service."""

    async def redeem(self, req: TokenRedeemRequest) -> TokenRedeemResponse:
        """Atomically validate and redeem token against Core."""
        ...


def extract_unverified_claims(token_str: str) -> dict[str, Any]:
    """Parse unverified claims from compact JWS to construct Core redeem request.

    Security Note: These claims are NEVER trusted for authorization.
    They are forwarded to Mandit Core where signature, bounds, and CAS are enforced.
    """
    parts = token_str.split(".")
    if len(parts) != 3:
        raise ValueError(f"Malformed JWS token: expected 3 parts, got {len(parts)}")
    claims_bytes = b64url_decode(parts[1])
    return json.loads(claims_bytes.decode("utf-8"))


class HttpTokenClient:
    """HTTP client invoking Core POST /v1/payment-tokens/redeem with Service <jwt> auth."""

    def __init__(
        self,
        base_url: str = "http://localhost:8000",
        http_client: httpx.AsyncClient | None = None,
        key_manager: Any | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._client = http_client
        self.key_manager = key_manager

    async def redeem(self, req: TokenRedeemRequest) -> TokenRedeemResponse:
        """Dispatch redemption request to Mandit Core with Service <jwt> header."""
        url = f"{self.base_url}/v1/payment-tokens/redeem"
        payload = req.model_dump()
        headers: dict[str, str] = {}

        if self.key_manager is not None and hasattr(self.key_manager, "create_service_jwt"):
            service_jwt = self.key_manager.create_service_jwt(aud="mandit-core")
            headers["Authorization"] = f"Service {service_jwt}"

        try:
            if self._client is not None:
                resp = await self._client.post(url, json=payload, headers=headers)
            else:
                async with httpx.AsyncClient(timeout=10.0) as client:
                    resp = await client.post(url, json=payload, headers=headers)
        except Exception as exc:
            raise TokenServiceUnavailable(
                f"Failed to communicate with Core Token Service at {url}: {exc}"
            ) from exc

        if resp.status_code == 200:
            data = resp.json()
            return TokenRedeemResponse(
                token_id=data.get("token_id", ""),
                result=data.get("result", "ACCEPTED"),
                status=data.get("status", "REDEEMING"),
            )

        # Extract structured error detail
        try:
            err_data = resp.json().get("detail", {})
            code = err_data.get("code", "TOKEN_REDEMPTION_FAILED")
            msg = err_data.get("message", resp.text)
        except Exception:
            code = "TOKEN_REDEMPTION_FAILED"
            msg = resp.text

        raise TokenRedemptionFailed(code=code, message=msg, status_code=resp.status_code)
