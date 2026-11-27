"""PSP client adapters for communication with Mock PSP.

Implements HttpPspClient and InProcessPspClient adhering strictly to the PspClient protocol.
Per docs/modules/04-policy-and-payments.md §9 and docs/REFERENCE.md §9.4.
"""

from datetime import datetime
from typing import Any, NoReturn

import httpx
from pydantic import BaseModel, Field

from mandit.payments.interface import PspClient


class PspClientError(Exception):
    """Base exception for PSP client errors."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class PspConnectionError(PspClientError):
    """Raised when connection to PSP fails or is unreachable."""

    pass


class PspTimeoutError(PspClientError):
    """Raised when request to PSP times out (read or connect).

    Must not be retried automatically for state-mutating requests (modules/04 §8.1).
    """

    pass


class PspResponseError(PspClientError):
    """Raised when PSP returns a non-success HTTP status code (4xx, 5xx)."""

    def __init__(
        self,
        message: str,
        status_code: int = 400,
        error_code: str = "PSP_ERROR",
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.error_code = error_code


class PspPayloadError(PspClientError):
    """Raised when PSP response is malformed, not valid JSON, or schema-invalid."""

    pass


# --- PSP Wire Schemas ---


class PspCreateScopedCredentialRequest(BaseModel):
    """Request payload for POST /psp/v1/card/scoped-credentials."""

    mandit_token: str = Field(..., description="Single-use compact JWS payment token")
    merchant_id: str = Field(..., description="Target merchant identifier")
    max_amount_minor: int = Field(..., gt=0, description="Spend cap in minor units")
    currency: str = Field(..., min_length=3, max_length=3, description="3-letter currency")
    expires_at: datetime = Field(..., description="Expiry timestamp")
    idempotency_key: str | None = Field(None, description="Idempotency key")


class PspCreateScopedCredentialResponse(BaseModel):
    """Response payload for POST /psp/v1/card/scoped-credentials."""

    credential_id: str
    status: str = "ACTIVE"
    max_amount_minor: int
    currency: str
    expires_at: datetime


class PspAuthorizeCardRequest(BaseModel):
    """Request payload for POST /psp/v1/card/authorize."""

    credential_id: str = Field(..., description="Scoped credential ID")
    merchant_id: str = Field(..., description="Merchant requesting authorization")
    amount_minor: int = Field(..., gt=0, description="Authorization amount")
    currency: str = Field(..., min_length=3, max_length=3, description="Currency")
    idempotency_key: str | None = Field(None, description="Idempotency key")


class PspAuthorizeCardResponse(BaseModel):
    """Response payload for POST /psp/v1/card/authorize."""

    psp_payment_id: str
    status: str  # "AUTHORIZED" | "FAILED"
    amount_minor: int
    currency: str
    decline_code: str | None = None


class PspCaptureCardRequest(BaseModel):
    """Request payload for POST /psp/v1/card/capture."""

    psp_payment_id: str = Field(..., description="Authorized payment ID to capture")
    amount_minor: int = Field(..., gt=0, description="Capture amount")


class PspCaptureCardResponse(BaseModel):
    """Response payload for POST /psp/v1/card/capture."""

    psp_payment_id: str
    status: str = "CAPTURED"
    amount_minor: int
    currency: str


class PspCreateUpiIntentRequest(BaseModel):
    """Request payload for POST /psp/v1/upi/intents."""

    mandit_token: str = Field(..., description="Single-use compact JWS payment token")
    payee_vpa: str = Field(..., description="Payee VPA")
    amount_minor: int = Field(..., gt=0, description="Collect amount")
    currency: str = Field(..., min_length=3, max_length=3, description="Currency")
    expires_at: datetime = Field(..., description="Intent expiry timestamp")
    idempotency_key: str | None = Field(None, description="Idempotency key")


class PspCreateUpiIntentResponse(BaseModel):
    """Response payload for POST /psp/v1/upi/intents."""

    intent_id: str
    psp_payment_id: str
    status: str = "PENDING"
    amount_minor: int
    currency: str
    payee_vpa: str
    expires_at: datetime


class PspPaymentStatusResponse(BaseModel):
    """Response payload for GET /psp/v1/payments/{psp_payment_id}."""

    psp_payment_id: str
    status: str
    amount_minor: int
    currency: str
    merchant_id: str


class PspPublicKeyJwk(BaseModel):
    """Ed25519 public key JWK representation."""

    kty: str = "OKP"
    crv: str = "Ed25519"
    kid: str
    x: str


class PspJwksResponse(BaseModel):
    """Response payload for GET /.well-known/psp-keys.json."""

    keys: list[PspPublicKeyJwk]


# --- Helper: Convert Request to Dict ---


def _serialize_request(req: Any) -> dict[str, Any]:
    if isinstance(req, BaseModel):
        data = req.model_dump(mode="json")
        return data
    if isinstance(req, dict):
        return {k: (v.isoformat() if isinstance(v, datetime) else v) for k, v in req.items()}
    raise PspPayloadError(f"Unsupported request type: {type(req)}")


# --- HTTP PSP Client Implementation ---


class HttpPspClient(PspClient):
    """Production HTTP client for standalone Mock PSP service."""

    def __init__(
        self,
        base_url: str = "http://mock-psp:8200",
        timeout: float = 10.0,
        connect_timeout: float = 5.0,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = httpx.Timeout(timeout, connect=connect_timeout)
        self._client = http_client

    async def _request(
        self,
        method: str,
        path: str,
        json_data: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        url = f"{self.base_url}{path}"
        req_headers = {"Content-Type": "application/json", **(headers or {})}

        try:
            if self._client is not None:
                resp = await self._client.request(
                    method, url, json=json_data, headers=req_headers, timeout=self.timeout
                )
            else:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    resp = await client.request(method, url, json=json_data, headers=req_headers)
        except httpx.TimeoutException as exc:
            raise PspTimeoutError(f"PSP request to {path} timed out: {exc}") from exc
        except httpx.RequestError as exc:
            raise PspConnectionError(f"PSP connection to {path} failed: {exc}") from exc

        if resp.status_code not in (200, 201):
            error_code = "PSP_ERROR"
            message = resp.text
            try:
                data = resp.json()
                if isinstance(data, dict):
                    detail = data.get("detail")
                    if isinstance(detail, dict):
                        error_code = detail.get("code", error_code)
                        message = detail.get("message", message)
                    elif isinstance(detail, str):
                        message = detail
                    error_code = data.get("code", error_code)
                    message = data.get("message", message)
            except Exception:
                pass
            raise PspResponseError(
                f"PSP responded with status {resp.status_code}: {message}",
                status_code=resp.status_code,
                error_code=str(error_code),
            )

        try:
            return resp.json()
        except Exception as exc:
            raise PspPayloadError(f"Invalid JSON response from PSP: {exc}") from exc

    async def create_scoped_credential(self, req: Any) -> PspCreateScopedCredentialResponse:
        data = _serialize_request(req)
        raw = await self._request("POST", "/psp/v1/card/scoped-credentials", json_data=data)
        return PspCreateScopedCredentialResponse.model_validate(raw)

    async def authorize_card(self, req: Any) -> PspAuthorizeCardResponse:
        data = _serialize_request(req)
        raw = await self._request("POST", "/psp/v1/card/authorize", json_data=data)
        return PspAuthorizeCardResponse.model_validate(raw)

    async def capture_card(self, req: Any) -> PspCaptureCardResponse:
        data = _serialize_request(req)
        raw = await self._request("POST", "/psp/v1/card/capture", json_data=data)
        return PspCaptureCardResponse.model_validate(raw)

    async def create_upi_intent(self, req: Any) -> PspCreateUpiIntentResponse:
        data = _serialize_request(req)
        raw = await self._request("POST", "/psp/v1/upi/intents", json_data=data)
        return PspCreateUpiIntentResponse.model_validate(raw)

    async def get_payment_status(self, psp_payment_id: str) -> PspPaymentStatusResponse:
        raw = await self._request("GET", f"/psp/v1/payments/{psp_payment_id}")
        return PspPaymentStatusResponse.model_validate(raw)

    async def get_public_jwks(self) -> PspJwksResponse:
        raw = await self._request("GET", "/.well-known/psp-keys.json")
        return PspJwksResponse.model_validate(raw)


# --- In-Process PSP Client Implementation (For Unit/Integration Tests) ---


class InProcessPspClient(PspClient):
    """Deterministic in-process adapter wrapping MockPspService for test isolation."""

    def __init__(
        self,
        psp_service: Any,
        session_factory: Any = None,
    ) -> None:
        self.psp_service = psp_service
        self.session_factory = session_factory

    def _get_session(self) -> Any:
        if callable(self.session_factory):
            return self.session_factory()
        return self.session_factory

    async def create_scoped_credential(self, req: Any) -> PspCreateScopedCredentialResponse:
        session = self._get_session()
        try:
            # Convert to schema model if passed dict
            if isinstance(req, dict):
                req = PspCreateScopedCredentialRequest.model_validate(req)
            raw = await self.psp_service.create_scoped_credential(req, session)
            return PspCreateScopedCredentialResponse.model_validate(
                raw.model_dump() if hasattr(raw, "model_dump") else raw
            )
        except Exception as exc:
            self._handle_service_error(exc)

    async def authorize_card(self, req: Any) -> PspAuthorizeCardResponse:
        session = self._get_session()
        try:
            if isinstance(req, dict):
                req = PspAuthorizeCardRequest.model_validate(req)
            raw = await self.psp_service.authorize_card(req, session)
            return PspAuthorizeCardResponse.model_validate(
                raw.model_dump() if hasattr(raw, "model_dump") else raw
            )
        except Exception as exc:
            self._handle_service_error(exc)

    async def capture_card(self, req: Any) -> PspCaptureCardResponse:
        session = self._get_session()
        try:
            if isinstance(req, dict):
                req = PspCaptureCardRequest.model_validate(req)
            raw = await self.psp_service.capture_card(req, session)
            return PspCaptureCardResponse.model_validate(
                raw.model_dump() if hasattr(raw, "model_dump") else raw
            )
        except Exception as exc:
            self._handle_service_error(exc)

    async def create_upi_intent(self, req: Any) -> PspCreateUpiIntentResponse:
        session = self._get_session()
        try:
            if isinstance(req, dict):
                req = PspCreateUpiIntentRequest.model_validate(req)
            raw = await self.psp_service.create_upi_intent(req, session)
            return PspCreateUpiIntentResponse.model_validate(
                raw.model_dump() if hasattr(raw, "model_dump") else raw
            )
        except Exception as exc:
            self._handle_service_error(exc)

    async def get_payment_status(self, psp_payment_id: str) -> PspPaymentStatusResponse:
        session = self._get_session()
        try:
            raw = await self.psp_service.get_payment_status(psp_payment_id, session)
            return PspPaymentStatusResponse.model_validate(
                raw.model_dump() if hasattr(raw, "model_dump") else raw
            )
        except Exception as exc:
            self._handle_service_error(exc)

    async def get_public_jwks(self) -> PspJwksResponse:
        try:
            raw = self.psp_service.get_jwks()
            return PspJwksResponse.model_validate(
                raw.model_dump() if hasattr(raw, "model_dump") else raw
            )
        except Exception as exc:
            self._handle_service_error(exc)

    def _handle_service_error(self, exc: Exception) -> NoReturn:
        status_code = getattr(exc, "status_code", 400)
        code = getattr(exc, "code", "PSP_ERROR")
        message = getattr(exc, "message", str(exc))
        raise PspResponseError(
            f"Mock PSP service error: {message}",
            status_code=status_code,
            error_code=code,
        ) from exc
