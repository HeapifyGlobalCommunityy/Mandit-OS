"""Pydantic schemas and wire contracts for Mock PSP Service.

Follows docs/modules/04-policy-and-payments.md §9 and docs/REFERENCE.md §9.4.
"""

from datetime import datetime

from pydantic import BaseModel, Field

# --- Card Schemas ---


class CreateScopedCredentialRequest(BaseModel):
    """Request for POST /psp/v1/card/scoped-credentials."""

    mandit_token: str = Field(..., description="Compact JWS Scoped Payment Token")
    merchant_id: str = Field(..., description="Target merchant identifier")
    max_amount_minor: int = Field(..., gt=0, description="Upper bound spend cap in minor units")
    currency: str = Field(..., min_length=3, max_length=3, description="3-letter currency code")
    expires_at: datetime = Field(..., description="Credential expiry timestamp")
    idempotency_key: str | None = Field(None, description="Client idempotency key")


class CreateScopedCredentialResponse(BaseModel):
    """Response for POST /psp/v1/card/scoped-credentials."""

    credential_id: str
    status: str = "ACTIVE"
    max_amount_minor: int
    currency: str
    expires_at: datetime


class AuthorizeCardRequest(BaseModel):
    """Request for POST /psp/v1/card/authorize."""

    credential_id: str = Field(..., description="Active scoped credential identifier")
    merchant_id: str = Field(..., description="Merchant requesting authorization")
    amount_minor: int = Field(..., gt=0, description="Authorization amount")
    currency: str = Field(..., min_length=3, max_length=3, description="Currency")
    idempotency_key: str | None = Field(None, description="Idempotency key")


class AuthorizeCardResponse(BaseModel):
    """Response for POST /psp/v1/card/authorize."""

    psp_payment_id: str
    status: str  # "AUTHORIZED" | "FAILED"
    amount_minor: int
    currency: str
    decline_code: str | None = None


class CaptureCardRequest(BaseModel):
    """Request for POST /psp/v1/card/capture."""

    psp_payment_id: str = Field(..., description="Authorized payment ID to capture")
    amount_minor: int = Field(..., gt=0, description="Final capture amount")


class CaptureCardResponse(BaseModel):
    """Response for POST /psp/v1/card/capture."""

    psp_payment_id: str
    status: str = "CAPTURED"
    amount_minor: int
    currency: str


# --- UPI Schemas ---


class CreateUpiIntentRequest(BaseModel):
    """Request for POST /psp/v1/upi/intents."""

    mandit_token: str = Field(..., description="Compact JWS Scoped Payment Token")
    payee_vpa: str = Field(..., description="Payee Virtual Payment Address")
    amount_minor: int = Field(..., gt=0, description="Collect amount")
    currency: str = Field(..., min_length=3, max_length=3, description="Currency code")
    expires_at: datetime = Field(..., description="Intent expiry timestamp")
    idempotency_key: str | None = Field(None, description="Idempotency key")


class CreateUpiIntentResponse(BaseModel):
    """Response for POST /psp/v1/upi/intents."""

    intent_id: str
    psp_payment_id: str
    status: str = "PENDING"
    amount_minor: int
    currency: str
    payee_vpa: str
    expires_at: datetime


class ApproveUpiIntentRequest(BaseModel):
    """Request for POST /psp/v1/upi/intents/{id}/approve or /psp/v1/upi/approve."""

    payer_vpa: str = Field(default="demo.user@mockbank", description="Payer VPA")
    intent_id: str | None = Field(None, description="Intent ID if called via non-path alias")


class ApproveUpiIntentResponse(BaseModel):
    """Response for POST /psp/v1/upi/intents/{id}/approve."""

    intent_id: str
    psp_payment_id: str
    status: str = "SUCCESS"


class DeclineUpiIntentRequest(BaseModel):
    """Request for POST /psp/v1/upi/intents/{id}/decline or /psp/v1/upi/decline."""

    intent_id: str | None = Field(None, description="Intent ID if called via non-path alias")


class DeclineUpiIntentResponse(BaseModel):
    """Response for POST /psp/v1/upi/intents/{id}/decline."""

    intent_id: str
    psp_payment_id: str
    status: str = "FAILED"


# --- Payment Status & Public Keys ---


class PspPaymentStatusResponse(BaseModel):
    """Response for GET /psp/v1/payments/{psp_payment_id} (reconciliation source)."""

    psp_payment_id: str
    status: str
    amount_minor: int
    currency: str
    merchant_id: str


class PspPublicKeyJwk(BaseModel):
    """Ed25519 public key representation in RFC 7517 JWK format."""

    kty: str = "OKP"
    crv: str = "Ed25519"
    kid: str
    x: str


class PspJwksResponse(BaseModel):
    """Response for GET /.well-known/psp-keys.json."""

    keys: list[PspPublicKeyJwk]


# --- Fault Injection ---


class PspFaultItem(BaseModel):
    """Individual fault configuration item per docs/modules/04-policy-and-payments.md §9.3."""

    type: str = Field(
        ...,
        description=(
            "TIMEOUT_AFTER_SUCCESS, DUPLICATE_WEBHOOK, OUT_OF_ORDER_WEBHOOK, "
            "DECLINE, FORGED_CALLBACK"
        ),
    )
    probability: float | None = Field(None, ge=0.0, le=1.0)
    count: int | None = Field(None, ge=1)
    decline_code: str | None = None


class PspFaultScope(BaseModel):
    """Scope targeting fault injection."""

    merchant_id: str | None = None


class ConfigureFaultsRequest(BaseModel):
    """Request for POST /psp/v1/admin/faults."""

    scope: PspFaultScope = Field(default_factory=PspFaultScope)
    faults: list[PspFaultItem]


class ConfigureFaultsResponse(BaseModel):
    """Response for POST /psp/v1/admin/faults."""

    status: str = "CONFIGURED"
    faults_count: int
