"""Canonical schemas and wire contracts for Mandit OS Payment Orchestrator.

Follows docs/modules/04-policy-and-payments.md §8 and docs/REFERENCE.md §9.4, §12.5, §13.
"""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class PaymentRail(StrEnum):
    """Supported payment rail types matching migration 0004."""

    CARD = "CARD"
    UPI = "UPI"


class PaymentStatus(StrEnum):
    """Lifecycle states of a Core payment per REFERENCE §12.5 and modules/04 §8."""

    CREATED = "CREATED"
    AUTHORIZED = "AUTHORIZED"
    CAPTURED = "CAPTURED"
    PENDING = "PENDING"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    UNKNOWN = "UNKNOWN"
    EXPIRED = "EXPIRED"


class PaymentErrorCode(StrEnum):
    """Error and reason codes for payment execution and webhook processing."""

    DECISION_NOT_FOUND = "DECISION_NOT_FOUND"
    DECISION_NOT_ALLOW = "DECISION_NOT_ALLOW"
    DECISION_EXPIRED = "DECISION_EXPIRED"
    PROPOSAL_NOT_FOUND = "PROPOSAL_NOT_FOUND"
    PAYMENT_NOT_FOUND = "PAYMENT_NOT_FOUND"
    PAYMENT_ALREADY_EXISTS = "PAYMENT_ALREADY_EXISTS"
    OVER_TOTAL_CAP = "OVER_TOTAL_CAP"
    CHECKOUT_CHANGED = "CHECKOUT_CHANGED"
    IDEMPOTENCY_KEY_MISMATCH = "IDEMPOTENCY_KEY_MISMATCH"
    PSP_DECLINED = "PSP_DECLINED"
    PSP_TIMEOUT = "PSP_TIMEOUT"
    PSP_COMMUNICATION_ERROR = "PSP_COMMUNICATION_ERROR"
    WEBHOOK_SIGNATURE_INVALID = "WEBHOOK_SIGNATURE_INVALID"
    WEBHOOK_REPLAYED = "WEBHOOK_REPLAYED"
    INVALID_PAYMENT_STATE = "INVALID_PAYMENT_STATE"


@dataclass(frozen=True)
class PaymentReceipt:
    """Transaction evidence linkage for a successful payment per modules/04 §8.1."""

    transaction_id: str
    evidence_url: str | None = None


@dataclass(frozen=True)
class Payment:
    """Canonical domain representation of a payment matching table payments."""

    payment_id: str
    proposal_id: str
    token_id: str | None
    rail: PaymentRail
    psp_payment_id: str | None
    status: PaymentStatus
    amount_minor: int
    currency: str
    failure_code: str | None
    created_at: datetime
    updated_at: datetime

    def __post_init__(self) -> None:
        if self.created_at.tzinfo is None:
            raise ValueError("created_at must be timezone-aware")
        if self.updated_at.tzinfo is None:
            raise ValueError("updated_at must be timezone-aware")
        if self.amount_minor <= 0:
            raise ValueError(f"amount_minor must be positive, got {self.amount_minor}")
        if len(self.currency) != 3:
            raise ValueError(f"currency must be 3-letter ISO code, got {self.currency}")


class PaymentReceiptSchema(BaseModel):
    """Pydantic representation of PaymentReceipt."""

    transaction_id: str = Field(..., description="Evidence transaction identifier")
    evidence_url: str | None = Field(None, description="Direct URL to evidence bundle")


class PaymentExecuteRequest(BaseModel):
    """Request schema for POST /v1/payments/execute per modules/04 §8.1."""

    proposal_id: str = Field(..., min_length=1, description="Approved proposal identifier")


class PaymentExecuteResponse(BaseModel):
    """Response schema for POST /v1/payments/execute per modules/04 §8.1."""

    payment_id: str = Field(..., description="Unique Mandit payment identifier")
    proposal_id: str = Field(..., description="Associated proposal identifier")
    rail: PaymentRail = Field(..., description="Payment rail used")
    status: PaymentStatus = Field(..., description="Current payment lifecycle state")
    amount_minor: int = Field(..., gt=0, description="Amount in minor units")
    currency: str = Field(..., min_length=3, max_length=3, description="ISO 4217 currency")
    merchant_id: str = Field(..., description="Target merchant identifier")
    receipt: PaymentReceiptSchema | None = Field(
        None, description="Receipt details for captured/successful payments"
    )


class PaymentStatusResponse(BaseModel):
    """Response schema for GET /v1/payments/{payment_id} per REFERENCE §9.4."""

    payment_id: str = Field(..., description="Unique Mandit payment identifier")
    proposal_id: str = Field(..., description="Associated proposal identifier")
    token_id: str | None = Field(None, description="Associated payment token identifier")
    rail: PaymentRail = Field(..., description="Payment rail")
    psp_payment_id: str | None = Field(None, description="PSP payment identifier")
    status: PaymentStatus = Field(..., description="Current payment state")
    amount_minor: int = Field(..., gt=0, description="Amount in minor units")
    currency: str = Field(..., min_length=3, max_length=3, description="ISO 4217 currency")
    failure_code: str | None = Field(None, description="Reason code if payment failed")
    created_at: datetime = Field(..., description="Payment creation timestamp")
    updated_at: datetime = Field(..., description="Payment last update timestamp")
    receipt: PaymentReceiptSchema | None = Field(None, description="Receipt details if available")


class MockPspWebhookPayload(BaseModel):
    """Wire schema for incoming PSP webhooks per modules/04 §8.3."""

    psp_event_id: str = Field(..., description="Unique PSP webhook event ID for replay prevention")
    type: str = Field(..., description="Event type, e.g. payment.captured or payment.failed")
    psp_payment_id: str = Field(..., description="PSP payment reference")
    payment_ref: str | None = Field(None, description="Core payment or intent reference")
    amount_minor: int = Field(..., gt=0, description="Payment amount in minor units")
    currency: str = Field(..., min_length=3, max_length=3, description="ISO 4217 currency")
    status: str = Field(..., description="Payment state reported by PSP")
    occurred_at: str = Field(..., description="Event occurrence timestamp in ISO 8601")
