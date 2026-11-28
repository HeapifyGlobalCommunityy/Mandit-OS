"""Canonical schemas for Mandit OS Scoped Payment Token Service.

Matches migration 0004_policy_and_payments.py and docs/modules/04-policy-and-payments.md §7.
"""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class TokenStatus(StrEnum):
    """Lifecycle states of a Scoped Payment Token per migration 0004."""

    ISSUED = "ISSUED"
    REDEEMING = "REDEEMING"
    REDEEMED = "REDEEMED"
    FAILED = "FAILED"
    UNKNOWN = "UNKNOWN"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"


class PaymentRail(StrEnum):
    """Supported payment rail types per migration 0004."""

    CARD = "CARD"
    UPI = "UPI"


class TokenErrorCode(StrEnum):
    """Reason codes for token issuance, validation, redemption, and revocation rejections."""

    DECISION_NOT_FOUND = "DECISION_NOT_FOUND"
    DECISION_NOT_ALLOW = "DECISION_NOT_ALLOW"
    DECISION_EXPIRED = "DECISION_EXPIRED"
    AGENT_REVOKED = "AGENT_REVOKED"
    AGENT_INACTIVE = "AGENT_INACTIVE"
    MANDATE_INVALID = "MANDATE_INVALID"
    RESERVATION_MISMATCH = "RESERVATION_MISMATCH"
    CHECKOUT_CHANGED = "CHECKOUT_CHANGED"
    TOKEN_ALREADY_EXISTS = "TOKEN_ALREADY_EXISTS"
    TOKEN_NOT_FOUND = "TOKEN_NOT_FOUND"
    TOKEN_SIGNATURE_INVALID = "TOKEN_SIGNATURE_INVALID"
    TOKEN_FORMAT_INVALID = "TOKEN_FORMAT_INVALID"
    TOKEN_EXPIRED = "TOKEN_EXPIRED"
    TOKEN_REVOKED = "TOKEN_REVOKED"
    TOKEN_ALREADY_REDEEMED = "TOKEN_ALREADY_REDEEMED"
    TOKEN_FAILED = "TOKEN_FAILED"
    TOKEN_MERCHANT_MISMATCH = "TOKEN_MERCHANT_MISMATCH"
    TOKEN_PAYEE_MISMATCH = "TOKEN_PAYEE_MISMATCH"
    TOKEN_AMOUNT_MISMATCH = "TOKEN_AMOUNT_MISMATCH"
    TOKEN_CURRENCY_MISMATCH = "TOKEN_CURRENCY_MISMATCH"
    TOKEN_CHECKOUT_MISMATCH = "TOKEN_CHECKOUT_MISMATCH"
    IDEMPOTENCY_KEY_MISMATCH = "IDEMPOTENCY_KEY_MISMATCH"
    TOKEN_REDEMPTION_FAILED = "TOKEN_REDEMPTION_FAILED"


@dataclass(frozen=True)
class PaymentToken:
    """Canonical domain representation of a payment token matching migration 0004."""

    token_id: str
    proposal_id: str
    decision_id: str
    mandate_id: str
    reservation_id: str
    merchant_id: str
    payee_id: str
    amount_minor: int
    currency: str
    checkout_hash: str
    rail: str
    status: TokenStatus
    idem_key: str | None
    expires_at: datetime
    issued_at: datetime
    redeemed_at: datetime | None = None

    def __post_init__(self) -> None:
        if self.expires_at.tzinfo is None:
            raise ValueError("expires_at must be timezone-aware")
        if self.issued_at.tzinfo is None:
            raise ValueError("issued_at must be timezone-aware")
        if self.amount_minor <= 0:
            raise ValueError(f"amount_minor must be positive, got {self.amount_minor}")


@dataclass(frozen=True)
class IssuedToken:
    """Internal result of token issuance for the Payment Orchestrator.

    Contains both the database record and the signed JWS token.
    Never exposed to the agent (INV-09).
    """

    token_record: PaymentToken
    signed_token: str


@dataclass(frozen=True)
class TokenClaims:
    """Structured claims embedded in the EdDSA JWS payload per modules/04 §7.1."""

    jti: str
    iss: str
    aud: str
    proposal_id: str
    mandate_id: str
    decision_id: str
    merchant_id: str
    payee_id: str
    amount_minor: int
    currency: str
    checkout_hash: str
    rail: str
    max_uses: int
    iat: int
    exp: int
    nonce: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "jti": self.jti,
            "iss": self.iss,
            "aud": self.aud,
            "proposal_id": self.proposal_id,
            "mandate_id": self.mandate_id,
            "decision_id": self.decision_id,
            "merchant_id": self.merchant_id,
            "payee_id": self.payee_id,
            "amount_minor": self.amount_minor,
            "currency": self.currency,
            "checkout_hash": self.checkout_hash,
            "rail": self.rail,
            "max_uses": self.max_uses,
            "iat": self.iat,
            "exp": self.exp,
            "nonce": self.nonce,
        }


# --- Request and Response Schemas for API / Wire ---


class TokenRedeemRequest(BaseModel):
    """Request payload for POST /v1/payment-tokens/redeem per modules/04 §7.3."""

    token: str = Field(..., description="Compact JWS signed token")
    merchant_id: str = Field(..., description="Target merchant identifier")
    payee_id: str = Field(..., description="Settlement payee identifier")
    amount_minor: int = Field(..., gt=0, description="Authorized amount in minor units")
    currency: str = Field(..., min_length=3, max_length=3, description="3-letter currency code")
    checkout_hash: str = Field(..., description="Hash of the finalized checkout")
    idempotency_key: str = Field(..., description="Unique client idempotency key")


class TokenRedeemResponse(BaseModel):
    """Response payload for successful POST /v1/payment-tokens/redeem."""

    token_id: str
    result: str = "ACCEPTED"
    status: str = "REDEEMING"


class TokenValidateRequest(BaseModel):
    """Request payload for POST /v1/payment-tokens/validate."""

    token: str
    merchant_id: str
    payee_id: str
    amount_minor: int
    currency: str
    checkout_hash: str
    idempotency_key: str | None = None


class TokenValidateResponse(BaseModel):
    """Response payload for POST /v1/payment-tokens/validate."""

    token_id: str
    valid: bool
    status: str
    reason: str | None = None


class TokenRevokeRequest(BaseModel):
    """Request payload for POST /v1/payment-tokens/{token_id}/revoke."""

    reason: str = Field(..., min_length=1, description="Reason for token revocation")


class TokenRevokeResponse(BaseModel):
    """Response payload for POST /v1/payment-tokens/{token_id}/revoke."""

    token_id: str
    status: str = "REVOKED"
    reason: str


class TokenMetadataResponse(BaseModel):
    """Response payload for GET /v1/payment-tokens/{token_id}.

    Never returns the signed token JWS (INV-09).
    """

    token_id: str
    proposal_id: str
    decision_id: str
    mandate_id: str
    reservation_id: str
    merchant_id: str
    payee_id: str
    amount_minor: int
    currency: str
    rail: str
    status: str
    expires_at: datetime
    issued_at: datetime
    redeemed_at: datetime | None = None
