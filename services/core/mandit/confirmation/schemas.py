"""Schemas and contracts for Human Confirmation.

Per docs/modules/04-policy-and-payments.md §6 and REFERENCE.md §11.
"""
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Literal


class ConfirmationStatus(str, Enum):
    """Lifecycle status of a human confirmation request per migration 0004."""
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    INVALIDATED = "INVALIDATED"


@dataclass(frozen=True)
class SignatureEnvelope:
    """Canonical signature envelope per REFERENCE.md §8."""
    alg: str
    key_id: str
    signed_digest: str
    value: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "alg": self.alg,
            "key_id": self.key_id,
            "signed_digest": self.signed_digest,
            "value": self.value,
        }


@dataclass(frozen=True)
class ConfirmationRespondRequest:
    """Request payload for POST /v1/confirmations/{confirmation_id}/respond."""
    response: Literal["APPROVE", "REJECT"]
    signature: dict[str, Any] | None = None


@dataclass(frozen=True)
class ConfirmationRespondResponse:
    """Response payload for POST /v1/confirmations/{confirmation_id}/respond."""
    confirmation_id: str
    status: str
    decision_id: str | None = None
    outcome: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "confirmation_id": self.confirmation_id,
            "status": self.status,
            "decision_id": self.decision_id,
            "outcome": self.outcome,
        }


@dataclass(frozen=True)
class UserKeyRecord:
    """User key representation matching user_keys table per docs/modules/01 §4."""
    key_id: str
    user_id: str
    alg: str
    jwk: dict[str, Any]
    status: Literal["ACTIVE", "REVOKED"]
    created_at: datetime | None = None


# --- Domain Exceptions ---

class ConfirmationError(Exception):
    """Base exception for confirmation failures."""
    code: str
    status_code: int = 400

    def __init__(self, message: str, code: str = "CONFIRMATION_ERROR", status_code: int = 400):
        super().__init__(message)
        self.message = message
        self.code = code
        self.status_code = status_code


class ConfirmationNotFoundError(ConfirmationError):
    def __init__(self, message: str = "Confirmation not found"):
        super().__init__(message, code="CONFIRMATION_NOT_FOUND", status_code=404)


class ConfirmationNotPendingError(ConfirmationError):
    def __init__(self, message: str = "Confirmation is not in PENDING status"):
        super().__init__(message, code="CONFIRMATION_NOT_PENDING", status_code=409)


class ConfirmationOwnershipError(ConfirmationError):
    def __init__(self, message: str = "User does not own this confirmation"):
        super().__init__(message, code="CONFIRMATION_OWNERSHIP_MISMATCH", status_code=403)


class ConfirmationExpiredError(ConfirmationError):
    def __init__(self, message: str = "Confirmation has expired"):
        super().__init__(message, code="CONFIRMATION_EXPIRED", status_code=409)


class ConfirmationInvalidatedError(ConfirmationError):
    def __init__(self, message: str = "Confirmation has been invalidated", code: str = "CONFIRMATION_PROPOSAL_CHANGED"):
        super().__init__(message, code=code, status_code=409)


class ChallengeMismatchError(ConfirmationError):
    def __init__(self, message: str = "Signature signed_digest does not match stored challenge"):
        super().__init__(message, code="CHALLENGE_MISMATCH", status_code=400)


class SignatureInvalidError(ConfirmationError):
    def __init__(self, message: str = "Signature verification failed"):
        super().__init__(message, code="SIGNATURE_INVALID", status_code=400)


class UserKeyInvalidError(ConfirmationError):
    def __init__(self, message: str = "User signing key is invalid or revoked", code: str = "USER_KEY_INVALID"):
        super().__init__(message, code=code, status_code=403)
