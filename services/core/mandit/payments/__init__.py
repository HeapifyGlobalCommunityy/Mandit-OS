"""Mandit OS Payment Orchestrator module.

Per docs/modules/04-policy-and-payments.md §8 and docs/REFERENCE.md §9.4, §12.5.
"""

from mandit.payments.interface import (
    DecisionProvider,
    GroundingClient,
    MandateClient,
    PaymentOrchestrator,
    PspClient,
)
from mandit.payments.models import (
    IdempotencyKeyModel,
    PaymentModel,
    PspWebhookEventModel,
)
from mandit.payments.psp_client import (
    HttpPspClient,
    InProcessPspClient,
    PspAuthorizeCardRequest,
    PspAuthorizeCardResponse,
    PspCaptureCardRequest,
    PspCaptureCardResponse,
    PspClientError,
    PspConnectionError,
    PspCreateScopedCredentialRequest,
    PspCreateScopedCredentialResponse,
    PspCreateUpiIntentRequest,
    PspCreateUpiIntentResponse,
    PspJwksResponse,
    PspPayloadError,
    PspResponseError,
    PspTimeoutError,
)
from mandit.payments.psp_client import (
    PspPaymentStatusResponse as PspClientPaymentStatusResponse,
)
from mandit.payments.schemas import (
    MockPspWebhookPayload,
    Payment,
    PaymentErrorCode,
    PaymentExecuteRequest,
    PaymentExecuteResponse,
    PaymentRail,
    PaymentReceipt,
    PaymentReceiptSchema,
    PaymentStatus,
    PaymentStatusResponse,
)
from mandit.payments.service import (
    CheckoutChangedError,
    DecisionExpiredError,
    DecisionNotAllowError,
    DecisionNotFoundError,
    IdempotencyConflictError,
    MandateInvalidError,
    PaymentAlreadyExistsError,
    PaymentError,
    PaymentNotFoundError,
    PaymentOrchestratorImpl,
    ProposalNotFoundError,
    SpendReservationError,
)
from mandit.payments.webhook_verifier import (
    PspWebhookVerifier,
    WebhookSignatureError,
    get_webhook_verifier,
    set_webhook_verifier,
)

__all__ = [
    # Models
    "PaymentModel",
    "PspWebhookEventModel",
    "IdempotencyKeyModel",
    # Schemas
    "Payment",
    "PaymentRail",
    "PaymentStatus",
    "PaymentErrorCode",
    "PaymentReceipt",
    "PaymentReceiptSchema",
    "PaymentExecuteRequest",
    "PaymentExecuteResponse",
    "PaymentStatusResponse",
    "MockPspWebhookPayload",
    # Interfaces & Service
    "PaymentOrchestrator",
    "PaymentOrchestratorImpl",
    "PaymentError",
    "DecisionNotFoundError",
    "DecisionNotAllowError",
    "DecisionExpiredError",
    "ProposalNotFoundError",
    "PaymentNotFoundError",
    "PaymentAlreadyExistsError",
    "IdempotencyConflictError",
    "CheckoutChangedError",
    "SpendReservationError",
    "MandateInvalidError",
    "MandateClient",
    "GroundingClient",
    "DecisionProvider",
    "PspClient",
    # PSP Clients & Errors
    "HttpPspClient",
    "InProcessPspClient",
    "PspClientError",
    "PspConnectionError",
    "PspTimeoutError",
    "PspResponseError",
    "PspPayloadError",
    "PspCreateScopedCredentialRequest",
    "PspCreateScopedCredentialResponse",
    "PspAuthorizeCardRequest",
    "PspAuthorizeCardResponse",
    "PspCaptureCardRequest",
    "PspCaptureCardResponse",
    "PspCreateUpiIntentRequest",
    "PspCreateUpiIntentResponse",
    "PspClientPaymentStatusResponse",
    "PspJwksResponse",
    # Webhook Verifier
    "PspWebhookVerifier",
    "WebhookSignatureError",
    "get_webhook_verifier",
    "set_webhook_verifier",
]
