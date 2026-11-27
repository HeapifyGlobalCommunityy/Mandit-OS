"""FastAPI HTTP router for Payment Orchestrator endpoints.

Per docs/modules/04-policy-and-payments.md §8 and docs/REFERENCE.md §9.4, §12.5.
Provides routes for payment execution, status lookup, and Mock PSP webhook callbacks.
"""

from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status

from mandit.payments.interface import PaymentOrchestrator
from mandit.payments.schemas import (
    PaymentExecuteRequest,
    PaymentExecuteResponse,
    PaymentStatusResponse,
)
from mandit.payments.service import PaymentError
from mandit.payments.webhook_verifier import WebhookSignatureError

router = APIRouter(prefix="/v1/payments", tags=["payments"])


def get_payment_orchestrator() -> PaymentOrchestrator:
    """Dependency provider for PaymentOrchestrator.

    Should be overridden in production application setup or test dependency_overrides.
    """
    raise NotImplementedError("PaymentOrchestrator dependency must be registered")


def get_db_session() -> Any:
    """Dependency provider for the transactional database session.

    Should be overridden in production application setup or test dependency_overrides.
    """
    raise NotImplementedError("Database session dependency must be registered")


@router.post(
    "/execute",
    status_code=status.HTTP_200_OK,
    response_model=PaymentExecuteResponse,
)
async def execute_payment(
    req: PaymentExecuteRequest,
    idempotency_key: str = Header(..., alias="Idempotency-Key"),
    orchestrator: PaymentOrchestrator = Depends(get_payment_orchestrator),
    session: Any = Depends(get_db_session),
) -> PaymentExecuteResponse:
    """Execute payment for an approved policy decision.

    Requires Idempotency-Key header. Replays identical requests safely.
    """
    if not idempotency_key or not idempotency_key.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "code": "IDEMPOTENCY_KEY_MISSING",
                "message": "Idempotency-Key header is required",
            },
        )

    try:
        return await orchestrator.execute(
            proposal_id=req.proposal_id,
            idempotency_key=idempotency_key,
            session=session,
        )
    except PaymentError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail={"code": exc.code, "message": exc.message},
        ) from exc


@router.get(
    "/{payment_id}",
    status_code=status.HTTP_200_OK,
    response_model=PaymentStatusResponse,
)
async def get_payment_status(
    payment_id: str,
    orchestrator: PaymentOrchestrator = Depends(get_payment_orchestrator),
    session: Any = Depends(get_db_session),
) -> PaymentStatusResponse:
    """Retrieve payment lifecycle status and transaction receipt by payment_id."""
    payment = await orchestrator.get(payment_id, session=session)
    if payment is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "code": "PAYMENT_NOT_FOUND",
                "message": f"Payment '{payment_id}' not found",
            },
        )
    return payment


@router.post(
    "/webhooks/mock-psp",
    status_code=status.HTTP_200_OK,
)
async def process_psp_webhook(
    request: Request,
    mock_psp_signature: str | None = Header(None, alias="Mock-PSP-Signature"),
    orchestrator: PaymentOrchestrator = Depends(get_payment_orchestrator),
    session: Any = Depends(get_db_session),
) -> dict[str, Any]:
    """Ingest and verify signed webhook callbacks from Mock PSP.

    Enforces RFC 8785 JCS Ed25519 signature verification and replay prevention.
    Confirms payment status with PSP before mutating state.
    """
    body_bytes = await request.body()
    try:
        return await orchestrator.process_webhook(
            payload=body_bytes,
            signature_header=mock_psp_signature,
            session=session,
        )
    except WebhookSignatureError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail={"code": exc.code, "message": exc.message},
        ) from exc
    except PaymentError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail={"code": exc.code, "message": exc.message},
        ) from exc
