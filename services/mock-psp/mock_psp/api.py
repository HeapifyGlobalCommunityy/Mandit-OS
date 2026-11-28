"""FastAPI HTTP router for Mock PSP endpoints.

Follows docs/modules/04-policy-and-payments.md §9 and docs/REFERENCE.md §9.4.
"""

from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, status

from mock_psp.config import SETTINGS
from mock_psp.schemas import (
    ApproveUpiIntentRequest,
    ApproveUpiIntentResponse,
    AuthorizeCardRequest,
    AuthorizeCardResponse,
    CaptureCardRequest,
    CaptureCardResponse,
    ConfigureFaultsRequest,
    ConfigureFaultsResponse,
    CreateScopedCredentialRequest,
    CreateScopedCredentialResponse,
    CreateUpiIntentRequest,
    CreateUpiIntentResponse,
    DeclineUpiIntentRequest,
    DeclineUpiIntentResponse,
    PspJwksResponse,
    PspPaymentStatusResponse,
)
from mock_psp.service import MockPspService, PspServiceError

router = APIRouter()


def get_psp_service() -> MockPspService:
    """Dependency provider for MockPspService."""
    raise NotImplementedError("MockPspService dependency must be registered")


def get_psp_db_session() -> Any:
    """Dependency provider for Mock PSP database session."""
    raise NotImplementedError("Mock PSP DB session dependency must be registered")


async def verify_admin_key(
    x_admin_key: str | None = Header(None, alias="X-Admin-Key"),
) -> None:
    """Enforce authentication on administrative endpoints."""
    if not SETTINGS.allows_fault_injection:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "FORBIDDEN", "message": "Admin faults disabled in this profile"},
        )
    if not x_admin_key or x_admin_key != SETTINGS.admin_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "UNAUTHORIZED", "message": "Invalid or missing X-Admin-Key"},
        )


# --- Card Endpoints ---


@router.post(
    "/psp/v1/card/scoped-credentials",
    status_code=status.HTTP_201_CREATED,
    response_model=CreateScopedCredentialResponse,
)
async def create_scoped_credential(
    req: CreateScopedCredentialRequest,
    psp_service: MockPspService = Depends(get_psp_service),
    session: Any = Depends(get_psp_db_session),
) -> CreateScopedCredentialResponse:
    try:
        return await psp_service.create_scoped_credential(req, session)
    except PspServiceError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail={"code": exc.code, "message": exc.message},
        ) from exc


@router.post(
    "/psp/v1/card/authorize",
    status_code=status.HTTP_200_OK,
    response_model=AuthorizeCardResponse,
)
async def authorize_card(
    req: AuthorizeCardRequest,
    psp_service: MockPspService = Depends(get_psp_service),
    session: Any = Depends(get_psp_db_session),
) -> AuthorizeCardResponse:
    try:
        return await psp_service.authorize_card(req, session)
    except PspServiceError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail={"code": exc.code, "message": exc.message},
        ) from exc


@router.post(
    "/psp/v1/card/capture",
    status_code=status.HTTP_200_OK,
    response_model=CaptureCardResponse,
)
async def capture_card(
    req: CaptureCardRequest,
    psp_service: MockPspService = Depends(get_psp_service),
    session: Any = Depends(get_psp_db_session),
) -> CaptureCardResponse:
    try:
        return await psp_service.capture_card(req, session)
    except PspServiceError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail={"code": exc.code, "message": exc.message},
        ) from exc


# --- UPI Endpoints ---


@router.post(
    "/psp/v1/upi/intents",
    status_code=status.HTTP_201_CREATED,
    response_model=CreateUpiIntentResponse,
)
async def create_upi_intent(
    req: CreateUpiIntentRequest,
    psp_service: MockPspService = Depends(get_psp_service),
    session: Any = Depends(get_psp_db_session),
) -> CreateUpiIntentResponse:
    try:
        return await psp_service.create_upi_intent(req, session)
    except PspServiceError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail={"code": exc.code, "message": exc.message},
        ) from exc


@router.post(
    "/psp/v1/upi/intents/{intent_id}/approve",
    status_code=status.HTTP_200_OK,
    response_model=ApproveUpiIntentResponse,
)
async def approve_upi_intent_by_id(
    intent_id: str,
    req: ApproveUpiIntentRequest,
    psp_service: MockPspService = Depends(get_psp_service),
    session: Any = Depends(get_psp_db_session),
) -> ApproveUpiIntentResponse:
    try:
        return await psp_service.approve_upi_intent(intent_id, req.payer_vpa, session)
    except PspServiceError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail={"code": exc.code, "message": exc.message},
        ) from exc


@router.post(
    "/psp/v1/upi/approve",
    status_code=status.HTTP_200_OK,
    response_model=ApproveUpiIntentResponse,
)
async def approve_upi_intent_alias(
    req: ApproveUpiIntentRequest,
    psp_service: MockPspService = Depends(get_psp_service),
    session: Any = Depends(get_psp_db_session),
) -> ApproveUpiIntentResponse:
    if not req.intent_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "MISSING_INTENT_ID", "message": "intent_id is required"},
        )
    try:
        return await psp_service.approve_upi_intent(req.intent_id, req.payer_vpa, session)
    except PspServiceError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail={"code": exc.code, "message": exc.message},
        ) from exc


@router.post(
    "/psp/v1/upi/intents/{intent_id}/decline",
    status_code=status.HTTP_200_OK,
    response_model=DeclineUpiIntentResponse,
)
async def decline_upi_intent_by_id(
    intent_id: str,
    psp_service: MockPspService = Depends(get_psp_service),
    session: Any = Depends(get_psp_db_session),
) -> DeclineUpiIntentResponse:
    try:
        return await psp_service.decline_upi_intent(intent_id, session)
    except PspServiceError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail={"code": exc.code, "message": exc.message},
        ) from exc


@router.post(
    "/psp/v1/upi/decline",
    status_code=status.HTTP_200_OK,
    response_model=DeclineUpiIntentResponse,
)
async def decline_upi_intent_alias(
    req: DeclineUpiIntentRequest,
    psp_service: MockPspService = Depends(get_psp_service),
    session: Any = Depends(get_psp_db_session),
) -> DeclineUpiIntentResponse:
    if not req.intent_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "MISSING_INTENT_ID", "message": "intent_id is required"},
        )
    try:
        return await psp_service.decline_upi_intent(req.intent_id, session)
    except PspServiceError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail={"code": exc.code, "message": exc.message},
        ) from exc


# --- Status Endpoint ---


@router.get(
    "/psp/v1/payments",
    status_code=status.HTTP_200_OK,
    response_model=PspPaymentStatusResponse,
)
async def find_payment_by_idempotency_key(
    idempotency_key: str,
    psp_service: MockPspService = Depends(get_psp_service),
    session: Any = Depends(get_psp_db_session),
) -> PspPaymentStatusResponse:
    try:
        return await psp_service.find_payment_by_idempotency_key(idempotency_key, session)
    except PspServiceError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail={"code": exc.code, "message": exc.message},
        ) from exc


@router.get(
    "/psp/v1/payments/{psp_payment_id}",
    status_code=status.HTTP_200_OK,
    response_model=PspPaymentStatusResponse,
)
async def get_payment_status(
    psp_payment_id: str,
    psp_service: MockPspService = Depends(get_psp_service),
    session: Any = Depends(get_psp_db_session),
) -> PspPaymentStatusResponse:
    try:
        return await psp_service.get_payment_status(psp_payment_id, session)
    except PspServiceError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail={"code": exc.code, "message": exc.message},
        ) from exc


# --- Public Key Discovery ---


@router.get(
    "/.well-known/psp-keys.json",
    status_code=status.HTTP_200_OK,
    response_model=PspJwksResponse,
)
async def get_jwks(
    psp_service: MockPspService = Depends(get_psp_service),
) -> PspJwksResponse:
    return psp_service.get_jwks()


# --- Fault Injection ---


@router.post(
    "/psp/v1/admin/faults",
    status_code=status.HTTP_200_OK,
    response_model=ConfigureFaultsResponse,
    dependencies=[Depends(verify_admin_key)],
)
async def configure_faults(
    req: ConfigureFaultsRequest,
    psp_service: MockPspService = Depends(get_psp_service),
) -> ConfigureFaultsResponse:
    try:
        return psp_service.configure_faults(req)
    except PspServiceError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail={"code": exc.code, "message": exc.message},
        ) from exc
