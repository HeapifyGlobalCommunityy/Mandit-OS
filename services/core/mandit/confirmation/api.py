"""FastAPI HTTP router for Human Confirmation endpoints.

Per docs/modules/04-policy-and-payments.md §6.2.
"""

from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, status

from mandit.confirmation.interface import ConfirmationService, UserAuthService
from mandit.confirmation.schemas import (
    AuthenticationError,
    ChallengeMismatchError,
    ConfirmationError,
    ConfirmationExpiredError,
    ConfirmationInvalidatedError,
    ConfirmationNotFoundError,
    ConfirmationNotPendingError,
    ConfirmationOwnershipError,
    ConfirmationRespondRequest,
    SignatureInvalidError,
    UserKeyInvalidError,
)
from mandit.confirmation.service import FailClosedUserAuthService

router = APIRouter(prefix="/v1/confirmations", tags=["confirmations"])

# Singleton auth service instance: defaults to fail-closed unless overridden.
_USER_AUTH_SERVICE: UserAuthService = FailClosedUserAuthService()


def set_user_auth_service(service: UserAuthService) -> None:
    """Configure the active UserAuthService for session verification."""
    global _USER_AUTH_SERVICE
    _USER_AUTH_SERVICE = service


def get_user_auth_service() -> UserAuthService:
    """Dependency provider returning the configured UserAuthService."""
    return _USER_AUTH_SERVICE


def get_confirmation_service() -> ConfirmationService:
    """Dependency provider for ConfirmationService.

    Should be overridden in production application setup or test dependency_overrides.
    """
    raise NotImplementedError("ConfirmationService dependency must be registered")


def get_db_session() -> Any:
    """Dependency provider for the transactional database session.

    Should be overridden in production application setup or test dependency_overrides.
    """
    raise NotImplementedError("Database session dependency must be registered")


async def get_current_user_id(
    authorization: str | None = Header(None, alias="Authorization"),
    auth_service: UserAuthService = Depends(get_user_auth_service),
) -> str:
    """Extract authenticated user identifier via verified session credentials.

    Strictly fail-closed: Never inspects or trusts raw X-User-ID or unverified
    Authorization strings. Requires a valid session token verified by the gateway/identity service.
    """
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "UNAUTHORIZED", "message": "Missing Authorization credentials"},
        )
    try:
        return await auth_service.authenticate_user(authorization)
    except AuthenticationError as e:
        raise HTTPException(
            status_code=e.status_code,
            detail={"code": e.code, "message": e.message},
        ) from e
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "UNAUTHORIZED", "message": f"Authentication failed: {e}"},
        ) from e


@router.post("/{confirmation_id}/respond", status_code=status.HTTP_200_OK)
async def respond_to_confirmation(
    confirmation_id: str,
    payload: dict[str, Any],
    caller_user_id: str = Depends(get_current_user_id),
    confirmation_service: ConfirmationService = Depends(get_confirmation_service),
    session: Any = Depends(get_db_session),
) -> dict[str, Any]:
    """Submit human response (APPROVE or REJECT) to a pending step-up confirmation."""
    req_response = payload.get("response")
    if req_response not in ("APPROVE", "REJECT"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "code": "INVALID_RESPONSE_TYPE",
                "message": "response must be 'APPROVE' or 'REJECT'",
            },
        )

    req = ConfirmationRespondRequest(
        response=req_response,
        signature=payload.get("signature"),
    )

    try:
        res = await confirmation_service.respond(
            session=session,
            confirmation_id=confirmation_id,
            caller_user_id=caller_user_id,
            req=req,
        )
        return res.to_dict()
    except ConfirmationNotFoundError as e:
        raise HTTPException(
            status_code=e.status_code, detail={"code": e.code, "message": e.message}
        ) from e
    except (ConfirmationOwnershipError, UserKeyInvalidError) as e:
        raise HTTPException(
            status_code=e.status_code, detail={"code": e.code, "message": e.message}
        ) from e
    except (
        ConfirmationNotPendingError,
        ConfirmationExpiredError,
        ConfirmationInvalidatedError,
    ) as e:
        raise HTTPException(
            status_code=e.status_code, detail={"code": e.code, "message": e.message}
        ) from e
    except (ChallengeMismatchError, SignatureInvalidError) as e:
        raise HTTPException(
            status_code=e.status_code, detail={"code": e.code, "message": e.message}
        ) from e
    except ConfirmationError as e:
        raise HTTPException(
            status_code=e.status_code, detail={"code": e.code, "message": e.message}
        ) from e


@router.get("/{confirmation_id}", status_code=status.HTTP_200_OK)
async def get_confirmation(
    confirmation_id: str,
    caller_user_id: str = Depends(get_current_user_id),
    confirmation_service: ConfirmationService = Depends(get_confirmation_service),
    session: Any = Depends(get_db_session),
) -> dict[str, Any]:
    """Retrieve confirmation by ID for the console screen.

    Lazily evaluates expiry: if past expiry_at, transitions database status to EXPIRED
    and emits CONFIRMATION_EXPIRED.
    """
    conf = await confirmation_service.expire_if_needed(session, confirmation_id)
    if conf is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "code": "CONFIRMATION_NOT_FOUND",
                "message": f"Confirmation {confirmation_id} not found",
            },
        )
    if conf.user_id != caller_user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "code": "CONFIRMATION_OWNERSHIP_MISMATCH",
                "message": "User does not own this confirmation",
            },
        )
    return conf.to_dict()
