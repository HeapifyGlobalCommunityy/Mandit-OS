"""FastAPI router for Human Confirmation endpoints.

Per docs/modules/04-policy-and-payments.md §6.2.
"""
from typing import Any
from fastapi import APIRouter, Depends, Header, HTTPException, status

from mandit.confirmation.interface import ConfirmationService
from mandit.confirmation.schemas import (
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
from mandit.policy.models import ConfirmationModel

router = APIRouter(prefix="/v1/confirmations", tags=["confirmations"])


def get_current_user_id(
    authorization: str | None = Header(None, alias="Authorization"),
    x_user_id: str | None = Header(None, alias="X-User-ID"),
) -> str:
    """Extract authenticated user identifier."""
    if x_user_id:
        return x_user_id
    if authorization:
        # e.g. "Bearer usr_..." or "User usr_..."
        parts = authorization.split()
        if len(parts) == 2 and parts[1].startswith("usr_"):
            return parts[1]
        elif len(parts) == 2:
            return parts[1]
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={"code": "UNAUTHORIZED", "message": "Missing user authentication credentials"},
    )


@router.post("/{confirmation_id}/respond", status_code=status.HTTP_200_OK)
async def respond_to_confirmation(
    confirmation_id: str,
    payload: dict[str, Any],
    caller_user_id: str = Depends(get_current_user_id),
    confirmation_service: ConfirmationService = Depends(),
    session: Any = Depends(),
) -> dict[str, Any]:
    """Submit human response (APPROVE or REJECT) to a pending step-up confirmation."""
    req_response = payload.get("response")
    if req_response not in ("APPROVE", "REJECT"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "INVALID_RESPONSE_TYPE", "message": "response must be 'APPROVE' or 'REJECT'"},
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
        raise HTTPException(status_code=e.status_code, detail={"code": e.code, "message": e.message})
    except (ConfirmationOwnershipError, UserKeyInvalidError) as e:
        raise HTTPException(status_code=e.status_code, detail={"code": e.code, "message": e.message})
    except (ConfirmationNotPendingError, ConfirmationExpiredError, ConfirmationInvalidatedError) as e:
        raise HTTPException(status_code=e.status_code, detail={"code": e.code, "message": e.message})
    except (ChallengeMismatchError, SignatureInvalidError) as e:
        raise HTTPException(status_code=e.status_code, detail={"code": e.code, "message": e.message})
    except ConfirmationError as e:
        raise HTTPException(status_code=e.status_code, detail={"code": e.code, "message": e.message})


@router.get("/{confirmation_id}", status_code=status.HTTP_200_OK)
async def get_confirmation(
    confirmation_id: str,
    caller_user_id: str = Depends(get_current_user_id),
    confirmation_service: ConfirmationService = Depends(),
    session: Any = Depends(),
) -> dict[str, Any]:
    """Retrieve confirmation by ID for the console screen."""
    conf = await confirmation_service.get(session, confirmation_id)
    if conf is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "CONFIRMATION_NOT_FOUND", "message": f"Confirmation {confirmation_id} not found"},
        )
    if conf.user_id != caller_user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "CONFIRMATION_OWNERSHIP_MISMATCH", "message": "User does not own this confirmation"},
        )
    return conf.to_dict()
