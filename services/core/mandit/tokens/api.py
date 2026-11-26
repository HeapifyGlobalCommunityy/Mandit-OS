"""FastAPI HTTP router for Scoped Payment Token endpoints.

Per docs/REFERENCE.md §9 and docs/modules/04-policy-and-payments.md §7.3.
"""

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status

from mandit.tokens.interface import TokenService
from mandit.tokens.schemas import (
    TokenMetadataResponse,
    TokenRedeemRequest,
    TokenRedeemResponse,
    TokenRevokeRequest,
    TokenRevokeResponse,
    TokenValidateRequest,
    TokenValidateResponse,
)
from mandit.tokens.service import TokenError

router = APIRouter(prefix="/v1/payment-tokens", tags=["tokens"])


def get_token_service() -> TokenService:
    """Dependency provider for TokenService."""
    raise NotImplementedError("TokenService dependency must be registered")


def get_db_session() -> Any:
    """Dependency provider for the database session."""
    raise NotImplementedError("Database session dependency must be registered")


@router.post("/redeem", status_code=status.HTTP_200_OK, response_model=TokenRedeemResponse)
async def redeem_token(
    req: TokenRedeemRequest,
    token_service: TokenService = Depends(get_token_service),
    session: Any = Depends(get_db_session),
) -> TokenRedeemResponse:
    """Atomically validate and consume a Scoped Payment Token (called by mock PSP)."""
    try:
        return await token_service.redeem(req, session=session)
    except TokenError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail={"code": exc.code, "message": exc.message},
        ) from exc


@router.post("/validate", status_code=status.HTTP_200_OK, response_model=TokenValidateResponse)
async def validate_token(
    req: TokenValidateRequest,
    token_service: TokenService = Depends(get_token_service),
    session: Any = Depends(get_db_session),
) -> TokenValidateResponse:
    """Validate token claims and database binding without consuming it."""
    return await token_service.validate(req, session=session)


@router.get("/{token_id}", status_code=status.HTTP_200_OK, response_model=TokenMetadataResponse)
async def get_token_metadata(
    token_id: str,
    token_service: TokenService = Depends(get_token_service),
    session: Any = Depends(get_db_session),
) -> TokenMetadataResponse:
    """Retrieve token metadata and status by token_id (never returns the signed JWS)."""
    token = await token_service.get(token_id, session=session)
    if token is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "TOKEN_NOT_FOUND", "message": f"Token {token_id} not found"},
        )
    return TokenMetadataResponse(
        token_id=token.token_id,
        proposal_id=token.proposal_id,
        decision_id=token.decision_id,
        mandate_id=token.mandate_id,
        reservation_id=token.reservation_id,
        merchant_id=token.merchant_id,
        payee_id=token.payee_id,
        amount_minor=token.amount_minor,
        currency=token.currency,
        rail=token.rail,
        status=token.status.value if hasattr(token.status, "value") else str(token.status),
        expires_at=token.expires_at,
        issued_at=token.issued_at,
        redeemed_at=token.redeemed_at,
    )


@router.post(
    "/{token_id}/revoke",
    status_code=status.HTTP_200_OK,
    response_model=TokenRevokeResponse,
)
async def revoke_token(
    token_id: str,
    req: TokenRevokeRequest,
    token_service: TokenService = Depends(get_token_service),
    session: Any = Depends(get_db_session),
) -> TokenRevokeResponse:
    """Revoke an unredeemed payment token."""
    try:
        return await token_service.revoke(token_id, reason=req.reason, session=session)
    except TokenError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail={"code": exc.code, "message": exc.message},
        ) from exc
