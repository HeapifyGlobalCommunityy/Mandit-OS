"""Scoped Payment Token Service for Mandit OS.

Implements token issuance, EdDSA/JWS signing, atomic CAS redemption, validation,
and revocation per docs/modules/04-policy-and-payments.md §7.
"""

import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, cast

from cryptography.hazmat.primitives.asymmetric import ed25519
from sqlalchemy import select, update

from mandit.common import events
from mandit.common.crypto import b64url_decode, b64url_encode
from mandit.tokens.interface import (
    DecisionProvider,
    GroundingProvider,
    IdentityProvider,
    MandateSpendProvider,
)
from mandit.tokens.models import PaymentTokenModel, ensure_tz
from mandit.tokens.schemas import (
    IssuedToken,
    PaymentToken,
    TokenClaims,
    TokenErrorCode,
    TokenRedeemRequest,
    TokenRedeemResponse,
    TokenRevokeResponse,
    TokenStatus,
    TokenValidateRequest,
    TokenValidateResponse,
)

TOKEN_ISSUER = "mandit-token-svc"
TOKEN_AUDIENCE = "mock-psp"
TOKEN_VALIDITY_MINUTES = 10


class TokenError(Exception):
    """Base exception for Token Service errors."""

    def __init__(self, code: str, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


class TokenIssueError(TokenError):
    """Raised when token issuance is refused or fails."""

    pass


class TokenValidationError(TokenError):
    """Raised when token JWS signature, claims, or format are invalid."""

    pass


class TokenRedemptionRejected(TokenError):
    """Raised when token redemption is rejected."""

    pass


def create_jws(
    header: dict[str, Any],
    claims: dict[str, Any],
    private_key: ed25519.Ed25519PrivateKey,
) -> str:
    """Create a compact JWS string (RFC 7515 / RFC 8037) signed with Ed25519."""
    header_json = json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8")
    claims_json = json.dumps(claims, separators=(",", ":"), sort_keys=True).encode("utf-8")
    header_b64 = b64url_encode(header_json)
    claims_b64 = b64url_encode(claims_json)
    signing_input = f"{header_b64}.{claims_b64}".encode("ascii")
    sig_bytes = private_key.sign(signing_input)
    sig_b64 = b64url_encode(sig_bytes)
    return f"{header_b64}.{claims_b64}.{sig_b64}"


def verify_jws(
    token_str: str,
    public_key: ed25519.Ed25519PublicKey,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Verify and decode a compact EdDSA JWS token.

    Returns (header, claims) or raises TokenValidationError.
    """
    if not isinstance(token_str, str) or not token_str:
        raise TokenValidationError(
            TokenErrorCode.TOKEN_FORMAT_INVALID,
            "Token must be a non-empty string",
        )

    parts = token_str.split(".")
    if len(parts) != 3:
        raise TokenValidationError(
            TokenErrorCode.TOKEN_FORMAT_INVALID,
            f"JWS must consist of 3 parts separated by '.', got {len(parts)}",
        )

    header_b64, claims_b64, sig_b64 = parts
    try:
        header_bytes = b64url_decode(header_b64)
        claims_bytes = b64url_decode(claims_b64)
        sig_bytes = b64url_decode(sig_b64)
        header = json.loads(header_bytes.decode("utf-8"))
        claims = json.loads(claims_bytes.decode("utf-8"))
    except Exception as exc:
        raise TokenValidationError(
            TokenErrorCode.TOKEN_FORMAT_INVALID,
            f"Malformed JWS serialization: {exc}",
        ) from exc

    if header.get("alg") != "EdDSA":
        raise TokenValidationError(
            TokenErrorCode.TOKEN_SIGNATURE_INVALID,
            f"Unsupported alg '{header.get('alg')}', expected 'EdDSA'",
        )

    if header.get("typ") != "mandit-pay+jwt":
        raise TokenValidationError(
            TokenErrorCode.TOKEN_FORMAT_INVALID,
            f"Unsupported typ '{header.get('typ')}', expected 'mandit-pay+jwt'",
        )

    signing_input = f"{header_b64}.{claims_b64}".encode("ascii")
    try:
        public_key.verify(sig_bytes, signing_input)
    except Exception as exc:
        raise TokenValidationError(
            TokenErrorCode.TOKEN_SIGNATURE_INVALID,
            f"JWS signature verification failed: {exc}",
        ) from exc

    return header, claims


class TokenServiceImpl:
    """Production Scoped Payment Token Service."""

    def __init__(
        self,
        decision_provider: DecisionProvider,
        identity_provider: IdentityProvider,
        mandate_provider: MandateSpendProvider,
        grounding_provider: GroundingProvider,
        session_factory: Any = None,
        private_key: ed25519.Ed25519PrivateKey | None = None,
    ) -> None:
        self.decision_provider = decision_provider
        self.identity_provider = identity_provider
        self.mandate_provider = mandate_provider
        self.grounding_provider = grounding_provider
        self.session_factory = session_factory
        self.private_key = private_key or ed25519.Ed25519PrivateKey.generate()

    @property
    def public_key(self) -> ed25519.Ed25519PublicKey:
        return self.private_key.public_key()

    async def _emit_event(
        self,
        session: Any,
        event_type: str,
        refs: dict[str, str],
        payload: dict[str, Any],
        transaction_id: str | None = None,
    ) -> None:
        await events.emit(
            session,
            transaction_id=transaction_id,
            event_type=event_type,
            producer="tokens",
            actor={"type": "SERVICE", "id": "mandit-token-svc"},
            refs=refs,
            payload=payload,
        )

    async def _flush(self, session: Any) -> None:
        if session is not None and hasattr(session, "flush"):
            fl = session.flush()
            if hasattr(fl, "__await__"):
                await fl

    async def issue(
        self,
        decision_id: str,
        reservation_id: str,
        session: Any = None,
    ) -> IssuedToken:
        """Issue a single-use payment token for an unexpired ALLOW decision.

        Called internally inside the Payment Orchestrator's database transaction.
        Never exposed directly to the agent (INV-09).
        """
        now = datetime.now(UTC)

        # 1. Fetch and validate decision
        decision = await self.decision_provider.get(decision_id, session)
        if decision is None:
            raise TokenIssueError(
                TokenErrorCode.DECISION_NOT_FOUND,
                f"Decision {decision_id} not found",
                status_code=404,
            )

        outcome_val = (
            decision.outcome.value if hasattr(decision.outcome, "value") else str(decision.outcome)
        )
        if outcome_val != "ALLOW":
            await self._emit_event(
                session,
                "TOKEN_ISSUE_REFUSED",
                {"decision_id": decision_id, "proposal_id": decision.proposal_id},
                {"code": TokenErrorCode.DECISION_NOT_ALLOW, "outcome": outcome_val},
                transaction_id=getattr(decision, "transaction_id", None),
            )
            raise TokenIssueError(
                TokenErrorCode.DECISION_NOT_ALLOW,
                f"Decision outcome is {outcome_val}, requires ALLOW",
                status_code=400,
            )

        dec_exp = ensure_tz(decision.expires_at)
        if dec_exp is not None and dec_exp <= now:
            await self._emit_event(
                session,
                "TOKEN_ISSUE_REFUSED",
                {"decision_id": decision_id, "proposal_id": decision.proposal_id},
                {"code": TokenErrorCode.DECISION_EXPIRED, "expires_at": dec_exp.isoformat()},
                transaction_id=getattr(decision, "transaction_id", None),
            )
            raise TokenIssueError(
                TokenErrorCode.DECISION_EXPIRED,
                f"Decision {decision_id} has expired",
                status_code=410,
            )

        # 2. Fetch proposal details
        proposal = await self.grounding_provider.get_proposal(decision.proposal_id)
        if proposal is None:
            raise TokenIssueError(
                TokenErrorCode.DECISION_NOT_FOUND,
                f"Proposal {decision.proposal_id} not found",
                status_code=404,
            )

        raw_agent_id = getattr(proposal, "agent_id", None) or getattr(decision, "agent_id", None)
        if not raw_agent_id:
            raise TokenIssueError(
                TokenErrorCode.DECISION_NOT_ALLOW,
                "Proposal missing agent_id",
                status_code=400,
            )
        agent_id: str = str(raw_agent_id)

        raw_mandate_id = getattr(proposal, "mandate_id", None) or getattr(
            decision, "mandate_id", None
        )
        if not raw_mandate_id:
            raise TokenIssueError(
                TokenErrorCode.MANDATE_INVALID,
                "Proposal missing mandate_id",
                status_code=400,
            )
        mandate_id: str = str(raw_mandate_id)

        raw_checkout_id = getattr(proposal, "checkout_id", None)
        if not raw_checkout_id:
            raise TokenIssueError(
                TokenErrorCode.CHECKOUT_CHANGED,
                "Proposal missing checkout_id",
                status_code=400,
            )
        checkout_id: str = str(raw_checkout_id)

        rail_raw = getattr(proposal, "rail", None) or getattr(proposal, "payment_method", "CARD")
        if rail_raw in ("CARD_TOKEN", "CARD"):
            rail = "CARD"
        elif rail_raw == "UPI":
            rail = "UPI"
        else:
            rail = "CARD"

        # 3. Re-verify agent active status
        if not await self.identity_provider.is_active(agent_id):
            await self._emit_event(
                session,
                "TOKEN_ISSUE_REFUSED",
                {"decision_id": decision_id, "proposal_id": decision.proposal_id},
                {"code": TokenErrorCode.AGENT_REVOKED, "agent_id": agent_id},
                transaction_id=getattr(decision, "transaction_id", None),
            )
            raise TokenIssueError(
                TokenErrorCode.AGENT_REVOKED,
                f"Agent {agent_id} is inactive or revoked",
                status_code=403,
            )

        # 4. Re-verify mandate usability
        mandate = await self.mandate_provider.assert_usable(mandate_id)
        if not mandate:
            await self._emit_event(
                session,
                "TOKEN_ISSUE_REFUSED",
                {"decision_id": decision_id, "mandate_id": mandate_id},
                {"code": TokenErrorCode.MANDATE_INVALID, "mandate_id": mandate_id},
                transaction_id=getattr(decision, "transaction_id", None),
            )
            raise TokenIssueError(
                TokenErrorCode.MANDATE_INVALID,
                f"Mandate {mandate_id} is not usable",
                status_code=400,
            )

        # 5. Verify spend reservation belongs to this proposal and mandate
        reservation = await self.mandate_provider.get_reservation(reservation_id)
        if reservation is None:
            await self._emit_event(
                session,
                "TOKEN_ISSUE_REFUSED",
                {"decision_id": decision_id, "reservation_id": reservation_id},
                {"code": TokenErrorCode.RESERVATION_MISMATCH, "reason": "RESERVATION_NOT_FOUND"},
                transaction_id=getattr(decision, "transaction_id", None),
            )
            raise TokenIssueError(
                TokenErrorCode.RESERVATION_MISMATCH,
                f"Reservation {reservation_id} not found",
                status_code=400,
            )

        res_proposal_id = getattr(reservation, "proposal_id", None)
        res_mandate_id = getattr(reservation, "mandate_id", None)
        res_status = getattr(reservation, "status", "RESERVED")

        if res_proposal_id != decision.proposal_id or res_mandate_id != mandate_id:
            await self._emit_event(
                session,
                "TOKEN_ISSUE_REFUSED",
                {"decision_id": decision_id, "reservation_id": reservation_id},
                {
                    "code": TokenErrorCode.RESERVATION_MISMATCH,
                    "reason": "PROPOSAL_OR_MANDATE_MISMATCH",
                },
                transaction_id=getattr(decision, "transaction_id", None),
            )
            raise TokenIssueError(
                TokenErrorCode.RESERVATION_MISMATCH,
                "Reservation proposal or mandate mismatch",
                status_code=400,
            )

        if res_status != "RESERVED":
            await self._emit_event(
                session,
                "TOKEN_ISSUE_REFUSED",
                {"decision_id": decision_id, "reservation_id": reservation_id},
                {"code": TokenErrorCode.RESERVATION_MISMATCH, "status": res_status},
                transaction_id=getattr(decision, "transaction_id", None),
            )
            raise TokenIssueError(
                TokenErrorCode.RESERVATION_MISMATCH,
                f"Reservation status is {res_status}, must be RESERVED",
                status_code=400,
            )

        # 6. TOCTOU: Refetch checkout from merchant and verify hash integrity
        refetched = await self.grounding_provider.refetch_checkout(checkout_id)
        expected_checkout_hash = getattr(
            proposal, "checkout_hash", getattr(refetched, "checkout_hash", "")
        )
        if refetched.checkout_hash != expected_checkout_hash:
            await self._emit_event(
                session,
                "TOKEN_ISSUE_REFUSED",
                {"decision_id": decision_id, "proposal_id": decision.proposal_id},
                {
                    "code": TokenErrorCode.CHECKOUT_CHANGED,
                    "expected_hash": expected_checkout_hash,
                    "actual_hash": refetched.checkout_hash,
                },
                transaction_id=getattr(decision, "transaction_id", None),
            )
            raise TokenIssueError(
                TokenErrorCode.CHECKOUT_CHANGED,
                "Checkout hash changed during re-fetch (TOCTOU violation)",
                status_code=409,
            )

        # Verify reservation amount and currency match refetched checkout
        res_amount = getattr(reservation, "amount_minor", None)
        res_currency = getattr(reservation, "currency", None)
        if res_amount != refetched.amount_minor or res_currency != refetched.currency:
            await self._emit_event(
                session,
                "TOKEN_ISSUE_REFUSED",
                {"decision_id": decision_id, "reservation_id": reservation_id},
                {
                    "code": TokenErrorCode.RESERVATION_MISMATCH,
                    "expected_amount": refetched.amount_minor,
                    "actual_amount": res_amount,
                },
                transaction_id=getattr(decision, "transaction_id", None),
            )
            raise TokenIssueError(
                TokenErrorCode.RESERVATION_MISMATCH,
                "Reservation amount or currency does not match checkout",
                status_code=400,
            )

        # 7. Check proposal uniqueness in DB (enforce 1 token per proposal)
        if session is not None:
            stmt = select(PaymentTokenModel).where(
                PaymentTokenModel.proposal_id == decision.proposal_id
            )
            res = await session.execute(stmt)
            existing_token = res.scalar_one_or_none()
            if existing_token is not None:
                await self._emit_event(
                    session,
                    "TOKEN_ISSUE_REFUSED",
                    {"decision_id": decision_id, "proposal_id": decision.proposal_id},
                    {"code": TokenErrorCode.TOKEN_ALREADY_EXISTS},
                    transaction_id=getattr(decision, "transaction_id", None),
                )
                raise TokenIssueError(
                    TokenErrorCode.TOKEN_ALREADY_EXISTS,
                    f"A payment token has already been issued for proposal {decision.proposal_id}",
                    status_code=409,
                )

        # 8. Create and insert token model
        token_id = f"ptok_{uuid.uuid4().hex}"
        expires_at = now + timedelta(minutes=TOKEN_VALIDITY_MINUTES)
        token_model = PaymentTokenModel(
            token_id=token_id,
            proposal_id=decision.proposal_id,
            decision_id=decision_id,
            mandate_id=mandate_id,
            reservation_id=reservation_id,
            merchant_id=refetched.merchant_id,
            payee_id=refetched.payee_id,
            amount_minor=refetched.amount_minor,
            currency=refetched.currency,
            checkout_hash=refetched.checkout_hash,
            rail=rail,
            status=TokenStatus.ISSUED.value,
            idem_key=None,
            expires_at=expires_at,
            issued_at=now,
            redeemed_at=None,
        )

        if session is not None:
            session.add(token_model)
            await self._flush(session)

        # 9. Sign compact JWS token
        claims = TokenClaims(
            jti=token_id,
            iss=TOKEN_ISSUER,
            aud=TOKEN_AUDIENCE,
            proposal_id=decision.proposal_id,
            mandate_id=mandate_id,
            decision_id=decision_id,
            merchant_id=refetched.merchant_id,
            payee_id=refetched.payee_id,
            amount_minor=refetched.amount_minor,
            currency=refetched.currency,
            checkout_hash=refetched.checkout_hash,
            rail=rail,
            max_uses=1,
            iat=int(now.timestamp()),
            exp=int(expires_at.timestamp()),
            nonce=uuid.uuid4().hex,
        )

        header = {"alg": "EdDSA", "typ": "mandit-pay+jwt"}
        signed_token = create_jws(header, claims.to_dict(), self.private_key)

        # 10. Emit TOKEN_ISSUED event (raw token excluded)
        await self._emit_event(
            session,
            "TOKEN_ISSUED",
            {
                "token_id": token_id,
                "proposal_id": decision.proposal_id,
                "decision_id": decision_id,
                "mandate_id": mandate_id,
            },
            {
                "token_id": token_id,
                "amount_minor": refetched.amount_minor,
                "currency": refetched.currency,
                "rail": rail,
                "expires_at": expires_at.isoformat(),
            },
            transaction_id=getattr(decision, "transaction_id", None),
        )

        return IssuedToken(
            token_record=token_model.to_schema(),
            signed_token=signed_token,
        )

    async def redeem(
        self,
        req: TokenRedeemRequest,
        session: Any = None,
    ) -> TokenRedeemResponse:
        """Atomically validate and redeem an issued payment token.

        Enforces single-use via database atomic compare-and-set.
        Supports idempotent retries with the same idempotency key.
        """
        now = datetime.now(UTC)

        # 1. Verify JWS cryptographic integrity and format
        header, claims = verify_jws(req.token, self.public_key)
        jti = claims.get("jti")
        if not jti:
            raise TokenRedemptionRejected(
                TokenErrorCode.TOKEN_FORMAT_INVALID,
                "Token missing 'jti' claim",
                status_code=400,
            )

        # 2. Check token claims against request parameters
        if claims.get("merchant_id") != req.merchant_id:
            await self._emit_rejection(
                session, jti, claims.get("proposal_id", ""), TokenErrorCode.TOKEN_MERCHANT_MISMATCH
            )
            raise TokenRedemptionRejected(
                TokenErrorCode.TOKEN_MERCHANT_MISMATCH,
                f"Merchant mismatch: expected {claims.get('merchant_id')}, got {req.merchant_id}",
                status_code=409,
            )

        if claims.get("payee_id") != req.payee_id:
            await self._emit_rejection(
                session, jti, claims.get("proposal_id", ""), TokenErrorCode.TOKEN_PAYEE_MISMATCH
            )
            raise TokenRedemptionRejected(
                TokenErrorCode.TOKEN_PAYEE_MISMATCH,
                f"Payee mismatch: expected {claims.get('payee_id')}, got {req.payee_id}",
                status_code=409,
            )

        if claims.get("amount_minor") != req.amount_minor:
            await self._emit_rejection(
                session, jti, claims.get("proposal_id", ""), TokenErrorCode.TOKEN_AMOUNT_MISMATCH
            )
            raise TokenRedemptionRejected(
                TokenErrorCode.TOKEN_AMOUNT_MISMATCH,
                f"Amount mismatch: expected {claims.get('amount_minor')}, got {req.amount_minor}",
                status_code=409,
            )

        if claims.get("currency") != req.currency:
            await self._emit_rejection(
                session, jti, claims.get("proposal_id", ""), TokenErrorCode.TOKEN_CURRENCY_MISMATCH
            )
            raise TokenRedemptionRejected(
                TokenErrorCode.TOKEN_CURRENCY_MISMATCH,
                f"Currency mismatch: expected {claims.get('currency')}, got {req.currency}",
                status_code=409,
            )

        if claims.get("checkout_hash") != req.checkout_hash:
            await self._emit_rejection(
                session, jti, claims.get("proposal_id", ""), TokenErrorCode.TOKEN_CHECKOUT_MISMATCH
            )
            raise TokenRedemptionRejected(
                TokenErrorCode.TOKEN_CHECKOUT_MISMATCH,
                "Checkout hash mismatch",
                status_code=409,
            )

        if session is None:
            raise TokenRedemptionRejected(
                TokenErrorCode.TOKEN_REDEMPTION_FAILED,
                "Active database session required for redemption",
                status_code=500,
            )

        # 3. Atomic CAS database update: ISSUED -> REDEEMING
        stmt = (
            update(PaymentTokenModel)
            .where(
                PaymentTokenModel.token_id == jti,
                PaymentTokenModel.status == TokenStatus.ISSUED.value,
                PaymentTokenModel.expires_at > now,
                PaymentTokenModel.merchant_id == req.merchant_id,
                PaymentTokenModel.payee_id == req.payee_id,
                PaymentTokenModel.amount_minor == req.amount_minor,
                PaymentTokenModel.currency == req.currency,
                PaymentTokenModel.checkout_hash == req.checkout_hash,
            )
            .values(
                status=TokenStatus.REDEEMING.value,
                idem_key=req.idempotency_key,
            )
            .returning(
                PaymentTokenModel.token_id,
                PaymentTokenModel.proposal_id,
                PaymentTokenModel.status,
            )
        )

        result = await session.execute(stmt)
        row = result.first()
        if row is not None:
            # Atomic transition succeeded!
            await self._emit_event(
                session,
                "TOKEN_REDEEMED",
                {"token_id": jti, "proposal_id": row.proposal_id},
                {"status": "REDEEMING", "idempotency_key": req.idempotency_key},
            )
            return TokenRedeemResponse(token_id=jti, result="ACCEPTED", status="REDEEMING")

        # 4. CAS failed: query persisted record to diagnose failure cause
        sel_stmt = select(PaymentTokenModel).where(PaymentTokenModel.token_id == jti)
        sel_res = await session.execute(sel_stmt)
        existing = sel_res.scalar_one_or_none()

        if existing is None:
            raise TokenRedemptionRejected(
                TokenErrorCode.TOKEN_NOT_FOUND,
                f"Token {jti} not found in database",
                status_code=404,
            )

        # Check idempotent retry: same key, already in REDEEMING or REDEEMED
        if existing.idem_key == req.idempotency_key and existing.status in (
            TokenStatus.REDEEMING.value,
            TokenStatus.REDEEMED.value,
        ):
            return TokenRedeemResponse(token_id=jti, result="ACCEPTED", status=existing.status)

        # Check other rejection reasons
        if existing.status in (TokenStatus.REDEEMING.value, TokenStatus.REDEEMED.value):
            await self._emit_rejection(
                session, jti, existing.proposal_id, TokenErrorCode.TOKEN_ALREADY_REDEEMED
            )
            raise TokenRedemptionRejected(
                TokenErrorCode.TOKEN_ALREADY_REDEEMED,
                "Token has already been redeemed or is currently redeeming",
                status_code=409,
            )

        if existing.status == TokenStatus.REVOKED.value:
            await self._emit_rejection(
                session, jti, existing.proposal_id, TokenErrorCode.TOKEN_REVOKED
            )
            raise TokenRedemptionRejected(
                TokenErrorCode.TOKEN_REVOKED,
                "Token has been revoked",
                status_code=410,
            )

        exp = ensure_tz(existing.expires_at)
        if existing.status == TokenStatus.EXPIRED.value or (exp is not None and exp <= now):
            await self._emit_rejection(
                session, jti, existing.proposal_id, TokenErrorCode.TOKEN_EXPIRED
            )
            raise TokenRedemptionRejected(
                TokenErrorCode.TOKEN_EXPIRED,
                "Token has expired",
                status_code=410,
            )

        if existing.merchant_id != req.merchant_id:
            await self._emit_rejection(
                session, jti, existing.proposal_id, TokenErrorCode.TOKEN_MERCHANT_MISMATCH
            )
            raise TokenRedemptionRejected(
                TokenErrorCode.TOKEN_MERCHANT_MISMATCH,
                f"Merchant mismatch: expected {existing.merchant_id}",
                status_code=409,
            )

        if existing.payee_id != req.payee_id:
            await self._emit_rejection(
                session, jti, existing.proposal_id, TokenErrorCode.TOKEN_PAYEE_MISMATCH
            )
            raise TokenRedemptionRejected(
                TokenErrorCode.TOKEN_PAYEE_MISMATCH,
                f"Payee mismatch: expected {existing.payee_id}",
                status_code=409,
            )

        if existing.amount_minor != req.amount_minor:
            await self._emit_rejection(
                session, jti, existing.proposal_id, TokenErrorCode.TOKEN_AMOUNT_MISMATCH
            )
            raise TokenRedemptionRejected(
                TokenErrorCode.TOKEN_AMOUNT_MISMATCH,
                f"Amount mismatch: expected {existing.amount_minor}",
                status_code=409,
            )

        if existing.currency != req.currency:
            await self._emit_rejection(
                session, jti, existing.proposal_id, TokenErrorCode.TOKEN_CURRENCY_MISMATCH
            )
            raise TokenRedemptionRejected(
                TokenErrorCode.TOKEN_CURRENCY_MISMATCH,
                f"Currency mismatch: expected {existing.currency}",
                status_code=409,
            )

        if existing.checkout_hash != req.checkout_hash:
            await self._emit_rejection(
                session, jti, existing.proposal_id, TokenErrorCode.TOKEN_CHECKOUT_MISMATCH
            )
            raise TokenRedemptionRejected(
                TokenErrorCode.TOKEN_CHECKOUT_MISMATCH,
                "Checkout hash mismatch",
                status_code=409,
            )

        await self._emit_rejection(
            session, jti, existing.proposal_id, TokenErrorCode.TOKEN_REDEMPTION_FAILED
        )
        raise TokenRedemptionRejected(
            TokenErrorCode.TOKEN_REDEMPTION_FAILED,
            "Token redemption failed",
            status_code=409,
        )

    async def validate(
        self,
        req: TokenValidateRequest,
        session: Any = None,
    ) -> TokenValidateResponse:
        """Validate token claims and database binding without consuming it."""
        try:
            _, claims = verify_jws(req.token, self.public_key)
        except TokenValidationError as exc:
            return TokenValidateResponse(
                token_id="",
                valid=False,
                status="INVALID",
                reason=exc.code,
            )

        jti = claims.get("jti", "")
        now = datetime.now(UTC)

        # Check token claims against request
        if claims.get("merchant_id") != req.merchant_id:
            return TokenValidateResponse(
                token_id=jti,
                valid=False,
                status="INVALID",
                reason=TokenErrorCode.TOKEN_MERCHANT_MISMATCH,
            )
        if claims.get("payee_id") != req.payee_id:
            return TokenValidateResponse(
                token_id=jti,
                valid=False,
                status="INVALID",
                reason=TokenErrorCode.TOKEN_PAYEE_MISMATCH,
            )
        if claims.get("amount_minor") != req.amount_minor:
            return TokenValidateResponse(
                token_id=jti,
                valid=False,
                status="INVALID",
                reason=TokenErrorCode.TOKEN_AMOUNT_MISMATCH,
            )
        if claims.get("currency") != req.currency:
            return TokenValidateResponse(
                token_id=jti,
                valid=False,
                status="INVALID",
                reason=TokenErrorCode.TOKEN_CURRENCY_MISMATCH,
            )
        if claims.get("checkout_hash") != req.checkout_hash:
            return TokenValidateResponse(
                token_id=jti,
                valid=False,
                status="INVALID",
                reason=TokenErrorCode.TOKEN_CHECKOUT_MISMATCH,
            )

        # Query database row
        if session is not None:
            sel_stmt = select(PaymentTokenModel).where(PaymentTokenModel.token_id == jti)
            sel_res = await session.execute(sel_stmt)
            existing = sel_res.scalar_one_or_none()
            if existing is None:
                return TokenValidateResponse(
                    token_id=jti,
                    valid=False,
                    status="NOT_FOUND",
                    reason=TokenErrorCode.TOKEN_NOT_FOUND,
                )

            exp = ensure_tz(existing.expires_at)
            if existing.status == TokenStatus.EXPIRED.value or (exp is not None and exp <= now):
                return TokenValidateResponse(
                    token_id=jti,
                    valid=False,
                    status=TokenStatus.EXPIRED.value,
                    reason=TokenErrorCode.TOKEN_EXPIRED,
                )

            if existing.status != TokenStatus.ISSUED.value:
                return TokenValidateResponse(
                    token_id=jti,
                    valid=False,
                    status=existing.status,
                    reason=TokenErrorCode.TOKEN_ALREADY_REDEEMED
                    if existing.status in (TokenStatus.REDEEMING.value, TokenStatus.REDEEMED.value)
                    else TokenErrorCode.TOKEN_REVOKED,
                )

            return TokenValidateResponse(
                token_id=jti,
                valid=True,
                status=existing.status,
            )

        return TokenValidateResponse(token_id=jti, valid=True, status="ISSUED")

    async def get(
        self,
        token_id: str,
        session: Any = None,
    ) -> PaymentToken | None:
        """Retrieve token record metadata by ID (never returns JWS)."""
        if session is not None:
            stmt = select(PaymentTokenModel).where(PaymentTokenModel.token_id == token_id)
            res = await session.execute(stmt)
            row = res.scalar_one_or_none()
            if row is not None:
                return cast(PaymentToken, row.to_schema())
        return None

    async def revoke(
        self,
        token_id: str,
        reason: str,
        session: Any = None,
    ) -> TokenRevokeResponse:
        """Revoke an unredeemed payment token."""
        if session is None:
            raise TokenError(
                TokenErrorCode.TOKEN_REDEMPTION_FAILED,
                "Database session required for revoke",
                500,
            )

        now = datetime.now(UTC)
        stmt = select(PaymentTokenModel).where(PaymentTokenModel.token_id == token_id)
        res = await session.execute(stmt)
        token = res.scalar_one_or_none()

        if token is None:
            raise TokenError(
                TokenErrorCode.TOKEN_NOT_FOUND,
                f"Token {token_id} not found",
                status_code=404,
            )

        if token.status in (TokenStatus.REDEEMING.value, TokenStatus.REDEEMED.value):
            raise TokenError(
                TokenErrorCode.TOKEN_ALREADY_REDEEMED,
                "Cannot revoke an already redeemed token",
                status_code=409,
            )

        exp = ensure_tz(token.expires_at)
        if token.status == TokenStatus.EXPIRED.value or (exp is not None and exp <= now):
            raise TokenError(
                TokenErrorCode.TOKEN_EXPIRED,
                "Cannot revoke an expired token",
                status_code=410,
            )

        token.status = TokenStatus.REVOKED.value
        await self._flush(session)

        await self._emit_event(
            session,
            "TOKEN_REVOKED",
            {"token_id": token_id, "proposal_id": token.proposal_id},
            {"reason": reason},
        )

        return TokenRevokeResponse(token_id=token_id, status="REVOKED", reason=reason)

    async def mark_redeemed(
        self,
        token_id: str,
        session: Any = None,
    ) -> None:
        """Mark token as fully REDEEMED following PSP successful capture."""
        now = datetime.now(UTC)
        stmt = (
            update(PaymentTokenModel)
            .where(PaymentTokenModel.token_id == token_id)
            .values(status=TokenStatus.REDEEMED.value, redeemed_at=now)
        )
        if session is not None and hasattr(session, "execute"):
            await session.execute(stmt)
            await self._flush(session)

    async def mark_failed(
        self,
        token_id: str,
        session: Any = None,
    ) -> None:
        """Mark token as FAILED following PSP terminal decline."""
        stmt = (
            update(PaymentTokenModel)
            .where(PaymentTokenModel.token_id == token_id)
            .values(status=TokenStatus.FAILED.value)
        )
        if session is not None and hasattr(session, "execute"):
            await session.execute(stmt)
            await self._flush(session)

    async def mark_unknown(
        self,
        token_id: str,
        session: Any = None,
    ) -> None:
        """Mark token as UNKNOWN following PSP gateway timeout."""
        stmt = (
            update(PaymentTokenModel)
            .where(PaymentTokenModel.token_id == token_id)
            .values(status=TokenStatus.UNKNOWN.value)
        )
        if session is not None and hasattr(session, "execute"):
            await session.execute(stmt)
            await self._flush(session)

    async def _emit_rejection(
        self,
        session: Any,
        token_id: str,
        proposal_id: str,
        code: str,
    ) -> None:
        await self._emit_event(
            session,
            "TOKEN_REDEMPTION_REJECTED",
            {"token_id": token_id, "proposal_id": proposal_id},
            {"code": code},
        )
