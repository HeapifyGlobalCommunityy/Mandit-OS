"""Core implementation of Mock PSP payment operations.

Implements card and UPI synthetic rail execution per docs/modules/04-policy-and-payments.md §9.
"""

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError

from mandit.tokens.schemas import TokenRedeemRequest
from mock_psp.config import SETTINGS
from mock_psp.crypto import PspKeyManager
from mock_psp.faults import FaultManager
from mock_psp.models import (
    PspPaymentModel,
    PspScopedCredentialModel,
    PspUpiIntentModel,
    PspWebhookOutboxModel,
    ensure_tz,
)
from mock_psp.schemas import (
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
    DeclineUpiIntentResponse,
    PspJwksResponse,
    PspPaymentStatusResponse,
)
from mock_psp.token_client import (
    TokenClient,
    TokenRedemptionFailed,
    extract_unverified_claims,
)
from mock_psp.webhook_dispatcher import WebhookDispatcher


class PspServiceError(Exception):
    """Base error for Mock PSP service exceptions."""

    def __init__(self, code: str, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


class MockPspService:
    """Mock PSP service orchestrating synthetic card and UPI flows."""

    def __init__(
        self,
        key_manager: PspKeyManager | None = None,
        token_client: TokenClient | None = None,
        webhook_dispatcher: WebhookDispatcher | None = None,
        fault_manager: FaultManager | None = None,
    ) -> None:
        self.key_manager = key_manager or PspKeyManager(key_id=SETTINGS.key_id)
        self.fault_manager = fault_manager or FaultManager()
        self.token_client = token_client
        self.webhook_dispatcher = webhook_dispatcher or WebhookDispatcher(
            key_manager=self.key_manager,
            core_base_url=SETTINGS.core_base_url,
            fault_manager=self.fault_manager,
        )

    async def _flush(self, session: Any) -> None:
        if session is not None and hasattr(session, "flush"):
            fl = session.flush()
            if hasattr(fl, "__await__"):
                await fl

    # --- Card Flow ---

    async def create_scoped_credential(
        self,
        req: CreateScopedCredentialRequest,
        session: Any,
    ) -> CreateScopedCredentialResponse:
        """Create a seller-bound, amount-capped, expiring credential from a Mandit token."""
        # 1. Parse unverified claims to construct Core redeem request
        claims = extract_unverified_claims(req.mandit_token)
        token_id = str(claims.get("jti", ""))
        payee_id = str(claims.get("payee_id", ""))
        token_merchant = str(claims.get("merchant_id", ""))
        token_amount = int(claims.get("amount_minor", 0))
        token_currency = str(claims.get("currency", ""))
        checkout_hash = str(claims.get("checkout_hash", ""))

        # 2. Check PSP idempotency: return existing credential if already created
        if session is not None:
            sel_stmt = select(PspScopedCredentialModel).where(
                PspScopedCredentialModel.token_id == token_id
            )
            res = await session.execute(sel_stmt)
            existing = res.scalar_one_or_none()
            if existing is not None:
                return CreateScopedCredentialResponse(
                    credential_id=existing.credential_id,
                    status=existing.status,
                    max_amount_minor=existing.max_amount_minor,
                    currency=existing.currency,
                    expires_at=ensure_tz(existing.expires_at) or existing.expires_at,
                )

        # 3. Independent claim validation
        if req.merchant_id != token_merchant:
            raise PspServiceError(
                "MERCHANT_MISMATCH",
                f"Merchant mismatch: expected {token_merchant}, got {req.merchant_id}",
                400,
            )
        if req.currency != token_currency:
            raise PspServiceError(
                "CURRENCY_MISMATCH",
                f"Currency mismatch: expected {token_currency}, got {req.currency}",
                400,
            )
        if req.max_amount_minor > token_amount:
            raise PspServiceError(
                "AMOUNT_EXCEEDS_TOKEN",
                f"Requested max amount {req.max_amount_minor} exceeds token amount {token_amount}",
                400,
            )

        # 4. Atomic redemption against Mandit Core
        if self.token_client is None:
            raise PspServiceError(
                "TOKEN_CLIENT_UNAVAILABLE",
                "TokenServiceClient not configured",
                500,
            )

        idem_key = req.idempotency_key or f"psp_redeem_{token_id}"
        redeem_req = TokenRedeemRequest(
            token=req.mandit_token,
            merchant_id=req.merchant_id,
            payee_id=payee_id,
            amount_minor=token_amount,
            currency=req.currency,
            checkout_hash=checkout_hash,
            idempotency_key=idem_key,
        )

        try:
            await self.token_client.redeem(redeem_req)
        except TokenRedemptionFailed as exc:
            raise PspServiceError(exc.code, exc.message, exc.status_code) from exc

        # 5. Persist synthetic scoped credential
        credential_id = f"spc_{uuid.uuid4().hex}"
        cred_model = PspScopedCredentialModel(
            credential_id=credential_id,
            token_id=token_id,
            merchant_id=req.merchant_id,
            max_amount_minor=req.max_amount_minor,
            currency=req.currency,
            status="ACTIVE",
            expires_at=req.expires_at,
            created_at=datetime.now(UTC),
        )

        if session is not None:
            session.add(cred_model)
            try:
                await self._flush(session)
            except IntegrityError as exc:
                sel_stmt = select(PspScopedCredentialModel).where(
                    PspScopedCredentialModel.token_id == token_id
                )
                res = await session.execute(sel_stmt)
                existing = res.scalar_one_or_none()
                if existing is not None:
                    return CreateScopedCredentialResponse(
                        credential_id=existing.credential_id,
                        status=existing.status,
                        max_amount_minor=existing.max_amount_minor,
                        currency=existing.currency,
                        expires_at=ensure_tz(existing.expires_at) or existing.expires_at,
                    )
                raise PspServiceError(
                    "TOKEN_ALREADY_REDEEMED",
                    f"Credential already created for token {token_id}",
                    409,
                ) from exc

        return CreateScopedCredentialResponse(
            credential_id=credential_id,
            status="ACTIVE",
            max_amount_minor=req.max_amount_minor,
            currency=req.currency,
            expires_at=req.expires_at,
        )

    async def authorize_card(
        self,
        req: AuthorizeCardRequest,
        session: Any,
    ) -> AuthorizeCardResponse:
        """Authorize against a scoped credential with defense-in-depth checks."""
        # 1. Idempotency check
        if req.idempotency_key and session is not None:
            stmt = select(PspPaymentModel).where(
                PspPaymentModel.idempotency_key == req.idempotency_key
            )
            res = await session.execute(stmt)
            existing_payment = res.scalar_one_or_none()
            if existing_payment is not None:
                return AuthorizeCardResponse(
                    psp_payment_id=existing_payment.psp_payment_id,
                    status=existing_payment.status,
                    amount_minor=existing_payment.amount_minor,
                    currency=existing_payment.currency,
                    decline_code=existing_payment.decline_code,
                )

        # 2. Credential validation & atomic single-use consumption
        if session is None:
            raise PspServiceError("DB_REQUIRED", "Session required", 500)

        now = datetime.now(UTC)

        # Atomic Compare-And-Set (CAS) update:
        # Only transitions status ACTIVE -> CONSUMED if unexpired, merchant matches,
        # currency matches, and amount does not exceed max_amount_minor.
        # This prevents concurrent double-spending at the database transaction level.
        cas_stmt = (
            update(PspScopedCredentialModel)
            .where(
                PspScopedCredentialModel.credential_id == req.credential_id,
                PspScopedCredentialModel.status == "ACTIVE",
                PspScopedCredentialModel.expires_at > now,
                PspScopedCredentialModel.merchant_id == req.merchant_id,
                PspScopedCredentialModel.currency == req.currency,
                PspScopedCredentialModel.max_amount_minor >= req.amount_minor,
            )
            .values(status="CONSUMED")
            .execution_options(synchronize_session="fetch")
        )
        cas_res = await session.execute(cas_stmt)

        if cas_res.rowcount == 0:
            # CAS failed: credential was either not found, already consumed, expired,
            # or failed one of the constraint checks. Run read-only query to diagnose.
            c_stmt = select(PspScopedCredentialModel).where(
                PspScopedCredentialModel.credential_id == req.credential_id
            )
            c_res = await session.execute(c_stmt)
            cred = c_res.scalar_one_or_none()

            if cred is None:
                raise PspServiceError("INVALID_CREDENTIAL", "Credential not found", 404)

            exp = ensure_tz(cred.expires_at)
            if cred.status != "ACTIVE":
                return AuthorizeCardResponse(
                    psp_payment_id="",
                    status="FAILED",
                    amount_minor=req.amount_minor,
                    currency=req.currency,
                    decline_code="CREDENTIAL_INACTIVE",
                )
            if exp is not None and exp <= now:
                return AuthorizeCardResponse(
                    psp_payment_id="",
                    status="FAILED",
                    amount_minor=req.amount_minor,
                    currency=req.currency,
                    decline_code="CREDENTIAL_EXPIRED",
                )
            if cred.merchant_id != req.merchant_id:
                return AuthorizeCardResponse(
                    psp_payment_id="",
                    status="FAILED",
                    amount_minor=req.amount_minor,
                    currency=req.currency,
                    decline_code="MERCHANT_MISMATCH",
                )
            if cred.currency != req.currency:
                return AuthorizeCardResponse(
                    psp_payment_id="",
                    status="FAILED",
                    amount_minor=req.amount_minor,
                    currency=req.currency,
                    decline_code="CURRENCY_MISMATCH",
                )
            if req.amount_minor > cred.max_amount_minor:
                return AuthorizeCardResponse(
                    psp_payment_id="",
                    status="FAILED",
                    amount_minor=req.amount_minor,
                    currency=req.currency,
                    decline_code="AMOUNT_EXCEEDS_LIMIT",
                )

            # Fallback if state changed between update and select
            return AuthorizeCardResponse(
                psp_payment_id="",
                status="FAILED",
                amount_minor=req.amount_minor,
                currency=req.currency,
                decline_code="CREDENTIAL_INACTIVE",
            )

        # 3. Check fault injection
        decline_fault = self.fault_manager.get_fault("DECLINE", req.merchant_id)
        if decline_fault is not None:
            code = decline_fault.get("decline_code", "INSUFFICIENT_FUNDS")
            psp_payment_id = f"psp_{uuid.uuid4().hex}"
            payment = PspPaymentModel(
                psp_payment_id=psp_payment_id,
                credential_id=req.credential_id,
                intent_id=None,
                merchant_id=req.merchant_id,
                amount_minor=req.amount_minor,
                currency=req.currency,
                status="FAILED",
                idempotency_key=req.idempotency_key,
                decline_code=code,
                created_at=now,
                updated_at=now,
            )
            session.add(payment)
            await self._flush(session)
            return AuthorizeCardResponse(
                psp_payment_id=psp_payment_id,
                status="FAILED",
                amount_minor=req.amount_minor,
                currency=req.currency,
                decline_code=code,
            )

        # 4. Successful authorization: single-use credential was atomically consumed
        psp_payment_id = f"psp_{uuid.uuid4().hex}"
        payment = PspPaymentModel(
            psp_payment_id=psp_payment_id,
            credential_id=req.credential_id,
            intent_id=None,
            merchant_id=req.merchant_id,
            amount_minor=req.amount_minor,
            currency=req.currency,
            status="AUTHORIZED",
            idempotency_key=req.idempotency_key,
            decline_code=None,
            created_at=now,
            updated_at=now,
        )
        session.add(payment)
        await self._flush(session)

        return AuthorizeCardResponse(
            psp_payment_id=psp_payment_id,
            status="AUTHORIZED",
            amount_minor=req.amount_minor,
            currency=req.currency,
            decline_code=None,
        )

    async def capture_card(
        self,
        req: CaptureCardRequest,
        session: Any,
    ) -> CaptureCardResponse:
        """Capture up to the authorized amount and emit a signed webhook."""
        if session is None:
            raise PspServiceError("DB_REQUIRED", "Session required", 500)

        stmt = select(PspPaymentModel).where(PspPaymentModel.psp_payment_id == req.psp_payment_id)
        res = await session.execute(stmt)
        payment = res.scalar_one_or_none()

        if payment is None:
            raise PspServiceError("PAYMENT_NOT_FOUND", "Payment not found", 404)

        if payment.status == "CAPTURED":
            # Idempotent capture
            return CaptureCardResponse(
                psp_payment_id=payment.psp_payment_id,
                status="CAPTURED",
                amount_minor=payment.amount_minor,
                currency=payment.currency,
            )

        if payment.status != "AUTHORIZED":
            raise PspServiceError(
                "INVALID_PAYMENT_STATE",
                f"Cannot capture payment in state {payment.status}",
                409,
            )

        if req.amount_minor > payment.amount_minor:
            raise PspServiceError(
                "CAPTURE_EXCEEDS_AUTH",
                f"Requested capture {req.amount_minor} exceeds authorized {payment.amount_minor}",
                409,
            )

        # Check TIMEOUT_AFTER_SUCCESS fault
        timeout_fault = self.fault_manager.get_fault("TIMEOUT_AFTER_SUCCESS", payment.merchant_id)

        # Transition payment
        payment.status = "CAPTURED"
        payment.amount_minor = req.amount_minor
        payment.updated_at = datetime.now(UTC)
        await self._flush(session)

        # Record and dispatch webhook
        await self.webhook_dispatcher.record_and_dispatch(
            session,
            event_type="payment.captured",
            psp_payment_id=payment.psp_payment_id,
            payment_ref=payment.credential_id,
            amount_minor=payment.amount_minor,
            currency=payment.currency,
            status="CAPTURED",
            merchant_id=payment.merchant_id,
        )

        if timeout_fault is not None:
            raise PspServiceError(
                "TIMEOUT_AFTER_SUCCESS",
                "Simulated PSP network timeout after successful capture",
                504,
            )

        return CaptureCardResponse(
            psp_payment_id=payment.psp_payment_id,
            status="CAPTURED",
            amount_minor=payment.amount_minor,
            currency=payment.currency,
        )

    # --- UPI Flow ---

    async def create_upi_intent(
        self,
        req: CreateUpiIntentRequest,
        session: Any,
    ) -> CreateUpiIntentResponse:
        """Create a UPI collect intent bound to payee VPA, amount, and expiry."""
        claims = extract_unverified_claims(req.mandit_token)
        token_id = str(claims.get("jti", ""))
        payee_id = str(claims.get("payee_id", ""))
        token_merchant = str(claims.get("merchant_id", ""))
        token_amount = int(claims.get("amount_minor", 0))
        token_currency = str(claims.get("currency", ""))
        checkout_hash = str(claims.get("checkout_hash", ""))

        # 1. Idempotency check
        if session is not None:
            stmt = select(PspUpiIntentModel).where(PspUpiIntentModel.token_id == token_id)
            res = await session.execute(stmt)
            existing_intent = res.scalar_one_or_none()
            if existing_intent is not None:
                return CreateUpiIntentResponse(
                    intent_id=existing_intent.intent_id,
                    psp_payment_id=existing_intent.psp_payment_id,
                    status=existing_intent.status,
                    amount_minor=existing_intent.amount_minor,
                    currency=existing_intent.currency,
                    payee_vpa=existing_intent.payee_vpa,
                    expires_at=ensure_tz(existing_intent.expires_at) or existing_intent.expires_at,
                )

        # 2. VPA binding check (REFERENCE §9.2: payee VPA must equal token payee_id)
        if not (req.payee_vpa == payee_id or req.payee_vpa.startswith(payee_id)):
            raise PspServiceError(
                "CHANGED_PAYEE",
                f"Payee VPA {req.payee_vpa} does not match token payee {payee_id}",
                409,
            )

        if req.currency != token_currency:
            raise PspServiceError("CURRENCY_MISMATCH", "Currency mismatch", 400)
        if req.amount_minor > token_amount:
            raise PspServiceError("AMOUNT_EXCEEDS_TOKEN", "Amount exceeds token cap", 400)

        # 3. Redeem token against Mandit Core
        if self.token_client is None:
            raise PspServiceError("TOKEN_CLIENT_UNAVAILABLE", "TokenClient not configured", 500)

        idem_key = req.idempotency_key or f"psp_redeem_upi_{token_id}"
        redeem_req = TokenRedeemRequest(
            token=req.mandit_token,
            merchant_id=token_merchant,
            payee_id=payee_id,
            amount_minor=token_amount,
            currency=req.currency,
            checkout_hash=checkout_hash,
            idempotency_key=idem_key,
        )

        try:
            await self.token_client.redeem(redeem_req)
        except TokenRedemptionFailed as exc:
            raise PspServiceError(exc.code, exc.message, exc.status_code) from exc

        # 4. Insert payment and intent
        now = datetime.now(UTC)
        intent_id = f"upi_intent_{uuid.uuid4().hex}"
        psp_payment_id = f"psp_{uuid.uuid4().hex}"

        payment = PspPaymentModel(
            psp_payment_id=psp_payment_id,
            credential_id=None,
            intent_id=intent_id,
            merchant_id=token_merchant,
            amount_minor=req.amount_minor,
            currency=req.currency,
            status="PENDING",
            idempotency_key=req.idempotency_key,
            decline_code=None,
            created_at=now,
            updated_at=now,
        )

        intent = PspUpiIntentModel(
            intent_id=intent_id,
            psp_payment_id=psp_payment_id,
            token_id=token_id,
            payee_vpa=req.payee_vpa,
            payer_vpa=None,
            amount_minor=req.amount_minor,
            currency=req.currency,
            status="PENDING",
            idempotency_key=req.idempotency_key,
            expires_at=req.expires_at,
            created_at=now,
            updated_at=now,
        )

        if session is not None:
            session.add(payment)
            session.add(intent)
            await self._flush(session)

        return CreateUpiIntentResponse(
            intent_id=intent_id,
            psp_payment_id=psp_payment_id,
            status="PENDING",
            amount_minor=req.amount_minor,
            currency=req.currency,
            payee_vpa=req.payee_vpa,
            expires_at=req.expires_at,
        )

    async def approve_upi_intent(
        self,
        intent_id: str,
        payer_vpa: str,
        session: Any,
    ) -> ApproveUpiIntentResponse:
        """Simulate customer UPI approval from banking app."""
        if session is None:
            raise PspServiceError("DB_REQUIRED", "Session required", 500)

        stmt = select(PspUpiIntentModel).where(PspUpiIntentModel.intent_id == intent_id)
        res = await session.execute(stmt)
        intent = res.scalar_one_or_none()

        if intent is None:
            raise PspServiceError("INTENT_NOT_FOUND", "UPI intent not found", 404)

        if intent.status == "SUCCESS":
            return ApproveUpiIntentResponse(
                intent_id=intent.intent_id,
                psp_payment_id=intent.psp_payment_id,
                status="SUCCESS",
            )

        now = datetime.now(UTC)
        exp = ensure_tz(intent.expires_at)
        if exp is not None and exp <= now:
            intent.status = "EXPIRED"
            intent.updated_at = now

            p_stmt = select(PspPaymentModel).where(
                PspPaymentModel.psp_payment_id == intent.psp_payment_id
            )
            p_res = await session.execute(p_stmt)
            payment = p_res.scalar_one_or_none()
            if payment is not None:
                payment.status = "EXPIRED"
                payment.updated_at = now

            await self._flush(session)

            # Check if webhook already dispatched to avoid duplicates
            wh_stmt = select(PspWebhookOutboxModel).where(
                PspWebhookOutboxModel.psp_payment_id == intent.psp_payment_id,
                PspWebhookOutboxModel.event_type == "payment.failed",
            )
            wh_res = await session.execute(wh_stmt)
            if wh_res.scalar_one_or_none() is None:
                await self.webhook_dispatcher.record_and_dispatch(
                    session,
                    event_type="payment.failed",
                    psp_payment_id=intent.psp_payment_id,
                    payment_ref=intent.intent_id,
                    amount_minor=intent.amount_minor,
                    currency=intent.currency,
                    status="EXPIRED",
                )

            raise PspServiceError("INTENT_EXPIRED", "UPI intent has expired", 410)

        if intent.status not in ("PENDING", "CREATED"):
            raise PspServiceError(
                "INVALID_INTENT_STATE",
                f"Cannot approve intent in status {intent.status}",
                409,
            )

        intent.status = "SUCCESS"
        intent.payer_vpa = payer_vpa
        intent.updated_at = now

        p_stmt = select(PspPaymentModel).where(
            PspPaymentModel.psp_payment_id == intent.psp_payment_id
        )
        p_res = await session.execute(p_stmt)
        payment = p_res.scalar_one_or_none()
        if payment is not None:
            payment.status = "SUCCESS"
            payment.updated_at = now

        await self._flush(session)

        # Trigger signed webhook callback
        await self.webhook_dispatcher.record_and_dispatch(
            session,
            event_type="payment.captured",
            psp_payment_id=intent.psp_payment_id,
            payment_ref=intent.intent_id,
            amount_minor=intent.amount_minor,
            currency=intent.currency,
            status="CAPTURED",
        )

        return ApproveUpiIntentResponse(
            intent_id=intent.intent_id,
            psp_payment_id=intent.psp_payment_id,
            status="SUCCESS",
        )

    async def decline_upi_intent(
        self,
        intent_id: str,
        session: Any,
    ) -> DeclineUpiIntentResponse:
        """Simulate customer UPI decline from banking app."""
        if session is None:
            raise PspServiceError("DB_REQUIRED", "Session required", 500)

        stmt = select(PspUpiIntentModel).where(PspUpiIntentModel.intent_id == intent_id)
        res = await session.execute(stmt)
        intent = res.scalar_one_or_none()

        if intent is None:
            raise PspServiceError("INTENT_NOT_FOUND", "UPI intent not found", 404)

        if intent.status == "FAILED":
            return DeclineUpiIntentResponse(
                intent_id=intent.intent_id,
                psp_payment_id=intent.psp_payment_id,
                status="FAILED",
            )

        now = datetime.now(UTC)
        intent.status = "FAILED"
        intent.updated_at = now

        p_stmt = select(PspPaymentModel).where(
            PspPaymentModel.psp_payment_id == intent.psp_payment_id
        )
        p_res = await session.execute(p_stmt)
        payment = p_res.scalar_one_or_none()
        if payment is not None:
            payment.status = "FAILED"
            payment.updated_at = now

        await self._flush(session)

        # Trigger signed decline webhook
        await self.webhook_dispatcher.record_and_dispatch(
            session,
            event_type="payment.failed",
            psp_payment_id=intent.psp_payment_id,
            payment_ref=intent.intent_id,
            amount_minor=intent.amount_minor,
            currency=intent.currency,
            status="FAILED",
        )

        return DeclineUpiIntentResponse(
            intent_id=intent.intent_id,
            psp_payment_id=intent.psp_payment_id,
            status="FAILED",
        )

    # --- Payment Status & Reconciliation ---

    async def get_payment_status(
        self,
        psp_payment_id: str,
        session: Any,
    ) -> PspPaymentStatusResponse:
        """Retrieve authoritative status of payment for reconciliation worker."""
        if session is None:
            raise PspServiceError("DB_REQUIRED", "Session required", 500)

        stmt = select(PspPaymentModel).where(PspPaymentModel.psp_payment_id == psp_payment_id)
        res = await session.execute(stmt)
        payment = res.scalar_one_or_none()

        if payment is None:
            raise PspServiceError("PAYMENT_NOT_FOUND", "Payment not found", 404)

        # Reconcile expired UPI intent if still pending
        if payment.status in ("PENDING", "CREATED") and payment.intent_id:
            i_stmt = select(PspUpiIntentModel).where(
                PspUpiIntentModel.intent_id == payment.intent_id
            )
            i_res = await session.execute(i_stmt)
            intent = i_res.scalar_one_or_none()
            if intent is not None:
                now = datetime.now(UTC)
                exp = ensure_tz(intent.expires_at)
                if exp is not None and exp <= now:
                    if intent.status in ("PENDING", "CREATED"):
                        intent.status = "EXPIRED"
                        intent.updated_at = now
                    payment.status = "EXPIRED"
                    payment.updated_at = now
                    await self._flush(session)

                    # Trigger signed failure webhook if not already recorded
                    wh_stmt = select(PspWebhookOutboxModel).where(
                        PspWebhookOutboxModel.psp_payment_id == payment.psp_payment_id,
                        PspWebhookOutboxModel.event_type == "payment.failed",
                    )
                    wh_res = await session.execute(wh_stmt)
                    if wh_res.scalar_one_or_none() is None:
                        await self.webhook_dispatcher.record_and_dispatch(
                            session,
                            event_type="payment.failed",
                            psp_payment_id=payment.psp_payment_id,
                            payment_ref=intent.intent_id,
                            amount_minor=payment.amount_minor,
                            currency=payment.currency,
                            status="EXPIRED",
                        )

        return PspPaymentStatusResponse(
            psp_payment_id=payment.psp_payment_id,
            status=payment.status,
            amount_minor=payment.amount_minor,
            currency=payment.currency,
            merchant_id=payment.merchant_id,
        )

    # --- JWKS Discovery & Faults ---

    def get_jwks(self) -> PspJwksResponse:
        """Return public keys for webhook verification."""
        return self.key_manager.get_public_jwks()

    def configure_faults(self, req: ConfigureFaultsRequest) -> ConfigureFaultsResponse:
        """Configure test faults with admin guard."""
        if not SETTINGS.allows_fault_injection:
            raise PspServiceError(
                "FORBIDDEN",
                "Fault injection is disabled outside test and demo profiles",
                403,
            )
        self.fault_manager.configure_faults(req.faults, req.scope.merchant_id)
        return ConfigureFaultsResponse(status="CONFIGURED", faults_count=len(req.faults))
