"""Payment Orchestrator execution engine and state machine.

Follows docs/modules/04-policy-and-payments.md §8 and docs/REFERENCE.md §9.4, §12.5, §14.
Implements the PaymentOrchestrator protocol connecting Policy, Confirmation, Token Service,
Mandate, Grounding, and Mock PSP components.
"""

import hashlib
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError

from mandit.common import events, jcs
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
    ensure_tz,
)
from mandit.payments.psp_client import (
    PspAuthorizeCardRequest,
    PspCaptureCardRequest,
    PspClientError,
    PspConnectionError,
    PspCreateScopedCredentialRequest,
    PspCreateUpiIntentRequest,
    PspResponseError,
    PspTimeoutError,
)
from mandit.payments.schemas import (
    PaymentErrorCode,
    PaymentExecuteResponse,
    PaymentRail,
    PaymentReceiptSchema,
    PaymentStatus,
    PaymentStatusResponse,
)
from mandit.tokens.interface import TokenService
from mandit.tokens.service import TokenError, TokenIssueError


class PaymentError(Exception):
    """Base exception for payment orchestrator errors."""

    def __init__(self, code: str, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


class DecisionNotFoundError(PaymentError):
    def __init__(self, message: str = "Decision not found") -> None:
        super().__init__(PaymentErrorCode.DECISION_NOT_FOUND, message, status_code=404)


class DecisionNotAllowError(PaymentError):
    def __init__(self, message: str = "Decision outcome is not ALLOW") -> None:
        super().__init__(PaymentErrorCode.DECISION_NOT_ALLOW, message, status_code=400)


class DecisionExpiredError(PaymentError):
    def __init__(self, message: str = "Decision has expired") -> None:
        super().__init__(PaymentErrorCode.DECISION_EXPIRED, message, status_code=410)


class ProposalNotFoundError(PaymentError):
    def __init__(self, message: str = "Proposal not found") -> None:
        super().__init__(PaymentErrorCode.PROPOSAL_NOT_FOUND, message, status_code=404)


class PaymentNotFoundError(PaymentError):
    def __init__(self, message: str = "Payment not found") -> None:
        super().__init__(PaymentErrorCode.PAYMENT_NOT_FOUND, message, status_code=404)


class PaymentAlreadyExistsError(PaymentError):
    def __init__(self, message: str = "Payment already exists for proposal") -> None:
        super().__init__(PaymentErrorCode.PAYMENT_ALREADY_EXISTS, message, status_code=409)


class IdempotencyConflictError(PaymentError):
    def __init__(
        self, message: str = "Idempotency key already used with different request"
    ) -> None:
        super().__init__(PaymentErrorCode.IDEMPOTENCY_KEY_MISMATCH, message, status_code=409)


class CheckoutChangedError(PaymentError):
    def __init__(self, message: str = "Checkout hash changed (TOCTOU violation)") -> None:
        super().__init__(PaymentErrorCode.CHECKOUT_CHANGED, message, status_code=409)


class SpendReservationError(PaymentError):
    def __init__(self, message: str = "Spend reservation failed") -> None:
        super().__init__(PaymentErrorCode.OVER_TOTAL_CAP, message, status_code=400)


class MandateInvalidError(PaymentError):
    def __init__(self, message: str = "Mandate is invalid or not usable") -> None:
        super().__init__("MANDATE_INVALID", message, status_code=400)


class PaymentOrchestratorImpl(PaymentOrchestrator):
    """Production Payment Orchestrator engine coordinating payment lifecycle."""

    def __init__(
        self,
        decision_provider: DecisionProvider,
        token_service: TokenService,
        mandate_client: MandateClient,
        grounding_client: GroundingClient,
        psp_client: PspClient,
        session_factory: Any = None,
    ) -> None:
        self.decision_provider = decision_provider
        self.token_service = token_service
        self.mandate_client = mandate_client
        self.grounding_client = grounding_client
        self.psp_client = psp_client
        self.session_factory = session_factory

    @asynccontextmanager
    async def _session_scope(self, session: Any = None) -> AsyncIterator[Any]:
        """Provide a managed database session context."""
        if session is not None:
            yield session
        elif self.session_factory is not None:
            ctx = self.session_factory()
            if hasattr(ctx, "__aenter__"):
                async with ctx as s:
                    yield s
            elif hasattr(ctx, "__enter__"):
                with ctx as s:
                    yield s
            else:
                yield ctx
        else:
            yield None

    async def _commit(self, session: Any) -> None:
        if session is not None and hasattr(session, "commit"):
            cm = session.commit()
            if hasattr(cm, "__await__"):
                await cm

    async def _rollback(self, session: Any) -> None:
        if session is not None and hasattr(session, "rollback"):
            rb = session.rollback()
            if hasattr(rb, "__await__"):
                await rb

    async def _flush(self, session: Any) -> None:
        if session is not None and hasattr(session, "flush"):
            fl = session.flush()
            if hasattr(fl, "__await__"):
                await fl

    async def _emit_event(
        self,
        session: Any,
        event_type: str,
        refs: dict[str, str],
        payload: dict[str, Any],
        transaction_id: str | None = None,
    ) -> None:
        """Emit transactional event via mandit.common.events outbox."""
        await events.emit(
            session,
            transaction_id=transaction_id,
            event_type=event_type,
            producer="payments",
            actor={"type": "SERVICE", "id": "mandit-payment-orchestrator"},
            refs=refs,
            payload=payload,
        )

    async def _get_latest_decision(self, proposal_id: str, session: Any = None) -> Any:
        """Fetch latest policy decision for proposal."""
        if hasattr(self.decision_provider, "get_latest_for_proposal"):
            dec = await self.decision_provider.get_latest_for_proposal(proposal_id, session=session)
            if dec is not None:
                return dec

        # Fallback to direct DB query if session is available
        if session is not None and hasattr(session, "execute"):
            try:
                from mandit.policy.models import DecisionModel

                stmt = (
                    select(DecisionModel)
                    .where(DecisionModel.proposal_id == proposal_id)
                    .order_by(DecisionModel.attempt.desc(), DecisionModel.created_at.desc())
                    .limit(1)
                )
                res = await session.execute(stmt)
                m = res.scalar_one_or_none()
                if m is not None:
                    return m.to_schema() if hasattr(m, "to_schema") else m
            except Exception:
                pass
        return None

    async def execute(
        self,
        proposal_id: str,
        idempotency_key: str,
        session: Any = None,
    ) -> PaymentExecuteResponse:
        """Execute payment for an approved proposal.

        Implements modules/04 §8.1 flow:
        1. Check idempotency (same key + same request -> return stored response)
        2. Validate latest decision (ALLOW, unexpired)
        3. Transaction 1: Reserve spend, issue token, insert payment(CREATED), commit
        4. External PSP call (no open database transaction)
        5. Transaction 2: Update payment state, commit/release spend, complete checkout, commit
        """
        if not idempotency_key or not isinstance(idempotency_key, str):
            raise PaymentError(
                PaymentErrorCode.IDEMPOTENCY_KEY_MISMATCH,
                "A non-empty string idempotency_key is required",
                status_code=400,
            )

        request_data = {"proposal_id": proposal_id}
        request_hash = hashlib.sha256(jcs.canonicalize(request_data)).hexdigest()

        # =========================================================================
        # PHASE 1: Validation, Preconditions, Spend Reservation, Token, & Payment(CREATED)
        # =========================================================================
        payment_id = f"pay_{uuid.uuid4().hex}"
        now = datetime.now(UTC)

        async with self._session_scope(session) as sess1:
            # 1. Idempotency verification
            if sess1 is not None and hasattr(sess1, "execute"):
                stmt_idem = select(IdempotencyKeyModel).where(
                    IdempotencyKeyModel.key == idempotency_key
                )
                res_idem = await sess1.execute(stmt_idem)
                idem_record = res_idem.scalar_one_or_none()

                if idem_record is not None:
                    if idem_record.request_hash != request_hash:
                        raise IdempotencyConflictError(
                            f"Idempotency key '{idempotency_key}' reused with different request"
                        )
                    if idem_record.response_body is not None:
                        # Idempotent replay: return stored response
                        return PaymentExecuteResponse.model_validate(idem_record.response_body)
                    else:
                        # In-progress execution
                        raise PaymentAlreadyExistsError(
                            f"Concurrent execution in progress for key '{idempotency_key}'"
                        )

                # Record in-flight idempotency key
                new_idem = IdempotencyKeyModel(
                    key=idempotency_key,
                    route="/v1/payments/execute",
                    request_hash=request_hash,
                    response_status=None,
                    response_body=None,
                    created_at=now,
                )
                sess1.add(new_idem)
                try:
                    await self._flush(sess1)
                except IntegrityError as exc:
                    await self._rollback(sess1)
                    raise PaymentAlreadyExistsError(
                        f"Concurrent request raced for idempotency key '{idempotency_key}'"
                    ) from exc

                # Check if proposal already has a payment
                stmt_pay = select(PaymentModel).where(PaymentModel.proposal_id == proposal_id)
                res_pay = await sess1.execute(stmt_pay)
                existing_pay = res_pay.scalar_one_or_none()
                if existing_pay is not None:
                    raise PaymentAlreadyExistsError(
                        f"Payment already exists for proposal '{proposal_id}'"
                    )

            # 2. Load latest decision for proposal
            decision = await self._get_latest_decision(proposal_id, sess1)
            if decision is None:
                raise DecisionNotFoundError(
                    f"No policy decision found for proposal '{proposal_id}'"
                )

            outcome_val = (
                decision.outcome.value
                if hasattr(decision.outcome, "value")
                else str(decision.outcome)
            )
            if outcome_val != "ALLOW":
                raise DecisionNotAllowError(
                    f"Latest decision for proposal '{proposal_id}' is {outcome_val}, requires ALLOW"
                )

            dec_exp = ensure_tz(decision.expires_at)
            if dec_exp is not None and dec_exp <= now:
                raise DecisionExpiredError(
                    f"Latest decision for proposal '{proposal_id}' expired at {dec_exp.isoformat()}"
                )

            # 3. Fetch proposal details
            proposal = await self.grounding_client.get_proposal(proposal_id, session=sess1)
            if proposal is None:
                raise ProposalNotFoundError(f"Proposal '{proposal_id}' not found")

            checkout_id = getattr(proposal, "checkout_id", None) or (
                getattr(proposal, "checkout", {}).get("checkout_id")
                if isinstance(getattr(proposal, "checkout", None), dict)
                else None
            )
            if not checkout_id:
                raise CheckoutChangedError(f"Proposal '{proposal_id}' missing checkout_id")

            # 4. Refetch checkout from merchant and verify TOCTOU hash integrity
            checkout = await self.grounding_client.refetch_checkout(checkout_id, session=sess1)
            if checkout is None:
                raise CheckoutChangedError(f"Refetched checkout '{checkout_id}' not found")

            expected_checkout_hash = getattr(proposal, "checkout_hash", None)
            actual_checkout_hash = getattr(checkout, "checkout_hash", None)
            if (
                expected_checkout_hash
                and actual_checkout_hash
                and expected_checkout_hash != actual_checkout_hash
            ):
                raise CheckoutChangedError(
                    "Checkout hash changed during re-fetch (TOCTOU violation)"
                )

            merchant_id: str = str(
                getattr(checkout, "merchant_id", None) or getattr(proposal, "merchant_id", "")
            )
            payee_id: str = str(
                getattr(checkout, "payee_id", None) or getattr(checkout, "payee", "")
            )
            raw_amount = getattr(checkout, "amount_minor", None)
            if raw_amount is None:
                raw_amount = getattr(checkout, "total_minor", 0)
            amount_minor: int = int(raw_amount or 0)
            currency: str = str(getattr(checkout, "currency", "INR"))

            rail_str = getattr(proposal, "rail", None) or getattr(
                proposal, "payment_method", "CARD"
            )
            if rail_str in ("CARD", "CARD_TOKEN"):
                rail = PaymentRail.CARD
            elif rail_str == "UPI":
                rail = PaymentRail.UPI
            else:
                rail = PaymentRail.CARD

            # 5. Reserve spend with MandateClient (Team 1)
            mandate_id = getattr(proposal, "mandate_id", None) or getattr(
                decision, "mandate_id", None
            )
            if not mandate_id:
                raise MandateInvalidError("Proposal missing mandate_id")

            try:
                reservation = await self.mandate_client.reserve_spend(
                    mandate_id=mandate_id,
                    proposal_id=proposal_id,
                    amount_minor=amount_minor,
                    currency=currency,
                    session=sess1,
                )
            except Exception as exc:
                raise SpendReservationError(f"Mandate spend reservation refused: {exc}") from exc

            if reservation is None:
                raise SpendReservationError("Mandate spend reservation returned None")

            res_id = getattr(reservation, "reservation_id", None)
            if res_id is None and isinstance(reservation, dict):
                res_id = reservation.get("reservation_id")
            reservation_id = str(res_id) if res_id is not None else str(reservation)

            # 6. Issue scoped payment token (Team 4 Tokens)
            try:
                issued_token = await self.token_service.issue(
                    decision_id=decision.decision_id,
                    reservation_id=reservation_id,
                    session=sess1,
                )
            except Exception as exc:
                # Clean up spend reservation on issuance failure
                try:
                    await self.mandate_client.release_spend(reservation_id, session=sess1)
                except Exception:
                    pass
                if isinstance(exc, (TokenIssueError, TokenError)):
                    raise PaymentError(exc.code, exc.message, status_code=exc.status_code) from exc
                raise

            token_id = issued_token.token_record.token_id
            signed_token = issued_token.signed_token
            expires_at = issued_token.token_record.expires_at

            # 7. Insert payments row (status=CREATED)
            payment_model = PaymentModel(
                payment_id=payment_id,
                proposal_id=proposal_id,
                token_id=token_id,
                rail=rail.value,
                psp_payment_id=None,
                status=PaymentStatus.CREATED.value,
                amount_minor=amount_minor,
                currency=currency,
                failure_code=None,
                created_at=now,
                updated_at=now,
            )
            if sess1 is not None and hasattr(sess1, "add"):
                sess1.add(payment_model)

            # 8. Emit PAYMENT_CREATED event
            await self._emit_event(
                sess1,
                event_type="PAYMENT_CREATED",
                refs={
                    "payment_id": payment_id,
                    "proposal_id": proposal_id,
                    "token_id": token_id,
                },
                payload={
                    "rail": rail.value,
                    "amount_minor": amount_minor,
                    "currency": currency,
                },
                transaction_id=getattr(decision, "transaction_id", None),
            )

            # COMMIT Phase 1: Close transaction before external PSP network calls!
            await self._commit(sess1)

        # =========================================================================
        # PHASE 2: External PSP Network Operations (Zero Open Database Transaction)
        # =========================================================================
        psp_payment_id: str | None = None
        outcome_status: PaymentStatus = PaymentStatus.FAILED
        failure_code: str | None = None

        if rail == PaymentRail.CARD:
            try:
                # Step 2a: Create Scoped Credential
                cred_req = PspCreateScopedCredentialRequest(
                    mandit_token=signed_token,
                    merchant_id=merchant_id,
                    max_amount_minor=amount_minor,
                    currency=currency,
                    expires_at=expires_at,
                    idempotency_key=f"{idempotency_key}:cred",
                )
                cred_resp = await self.psp_client.create_scoped_credential(cred_req)

                # Step 2b: Authorize Card
                auth_req = PspAuthorizeCardRequest(
                    credential_id=cred_resp.credential_id,
                    merchant_id=merchant_id,
                    amount_minor=amount_minor,
                    currency=currency,
                    idempotency_key=f"{idempotency_key}:auth",
                )
                auth_resp = await self.psp_client.authorize_card(auth_req)
                psp_payment_id = auth_resp.psp_payment_id

                if auth_resp.status == "AUTHORIZED":
                    # Step 2c: Capture Card
                    cap_req = PspCaptureCardRequest(
                        psp_payment_id=auth_resp.psp_payment_id,
                        amount_minor=amount_minor,
                    )
                    cap_resp = await self.psp_client.capture_card(cap_req)
                    if cap_resp.status == "CAPTURED":
                        outcome_status = PaymentStatus.CAPTURED
                        psp_payment_id = cap_resp.psp_payment_id
                    else:
                        outcome_status = PaymentStatus.FAILED
                        failure_code = "CAPTURE_FAILED"
                else:
                    outcome_status = PaymentStatus.FAILED
                    failure_code = auth_resp.decline_code or "PSP_DECLINED"

            except PspTimeoutError:
                outcome_status = PaymentStatus.UNKNOWN
                failure_code = "PSP_TIMEOUT"
            except (PspResponseError, PspConnectionError, PspClientError) as exc:
                outcome_status = PaymentStatus.FAILED
                failure_code = getattr(exc, "error_code", "PSP_ERROR")
            except Exception as exc:
                outcome_status = PaymentStatus.FAILED
                failure_code = str(exc) or "PSP_ERROR"

        elif rail == PaymentRail.UPI:
            try:
                upi_req = PspCreateUpiIntentRequest(
                    mandit_token=signed_token,
                    payee_vpa=payee_id,
                    amount_minor=amount_minor,
                    currency=currency,
                    expires_at=expires_at,
                    idempotency_key=f"{idempotency_key}:upi",
                )
                upi_resp = await self.psp_client.create_upi_intent(upi_req)
                psp_payment_id = upi_resp.psp_payment_id
                outcome_status = PaymentStatus.PENDING
            except PspTimeoutError:
                outcome_status = PaymentStatus.UNKNOWN
                failure_code = "PSP_TIMEOUT"
            except (PspResponseError, PspConnectionError, PspClientError) as exc:
                outcome_status = PaymentStatus.FAILED
                failure_code = getattr(exc, "error_code", "PSP_ERROR")
            except Exception as exc:
                outcome_status = PaymentStatus.FAILED
                failure_code = str(exc) or "PSP_ERROR"

        # =========================================================================
        # PHASE 3: Reopen Transaction, Persist Outcome, Settle Spend, Update Idempotency
        # =========================================================================
        async with self._session_scope(session) as sess2:
            now2 = datetime.now(UTC)

            if sess2 is not None and hasattr(sess2, "execute"):
                # Update Payment state
                stmt_upd = (
                    update(PaymentModel)
                    .where(PaymentModel.payment_id == payment_id)
                    .values(
                        status=outcome_status.value,
                        psp_payment_id=psp_payment_id,
                        failure_code=failure_code,
                        updated_at=now2,
                    )
                )
                await sess2.execute(stmt_upd)

            # Spend & Token Lifecycle Transitions
            if outcome_status == PaymentStatus.CAPTURED:
                # 1. Commit spend with MandateClient
                await self.mandate_client.commit_spend(reservation_id, session=sess2)

                # 2. Mark token REDEEMED
                if hasattr(self.token_service, "mark_redeemed"):
                    await self.token_service.mark_redeemed(token_id, sess2)

                # 3. Complete merchant checkout
                if psp_payment_id:
                    try:
                        await self.grounding_client.complete_checkout(
                            checkout_id, psp_payment_id, session=sess2
                        )
                    except Exception:
                        pass

                # 4. Emit PAYMENT_RESULT
                await self._emit_event(
                    sess2,
                    event_type="PAYMENT_RESULT",
                    refs={"payment_id": payment_id, "token_id": token_id},
                    payload={
                        "status": outcome_status.value,
                        "psp_payment_id": psp_payment_id,
                        "failure_code": None,
                        "reconciled": False,
                    },
                    transaction_id=getattr(decision, "transaction_id", None),
                )

            elif outcome_status == PaymentStatus.FAILED:
                # 1. Release spend with MandateClient
                await self.mandate_client.release_spend(reservation_id, session=sess2)

                # 2. Mark token FAILED
                if hasattr(self.token_service, "mark_failed"):
                    await self.token_service.mark_failed(token_id, sess2)

                # 3. Emit PAYMENT_RESULT
                await self._emit_event(
                    sess2,
                    event_type="PAYMENT_RESULT",
                    refs={"payment_id": payment_id, "token_id": token_id},
                    payload={
                        "status": outcome_status.value,
                        "psp_payment_id": psp_payment_id,
                        "failure_code": failure_code,
                        "reconciled": False,
                    },
                    transaction_id=getattr(decision, "transaction_id", None),
                )

            elif outcome_status == PaymentStatus.UNKNOWN:
                # Ambiguous outcome: DO NOT release spend reservation!
                if hasattr(self.token_service, "mark_unknown"):
                    await self.token_service.mark_unknown(token_id, sess2)

                # Emit PAYMENT_RESULT with UNKNOWN status
                await self._emit_event(
                    sess2,
                    event_type="PAYMENT_RESULT",
                    refs={"payment_id": payment_id, "token_id": token_id},
                    payload={
                        "status": outcome_status.value,
                        "psp_payment_id": psp_payment_id,
                        "failure_code": failure_code,
                        "reconciled": False,
                    },
                    transaction_id=getattr(decision, "transaction_id", None),
                )

            elif outcome_status == PaymentStatus.PENDING:
                # UPI intent pending user approval: spend reservation remains intact
                pass

            # Assemble response
            receipt: PaymentReceiptSchema | None = None
            if outcome_status in (PaymentStatus.CAPTURED, PaymentStatus.SUCCESS):
                txn_id = getattr(decision, "transaction_id", "")
                receipt = PaymentReceiptSchema(
                    transaction_id=txn_id,
                    evidence_url=f"/v1/evidence/{txn_id}" if txn_id else None,
                )

            response = PaymentExecuteResponse(
                payment_id=payment_id,
                proposal_id=proposal_id,
                rail=rail,
                status=outcome_status,
                amount_minor=amount_minor,
                currency=currency,
                merchant_id=merchant_id,
                receipt=receipt,
            )

            # Persist finalized response into idempotency_keys
            if sess2 is not None and hasattr(sess2, "execute"):
                stmt_idem_done = (
                    update(IdempotencyKeyModel)
                    .where(IdempotencyKeyModel.key == idempotency_key)
                    .values(
                        response_status=200,
                        response_body=response.model_dump(mode="json"),
                    )
                )
                await sess2.execute(stmt_idem_done)

            # COMMIT Phase 3
            await self._commit(sess2)

        return response

    async def get(
        self,
        payment_id: str,
        session: Any = None,
    ) -> PaymentStatusResponse | None:
        """Retrieve stored payment by payment_id."""
        async with self._session_scope(session) as sess:
            if sess is None or not hasattr(sess, "execute"):
                return None

            stmt = select(PaymentModel).where(PaymentModel.payment_id == payment_id)
            res = await sess.execute(stmt)
            model = res.scalar_one_or_none()
            if model is None:
                return None

            receipt: PaymentReceiptSchema | None = None
            if model.status in (PaymentStatus.CAPTURED.value, PaymentStatus.SUCCESS.value):
                dec = await self._get_latest_decision(model.proposal_id, sess)
                txn_id = getattr(dec, "transaction_id", "") if dec else ""
                receipt = PaymentReceiptSchema(
                    transaction_id=txn_id,
                    evidence_url=f"/v1/evidence/{txn_id}" if txn_id else None,
                )

            return PaymentStatusResponse(
                payment_id=model.payment_id,
                proposal_id=model.proposal_id,
                token_id=model.token_id,
                rail=PaymentRail(model.rail),
                psp_payment_id=model.psp_payment_id,
                status=PaymentStatus(model.status),
                amount_minor=model.amount_minor,
                currency=model.currency,
                failure_code=model.failure_code,
                created_at=ensure_tz(model.created_at) or model.created_at,
                updated_at=ensure_tz(model.updated_at) or model.updated_at,
                receipt=receipt,
            )

    async def get_by_proposal(
        self,
        proposal_id: str,
        session: Any = None,
    ) -> PaymentStatusResponse | None:
        """Retrieve stored payment by proposal_id."""
        async with self._session_scope(session) as sess:
            if sess is None or not hasattr(sess, "execute"):
                return None

            stmt = select(PaymentModel).where(PaymentModel.proposal_id == proposal_id)
            res = await sess.execute(stmt)
            model = res.scalar_one_or_none()
            if model is None:
                return None

            receipt: PaymentReceiptSchema | None = None
            if model.status in (PaymentStatus.CAPTURED.value, PaymentStatus.SUCCESS.value):
                dec = await self._get_latest_decision(proposal_id, sess)
                txn_id = getattr(dec, "transaction_id", "") if dec else ""
                receipt = PaymentReceiptSchema(
                    transaction_id=txn_id,
                    evidence_url=f"/v1/evidence/{txn_id}" if txn_id else None,
                )

            return PaymentStatusResponse(
                payment_id=model.payment_id,
                proposal_id=model.proposal_id,
                token_id=model.token_id,
                rail=PaymentRail(model.rail),
                psp_payment_id=model.psp_payment_id,
                status=PaymentStatus(model.status),
                amount_minor=model.amount_minor,
                currency=model.currency,
                failure_code=model.failure_code,
                created_at=ensure_tz(model.created_at) or model.created_at,
                updated_at=ensure_tz(model.updated_at) or model.updated_at,
                receipt=receipt,
            )

    async def process_webhook(
        self,
        payload: dict[str, Any],
        signature_header: str | None,
        session: Any = None,
    ) -> dict[str, Any]:
        """Webhook handling deferred to Milestone 4 per architectural roadmap."""
        raise NotImplementedError("Webhook processing is deferred to Milestone 4")

    async def reconcile(
        self,
        timeout_threshold_seconds: int = 15,
        session: Any = None,
    ) -> list[PaymentStatusResponse]:
        """Reconciliation worker deferred to Milestone 4 per architectural roadmap."""
        raise NotImplementedError("Payment reconciliation is deferred to Milestone 4")
