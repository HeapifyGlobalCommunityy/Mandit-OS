"""Confirmation Service implementation adhering strictly to docs/modules/04 §6."""
from datetime import datetime, timezone
from typing import Any, Callable

from mandit.common import events
from mandit.common.crypto import (
    load_es256_public_key_from_jwk,
    verify_es256_signature,
)
from mandit.confirmation.interface import ConfirmationService, UserKeyService
from mandit.confirmation.schemas import (
    ChallengeMismatchError,
    ConfirmationExpiredError,
    ConfirmationInvalidatedError,
    ConfirmationNotFoundError,
    ConfirmationNotPendingError,
    ConfirmationOwnershipError,
    ConfirmationRespondRequest,
    ConfirmationRespondResponse,
    SignatureInvalidError,
    UserKeyInvalidError,
)
from mandit.policy.models import ConfirmationModel, ensure_tz
from mandit.policy.repository import DecisionRepository
from mandit.policy.schemas import ConfirmationSnapshot
from mandit.policy.service import DecisionServiceImpl


class ConfirmationServiceImpl(ConfirmationService):
    """Production ConfirmationService managing human confirmation lifecycle and validation."""

    def __init__(
        self,
        repository: DecisionRepository,
        decision_service: DecisionServiceImpl,
        grounding_service: Any = None,
        user_key_service: UserKeyService | None = None,
        now_fn: Callable[[], datetime] | None = None,
    ) -> None:
        self.repository = repository
        self.decision_service = decision_service
        self.grounding_service = grounding_service
        self.user_key_service = user_key_service
        self.now_fn = now_fn or (lambda: datetime.now(timezone.utc))

    async def get(
        self,
        session: Any,
        confirmation_id: str,
    ) -> ConfirmationModel | None:
        """Retrieve confirmation model by ID."""
        return await self.repository.get_confirmation(session, confirmation_id)

    async def expire_if_needed(
        self,
        session: Any,
        confirmation_id: str,
    ) -> ConfirmationModel | None:
        """Check expiry and transition to EXPIRED if past expiry time."""
        conf = await self.repository.get_confirmation(session, confirmation_id)
        if conf is None:
            return None
        now = self.now_fn()
        conf_exp = ensure_tz(conf.expires_at)
        if conf.status == "PENDING" and conf_exp is not None and conf_exp <= now:
            cas_ok = await self.repository.update_confirmation_status_cas(
                session,
                confirmation_id=confirmation_id,
                expected_status="PENDING",
                new_status="EXPIRED",
                responded_at=now,
            )
            if cas_ok:
                await events.emit(
                    session,
                    transaction_id=None,
                    event_type="CONFIRMATION_EXPIRED",
                    producer="confirmation",
                    actor={"type": "SERVICE", "id": "mandit-confirmation"},
                    refs={"confirmation_id": confirmation_id},
                    payload={"expired_at": conf_exp.isoformat()},
                )
                conf.status = "EXPIRED"
        return conf

    async def _invalidate(
        self,
        session: Any,
        confirmation_id: str,
        old_proposal_hash: str,
        new_proposal_hash: str,
        code: str,
        caller_user_id: str,
    ) -> None:
        now = self.now_fn()
        cas_ok = await self.repository.update_confirmation_status_cas(
            session,
            confirmation_id=confirmation_id,
            expected_status="PENDING",
            new_status="INVALIDATED",
            responded_at=now,
        )
        if cas_ok:
            await events.emit(
                session,
                transaction_id=None,
                event_type="CONFIRMATION_INVALIDATED",
                producer="confirmation",
                actor={"type": "USER", "id": caller_user_id},
                refs={"confirmation_id": confirmation_id},
                payload={
                    "code": code,
                    "old_proposal_hash": old_proposal_hash,
                    "new_proposal_hash": new_proposal_hash,
                },
            )

    async def respond(
        self,
        session: Any,
        confirmation_id: str,
        caller_user_id: str,
        req: ConfirmationRespondRequest,
    ) -> ConfirmationRespondResponse:
        """Process user approval or rejection with atomic validation and event emission."""
        now = self.now_fn()

        # Step 1: Confirmation must exist
        conf = await self.repository.get_confirmation(session, confirmation_id)
        if conf is None:
            raise ConfirmationNotFoundError(f"Confirmation {confirmation_id} not found")

        # Step 2: Confirmation must currently be PENDING
        if conf.status != "PENDING":
            if conf.status == "EXPIRED":
                raise ConfirmationExpiredError("Confirmation has expired")
            elif conf.status == "INVALIDATED":
                raise ConfirmationInvalidatedError("Confirmation was invalidated", code="CONFIRMATION_INVALIDATED")
            raise ConfirmationNotPendingError(f"Confirmation is already {conf.status}")

        # Step 3: Confirmation must not be expired
        conf_exp = ensure_tz(conf.expires_at)
        if conf_exp is not None and conf_exp <= now:
            cas_ok = await self.repository.update_confirmation_status_cas(
                session,
                confirmation_id=confirmation_id,
                expected_status="PENDING",
                new_status="EXPIRED",
                responded_at=now,
            )
            if cas_ok:
                await events.emit(
                    session,
                    transaction_id=None,
                    event_type="CONFIRMATION_EXPIRED",
                    producer="confirmation",
                    actor={"type": "USER", "id": caller_user_id},
                    refs={"confirmation_id": confirmation_id},
                    payload={"expired_at": conf_exp.isoformat()},
                )
            raise ConfirmationExpiredError("Confirmation has expired")

        # Step 4: Caller must own confirmation
        if conf.user_id != caller_user_id:
            raise ConfirmationOwnershipError(f"User {caller_user_id} does not own confirmation {confirmation_id}")

        # Step 5: Handle REJECT
        if req.response == "REJECT":
            key_id: str | None = None
            if req.signature is not None:
                if req.signature.get("signed_digest") != conf.challenge:
                    raise ChallengeMismatchError("Signature signed_digest does not match stored challenge")
                key_id = req.signature.get("key_id")
            elif self.user_key_service is not None:
                active_key = await self.user_key_service.get_active_key(caller_user_id)
                if active_key is not None:
                    key_id = active_key.key_id

            cas_ok = await self.repository.update_confirmation_status_cas(
                session,
                confirmation_id=confirmation_id,
                expected_status="PENDING",
                new_status="REJECTED",
                response_signature=req.signature,
                responded_at=now,
            )
            if not cas_ok:
                raise ConfirmationNotPendingError("Confirmation already processed by a concurrent request")

            await events.emit(
                session,
                transaction_id=None,
                event_type="CONFIRMATION_REJECTED",
                producer="confirmation",
                actor={"type": "USER", "id": caller_user_id},
                refs={"confirmation_id": confirmation_id, "user_id": caller_user_id},
                payload={"challenge": conf.challenge, "key_id": key_id},
            )
            return ConfirmationRespondResponse(
                confirmation_id=confirmation_id,
                status="REJECTED",
                decision_id=None,
                outcome=None,
            )

        # Step 6: Handle APPROVE
        if req.response != "APPROVE":
            raise ValueError(f"Invalid response action: {req.response}")

        # Signature envelope required
        if req.signature is None:
            raise SignatureInvalidError("Signature envelope is required on APPROVE")

        sig = req.signature
        if sig.get("alg") != "ES256":
            raise SignatureInvalidError("Invalid signature algorithm: expected 'ES256'")

        if sig.get("signed_digest") != conf.challenge:
            raise ChallengeMismatchError("Signature signed_digest does not match stored challenge")

        key_id = sig.get("key_id")
        if not key_id:
            raise UserKeyInvalidError("Signature envelope missing key_id")

        if self.user_key_service is None:
            raise UserKeyInvalidError("UserKeyService not configured")

        user_key = await self.user_key_service.get_key(key_id)
        if (
            user_key is None
            or user_key.user_id != caller_user_id
            or user_key.status != "ACTIVE"
            or user_key.alg != "ES256"
        ):
            raise UserKeyInvalidError(f"Key {key_id} is invalid, revoked, or does not belong to user {caller_user_id}")

        # ES256 verification
        try:
            public_key = load_es256_public_key_from_jwk(user_key.jwk)
        except Exception as exc:
            raise UserKeyInvalidError(f"Malformed public key JWK: {exc}")

        if not verify_es256_signature(public_key, sig, conf.challenge):
            raise SignatureInvalidError("ES256 signature verification failed")

        # TOCTOU & Freshness check via GroundingService
        if self.grounding_service is not None:
            # 1. Proposal hash check
            current_hash = conf.proposal_hash
            if hasattr(self.grounding_service, "get_proposal"):
                prop = await self.grounding_service.get_proposal(conf.proposal_id)
                current_hash = getattr(prop, "proposal_hash", current_hash)
            elif hasattr(self.grounding_service, "get"):
                prop = await self.grounding_service.get(conf.proposal_id)
                current_hash = getattr(prop, "proposal_hash", current_hash)

            if current_hash != conf.proposal_hash:
                await self._invalidate(
                    session,
                    confirmation_id,
                    conf.proposal_hash,
                    current_hash,
                    code="CONFIRMATION_PROPOSAL_CHANGED",
                    caller_user_id=caller_user_id,
                )
                raise ConfirmationInvalidatedError(
                    "Proposal hash has changed since confirmation was issued",
                    code="CONFIRMATION_PROPOSAL_CHANGED",
                )

            # 2. Checkout expiry check
            verif = None
            if hasattr(self.grounding_service, "latest_verification"):
                verif = await self.grounding_service.latest_verification(conf.proposal_id)
            elif hasattr(self.grounding_service, "verify"):
                verif = await self.grounding_service.verify(conf.proposal_id, refresh=False)

            if verif is not None and getattr(verif, "checkout", None) is not None:
                chk_expires = ensure_tz(verif.checkout.expires_at)
                if chk_expires is not None and chk_expires <= now:
                    await self._invalidate(
                        session,
                        confirmation_id,
                        conf.proposal_hash,
                        current_hash,
                        code="CONFIRMATION_CHECKOUT_EXPIRED",
                        caller_user_id=caller_user_id,
                    )
                    raise ConfirmationInvalidatedError(
                        "Checkout has expired since confirmation was issued",
                        code="CONFIRMATION_CHECKOUT_EXPIRED",
                    )

        # Atomic CAS update to APPROVED
        cas_ok = await self.repository.update_confirmation_status_cas(
            session,
            confirmation_id=confirmation_id,
            expected_status="PENDING",
            new_status="APPROVED",
            response_signature=sig,
            responded_at=now,
        )
        if not cas_ok:
            raise ConfirmationNotPendingError("Confirmation already processed by a concurrent request")

        # Emit CONFIRMATION_APPROVED
        await events.emit(
            session,
            transaction_id=None,
            event_type="CONFIRMATION_APPROVED",
            producer="confirmation",
            actor={"type": "USER", "id": caller_user_id},
            refs={"confirmation_id": confirmation_id, "user_id": caller_user_id},
            payload={
                "challenge": conf.challenge,
                "key_id": key_id,
                "signature_digest": sig.get("signed_digest"),
            },
        )

        # Step 7: Policy Re-evaluation via DecisionService
        conf_snapshot = ConfirmationSnapshot(
            confirmation_id=confirmation_id,
            status="APPROVED",
            proposal_hash=conf.proposal_hash,
            expires_at=conf_exp or now,
            response_signature=sig,
            signature_verified=True,
            responded_at=now,
        )

        re_eval_inputs = await self.decision_service.build_inputs(
            conf.proposal_id,
            session=session,
            confirmation=conf_snapshot,
            evaluated_at=now,
        )
        new_decision = await self.decision_service.evaluate_with_inputs(re_eval_inputs, session=session)

        return ConfirmationRespondResponse(
            confirmation_id=confirmation_id,
            status="APPROVED",
            decision_id=new_decision.decision_id,
            outcome=new_decision.outcome.value if hasattr(new_decision.outcome, "value") else str(new_decision.outcome),
        )
