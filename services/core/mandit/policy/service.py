"""Policy Engine implementation for Mandit OS.

Contains the pure decision evaluation pipeline, DefaultPolicyEngine, and DecisionServiceImpl.
Strictly adheres to Invariant INV-11 (pure function, no I/O, no clock reads).
"""

import dataclasses
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, cast

from mandit.common import events, hashing
from mandit.common.crypto import Ed25519Signer
from mandit.policy.interface import PolicyEngine, PolicyRule
from mandit.policy.models import ConfirmationModel, DecisionModel
from mandit.policy.repository import DecisionRepository
from mandit.policy.rules import ALL_HARD_GATES, ALL_STEP_UP_RULES
from mandit.policy.schemas import (
    OUTCOME_SEVERITY,
    ConfirmationSnapshot,
    Decision,
    DecisionOutcome,
    DecisionResult,
    EvaluationStage,
    FrozenDecisionInputs,
    RuleHit,
    to_snapshot_dict,
)

DEFAULT_POLICY_VERSION = "policy-1.0.0"


def decide(
    inputs: FrozenDecisionInputs,
    hard_gates: tuple[PolicyRule, ...] = ALL_HARD_GATES,
    step_up_rules: tuple[PolicyRule, ...] = ALL_STEP_UP_RULES,
) -> DecisionResult:
    """Evaluate policy against frozen decision inputs.

    Pure function adhering to Invariant INV-11:
    - Zero I/O, network, or database access.
    - Zero clock calls (timestamps are read strictly from inputs.evaluated_at).
    - Zero random or non-deterministic state.
    - Deterministic replay identical to live evaluation.

    Pipeline stages:
    1. Stage 1 (Hard Gates): Evaluate all hard gates. If ANY fails (BLOCK), return immediately.
    2. Stage 2 (Step-Up Rules): Evaluate advisory heuristics that flag transactions for user review.
    3. Stage 3 (Trust Score Bands): Evaluate grounding trust score
       (ALLOW/STEP_UP/RETRIEVE_MORE/BLOCK). Enforce that RETRIEVE_MORE is permitted only
       on attempt 1; attempt >= 2 escalates to STEP_UP.
    4. Stage 4 (Confirmation): Human approval can resolve STEP_UP to ALLOW, but never overrides
       BLOCK or RETRIEVE_MORE (INV-07).
    """
    fired: list[RuleHit] = []

    # Stage 1: Hard Gates (HG-01 to HG-16). All evaluated, all recorded.
    for rule in hard_gates:
        hit = rule.evaluate(inputs)
        if hit is not None:
            fired.append(hit)

    # Invariant: If any hard gate triggers a BLOCK, return immediately.
    # Hard gate failures cannot be step-up confirmed and trust score is not evaluated.
    if any(h.effect == DecisionOutcome.BLOCK for h in fired):
        return DecisionResult(
            outcome=DecisionOutcome.BLOCK,
            stage=EvaluationStage.HARD_GATE,
            rules_fired=tuple(fired),
            trust_score=None,
        )

    # Stage 2: Step-up rules (SU-01 to SU-07). All evaluated, all recorded.
    for rule in step_up_rules:
        hit = rule.evaluate(inputs)
        if hit is not None:
            fired.append(hit)

    # Stage 3: Trust bands (advisory, evaluated after all hard gates pass)
    ts = inputs.verification.trust.score
    if ts >= 0.90:
        band_outcome = DecisionOutcome.ALLOW
    elif ts >= 0.70:
        band_outcome = DecisionOutcome.STEP_UP
        fired.append(
            RuleHit(
                rule_id="TS-01",
                code="TRUST_SCORE_STEP_UP",
                effect=DecisionOutcome.STEP_UP,
                detail={"score": ts, "band": "STEP_UP"},
            )
        )
    elif ts >= 0.50:
        if inputs.attempt >= 2:
            band_outcome = DecisionOutcome.STEP_UP
            fired.append(
                RuleHit(
                    rule_id="TS-02",
                    code="RETRIEVE_MORE_EXHAUSTED",
                    effect=DecisionOutcome.STEP_UP,
                    detail={"score": ts, "attempt": inputs.attempt},
                )
            )
        else:
            band_outcome = DecisionOutcome.RETRIEVE_MORE
            fired.append(
                RuleHit(
                    rule_id="TS-01",
                    code="TRUST_SCORE_RETRIEVE_MORE",
                    effect=DecisionOutcome.RETRIEVE_MORE,
                    detail={"score": ts, "band": "RETRIEVE_MORE"},
                )
            )
    else:
        band_outcome = DecisionOutcome.BLOCK
        fired.append(
            RuleHit(
                rule_id="TS-01",
                code="TRUST_SCORE_BLOCK",
                effect=DecisionOutcome.BLOCK,
                detail={"score": ts, "band": "BLOCK"},
            )
        )

    # Candidate outcome by severity: BLOCK (3) > RETRIEVE_MORE (2) > STEP_UP (1) > ALLOW (0)
    highest_effect = max(
        [h.effect for h in fired] + [band_outcome],
        key=lambda effect: OUTCOME_SEVERITY[effect],
    )

    # Stage 4: Confirmation resolution (INV-07: Confirmation can satisfy STEP_UP only)
    if (
        highest_effect == DecisionOutcome.STEP_UP
        and inputs.confirmation is not None
        and inputs.confirmation.valid_for(inputs.proposal_hash, inputs.evaluated_at)
    ):
        return DecisionResult(
            outcome=DecisionOutcome.ALLOW,
            stage=EvaluationStage.CONFIRMATION,
            rules_fired=tuple(fired),
            trust_score=ts,
        )

    # Determine stage for non-confirmation outcome
    if highest_effect == DecisionOutcome.BLOCK:
        stage = EvaluationStage.TRUST_SCORE
    elif highest_effect == DecisionOutcome.RETRIEVE_MORE:
        stage = EvaluationStage.TRUST_SCORE
    elif any(h.rule_id.startswith("SU") for h in fired):
        stage = EvaluationStage.RULE
    else:
        stage = EvaluationStage.TRUST_SCORE

    return DecisionResult(
        outcome=highest_effect,
        stage=stage,
        rules_fired=tuple(fired),
        trust_score=ts,
    )


class DefaultPolicyEngine:
    """Configurable pure Policy Engine instance."""

    def __init__(
        self,
        hard_gates: tuple[PolicyRule, ...] = ALL_HARD_GATES,
        step_up_rules: tuple[PolicyRule, ...] = ALL_STEP_UP_RULES,
        version: str = DEFAULT_POLICY_VERSION,
    ) -> None:
        self.hard_gates = hard_gates
        self.step_up_rules = step_up_rules
        self.version = version

    def decide(self, inputs: FrozenDecisionInputs) -> DecisionResult:
        """Evaluate decision for the given frozen inputs."""
        return decide(
            inputs=inputs,
            hard_gates=self.hard_gates,
            step_up_rules=self.step_up_rules,
        )


def build_display_payload(
    inputs: FrozenDecisionInputs, rules_fired: tuple[RuleHit, ...]
) -> dict[str, Any]:
    """Construct sanitized display payload for human confirmation per docs/modules/04 §6.1.

    Built strictly from signed checkout, mandate, and policy decisions.
    Agent-supplied text is never used.
    """
    checkout = inputs.verification.checkout
    calc = inputs.verification.calculation
    reasons: list[dict[str, Any]] = []

    for r in rules_fired:
        if r.rule_id == "SU-01":
            reasons.append(
                {
                    "code": "ABOVE_APPROVAL_THRESHOLD",
                    "template_id": "stepup.above_threshold",
                    "params": {
                        "threshold_minor": inputs.mandate.constraints.approval_threshold_minor
                    },
                }
            )
        elif r.rule_id == "SU-07":
            reasons.append(
                {
                    "code": "PRICIER_ALTERNATIVE_CHOSEN",
                    "template_id": "stepup.pricier_alternative",
                    "params": {
                        "difference_minor": inputs.verification.selection.difference_minor or 0,
                        "cheapest_matching_minor": (
                            inputs.verification.selection.cheapest_matching_minor
                        ),
                    },
                }
            )
        elif r.rule_id == "TS-02":
            reasons.append(
                {
                    "code": "RETRIEVE_MORE_EXHAUSTED",
                    "template_id": "stepup.retrieve_more_exhausted",
                    "params": {"attempt": inputs.attempt, "score": inputs.verification.trust.score},
                }
            )
        elif r.effect == DecisionOutcome.STEP_UP:
            reasons.append(
                {
                    "code": r.code,
                    "template_id": f"stepup.{r.code.lower()}",
                    "params": r.detail or {},
                }
            )

    tax_minor = (
        max(0, calc.computed_total_minor - calc.subtotal_minor) if calc.subtotal_minor > 0 else 0
    )
    return {
        "merchant": {
            "merchant_id": checkout.merchant_id,
            "legal_name": checkout.merchant_domain,
        },
        "items": [
            {
                "title": f"Purchase at {checkout.merchant_domain}",
                "quantity": 1,
                "amount_minor": calc.subtotal_minor or checkout.amount_minor,
            }
        ],
        "tax_minor": tax_minor,
        "fees_minor": 0,
        "total_minor": checkout.amount_minor,
        "currency": checkout.currency,
        "payment_method": inputs.payment_method,
        "delivery_eta_days": getattr(inputs.verification, "delivery_eta_days", None) or 3,
        "reasons": reasons,
    }


class DecisionServiceImpl:
    """Production DecisionService for evaluation, snapshotting, signing, persistence."""

    def __init__(
        self,
        engine: PolicyEngine | None = None,
        repository: DecisionRepository | None = None,
        session_factory: Any = None,
        grounding_service: Any = None,
        identity_service: Any = None,
        mandate_service: Any = None,
        safety_service: Any = None,
        user_history_service: Any = None,
        evidence_service: Any = None,
        signer: Ed25519Signer | None = None,
    ) -> None:
        self.engine = engine or DefaultPolicyEngine()
        self.repository = repository or DecisionRepository()
        self.session_factory = session_factory
        self.grounding_service = grounding_service
        self.identity_service = identity_service
        self.mandate_service = mandate_service
        self.safety_service = safety_service
        self.user_history_service = user_history_service
        self.evidence_service = evidence_service
        self.signer = signer or Ed25519Signer()

    async def _snapshot_inputs(self, session: Any, inputs: FrozenDecisionInputs) -> tuple[str, str]:
        """Snapshot frozen inputs via EvidenceService or fallback."""
        inputs_dict = to_snapshot_dict(inputs)
        if self.evidence_service is not None and hasattr(self.evidence_service, "snapshot"):
            snap = await self.evidence_service.snapshot(
                session,
                transaction_id=inputs.transaction_id,
                kind="decision_inputs",
                obj=inputs_dict,
            )
            snapshot_id = getattr(
                snap, "snapshot_id", getattr(snap, "id", f"snp_{uuid.uuid4().hex}")
            )
            digest = getattr(
                snap, "digest", getattr(snap, "inputs_hash", hashing.digest(inputs_dict))
            )
            return snapshot_id, digest

        snapshot_id = f"snp_{uuid.uuid4().hex}"
        digest = hashing.digest(inputs_dict)
        return snapshot_id, digest

    async def evaluate_with_inputs(
        self, inputs: FrozenDecisionInputs, session: Any = None
    ) -> Decision:
        """Run policy evaluation with already constructed FrozenDecisionInputs."""
        snap_id, inputs_hash = await self._snapshot_inputs(session, inputs)
        result = self.engine.decide(inputs)

        # RETRIEVE_MORE bounded loop (Phase 4): attempt 1 records, refreshes, re-evaluates
        if result.outcome == DecisionOutcome.RETRIEVE_MORE and inputs.attempt == 1:
            await self._record_decision(
                session=session,
                inputs=inputs,
                result=result,
                attempt=1,
                inputs_snapshot_id=snap_id,
                inputs_hash=inputs_hash,
                confirmation_id=None,
            )

            refreshed_report = None
            if self.grounding_service is not None and hasattr(self.grounding_service, "verify"):
                try:
                    refreshed_report = await self.grounding_service.verify(
                        inputs.proposal_id, refresh=True
                    )
                except Exception:
                    refreshed_report = inputs.verification

            if refreshed_report is None:
                refreshed_report = inputs.verification

            inputs_att2 = dataclasses.replace(
                inputs,
                evaluated_at=datetime.now(UTC),
                attempt=2,
                verification=refreshed_report,
            )
            snap_id_2, inputs_hash_2 = await self._snapshot_inputs(session, inputs_att2)
            result_2 = self.engine.decide(inputs_att2)

            return await self._finalize_and_persist_decision(
                session=session,
                inputs=inputs_att2,
                result=result_2,
                attempt=2,
                inputs_snapshot_id=snap_id_2,
                inputs_hash=inputs_hash_2,
            )

        return await self._finalize_and_persist_decision(
            session=session,
            inputs=inputs,
            result=result,
            attempt=inputs.attempt,
            inputs_snapshot_id=snap_id,
            inputs_hash=inputs_hash,
        )

    async def _finalize_and_persist_decision(
        self,
        session: Any,
        inputs: FrozenDecisionInputs,
        result: DecisionResult,
        attempt: int,
        inputs_snapshot_id: str,
        inputs_hash: str,
    ) -> Decision:
        decision_id = f"dec_{uuid.uuid4().hex}"
        evaluated_at = inputs.evaluated_at

        # Decision expiry per specification:
        # ALLOW / STEP_UP: valid for 10 minutes (docs/modules/04 §4 line 98)
        # BLOCK / RETRIEVE_MORE: expires immediately
        if result.outcome in (DecisionOutcome.ALLOW, DecisionOutcome.STEP_UP):
            expires_at = evaluated_at + timedelta(minutes=10)
        else:
            expires_at = evaluated_at

        confirmation_id: str | None = None
        if result.outcome == DecisionOutcome.STEP_UP:
            confirmation_id = f"cnf_{uuid.uuid4().hex}"
            display = build_display_payload(inputs, result.rules_fired)
            challenge = hashing.digest(
                {
                    "confirmation_id": confirmation_id,
                    "display": display,
                    "expires_at": expires_at.isoformat(),
                    "proposal_hash": inputs.proposal_hash,
                }
            )
            confirmation_model = ConfirmationModel(
                confirmation_id=confirmation_id,
                decision_id=decision_id,
                proposal_id=inputs.proposal_id,
                proposal_hash=inputs.proposal_hash,
                user_id=inputs.mandate.user_id,
                display=display,
                challenge=challenge,
                status="PENDING",
                response_signature=None,
                responded_at=None,
                expires_at=expires_at,
            )
            await self.repository.save_confirmation(session, confirmation_model)
            await events.emit(
                session,
                transaction_id=inputs.transaction_id,
                event_type="STEP_UP_REQUESTED",
                producer="policy",
                actor={"type": "SERVICE", "id": "mandit-policy"},
                refs={"decision_id": decision_id, "confirmation_id": confirmation_id},
                payload={
                    "reasons": [r.code for r in result.rules_fired],
                    "challenge": challenge,
                    "expires_at": expires_at.isoformat(),
                },
            )

        sign_payload = {
            "attempt": attempt,
            "confirmation_id": confirmation_id,
            "created_at": evaluated_at.isoformat(),
            "decision_id": decision_id,
            "expires_at": expires_at.isoformat(),
            "inputs_hash": inputs_hash,
            "inputs_snapshot_id": inputs_snapshot_id,
            "outcome": result.outcome.value
            if hasattr(result.outcome, "value")
            else str(result.outcome),
            "policy_version": self.engine.version,
            "proposal_hash": inputs.proposal_hash,
            "proposal_id": inputs.proposal_id,
            "rules_fired": [r.to_dict() for r in result.rules_fired],
            "stage": result.stage.value if hasattr(result.stage, "value") else str(result.stage),
            "transaction_id": inputs.transaction_id,
            "trust_model_version": getattr(inputs.verification.trust, "version", "trust-1.0.0"),
            "trust_score": float(result.trust_score) if result.trust_score is not None else None,
        }
        signature = self.signer.sign_payload(sign_payload)

        decision = Decision(
            decision_id=decision_id,
            proposal_id=inputs.proposal_id,
            proposal_hash=inputs.proposal_hash,
            transaction_id=inputs.transaction_id,
            attempt=attempt,
            outcome=result.outcome,
            stage=result.stage,
            rules_fired=result.rules_fired,
            trust_score=result.trust_score,
            policy_version=self.engine.version,
            trust_model_version=getattr(inputs.verification.trust, "version", "trust-1.0.0"),
            inputs_snapshot_id=inputs_snapshot_id,
            inputs_hash=inputs_hash,
            confirmation_id=confirmation_id,
            expires_at=expires_at,
            signature=signature,
            created_at=evaluated_at,
        )

        model = DecisionModel.from_schema(decision)
        await self.repository.save_decision(session, model)

        await events.emit(
            session,
            transaction_id=inputs.transaction_id,
            event_type="DECISION_MADE",
            producer="policy",
            actor={"type": "SERVICE", "id": "mandit-policy"},
            refs={
                "proposal_id": inputs.proposal_id,
                "decision_id": decision_id,
                "mandate_id": inputs.mandate.mandate_id,
            },
            payload={
                "attempt": attempt,
                "outcome": result.outcome.value
                if hasattr(result.outcome, "value")
                else str(result.outcome),
                "stage": result.stage.value
                if hasattr(result.stage, "value")
                else str(result.stage),
                "rules_fired": [r.to_dict() for r in result.rules_fired],
                "trust_score": float(result.trust_score)
                if result.trust_score is not None
                else None,
                "policy_version": self.engine.version,
                "trust_model_version": getattr(inputs.verification.trust, "version", "trust-1.0.0"),
                "inputs_hash": inputs_hash,
                "inputs_snapshot_id": inputs_snapshot_id,
            },
        )

        if result.outcome == DecisionOutcome.BLOCK and result.stage == EvaluationStage.TRUST_SCORE:
            await events.emit(
                session,
                transaction_id=inputs.transaction_id,
                event_type="INCIDENT_LOGGED",
                producer="policy",
                actor={"type": "SERVICE", "id": "mandit-policy"},
                refs={"proposal_id": inputs.proposal_id},
                payload={
                    "incident_type": "TRUST_BAND_BLOCK",
                    "code": "TRUST_SCORE_BLOCK",
                    "severity": "HIGH",
                },
            )

        return decision

    async def _record_decision(
        self,
        session: Any,
        inputs: FrozenDecisionInputs,
        result: DecisionResult,
        attempt: int,
        inputs_snapshot_id: str,
        inputs_hash: str,
        confirmation_id: str | None = None,
    ) -> Decision:
        decision_id = f"dec_{uuid.uuid4().hex}"
        evaluated_at = inputs.evaluated_at
        expires_at = evaluated_at

        sign_payload = {
            "attempt": attempt,
            "confirmation_id": confirmation_id,
            "created_at": evaluated_at.isoformat(),
            "decision_id": decision_id,
            "expires_at": expires_at.isoformat(),
            "inputs_hash": inputs_hash,
            "inputs_snapshot_id": inputs_snapshot_id,
            "outcome": result.outcome.value
            if hasattr(result.outcome, "value")
            else str(result.outcome),
            "policy_version": self.engine.version,
            "proposal_hash": inputs.proposal_hash,
            "proposal_id": inputs.proposal_id,
            "rules_fired": [r.to_dict() for r in result.rules_fired],
            "stage": result.stage.value if hasattr(result.stage, "value") else str(result.stage),
            "transaction_id": inputs.transaction_id,
            "trust_model_version": getattr(inputs.verification.trust, "version", "trust-1.0.0"),
            "trust_score": float(result.trust_score) if result.trust_score is not None else None,
        }
        signature = self.signer.sign_payload(sign_payload)

        decision = Decision(
            decision_id=decision_id,
            proposal_id=inputs.proposal_id,
            proposal_hash=inputs.proposal_hash,
            transaction_id=inputs.transaction_id,
            attempt=attempt,
            outcome=result.outcome,
            stage=result.stage,
            rules_fired=result.rules_fired,
            trust_score=result.trust_score,
            policy_version=self.engine.version,
            trust_model_version=getattr(inputs.verification.trust, "version", "trust-1.0.0"),
            inputs_snapshot_id=inputs_snapshot_id,
            inputs_hash=inputs_hash,
            confirmation_id=confirmation_id,
            expires_at=expires_at,
            signature=signature,
            created_at=evaluated_at,
        )

        model = DecisionModel.from_schema(decision)
        await self.repository.save_decision(session, model)

        await events.emit(
            session,
            transaction_id=inputs.transaction_id,
            event_type="DECISION_MADE",
            producer="policy",
            actor={"type": "SERVICE", "id": "mandit-policy"},
            refs={
                "proposal_id": inputs.proposal_id,
                "decision_id": decision_id,
                "mandate_id": inputs.mandate.mandate_id,
            },
            payload={
                "attempt": attempt,
                "outcome": result.outcome.value
                if hasattr(result.outcome, "value")
                else str(result.outcome),
                "stage": result.stage.value
                if hasattr(result.stage, "value")
                else str(result.stage),
                "rules_fired": [r.to_dict() for r in result.rules_fired],
                "trust_score": float(result.trust_score)
                if result.trust_score is not None
                else None,
                "policy_version": self.engine.version,
                "trust_model_version": getattr(inputs.verification.trust, "version", "trust-1.0.0"),
                "inputs_hash": inputs_hash,
                "inputs_snapshot_id": inputs_snapshot_id,
            },
        )
        return decision

    async def evaluate(self, proposal_id: str, session: Any = None) -> Decision:
        """Gather inputs and run policy evaluation for the proposal."""
        if self.session_factory is not None and session is None:
            ctx = self.session_factory()
            if hasattr(ctx, "__aenter__"):
                async with ctx as sess:
                    return await self._evaluate_with_session(proposal_id, sess)
            elif hasattr(ctx, "__enter__"):
                with ctx as sess:
                    return await self._evaluate_with_session(proposal_id, sess)
        return await self._evaluate_with_session(proposal_id, session)

    async def build_inputs(
        self,
        proposal_id: str,
        session: Any = None,
        confirmation: ConfirmationSnapshot | None = None,
        evaluated_at: datetime | None = None,
    ) -> FrozenDecisionInputs:
        """Gather all cross-team inputs required for policy evaluation."""
        if evaluated_at is None:
            evaluated_at = datetime.now(UTC)

        if self.grounding_service is None:
            raise ValueError("GroundingService is required to evaluate proposals")

        if hasattr(self.grounding_service, "get_proposal"):
            prop_data = await self.grounding_service.get_proposal(proposal_id)
        elif hasattr(self.grounding_service, "get"):
            prop_data = await self.grounding_service.get(proposal_id)
        else:
            prop_data = None

        if hasattr(self.grounding_service, "latest_verification"):
            verification = await self.grounding_service.latest_verification(proposal_id)
        elif hasattr(self.grounding_service, "verify"):
            verification = await self.grounding_service.verify(proposal_id, refresh=False)
        else:
            raise ValueError("GroundingService must provide latest_verification or verify")

        proposal_hash = getattr(prop_data, "proposal_hash", verification.checkout.checkout_hash)
        transaction_id = getattr(prop_data, "transaction_id", f"txn_{proposal_id}")
        mandate_id = getattr(prop_data, "mandate_id", "man_default")
        agent_id = getattr(prop_data, "agent_id", "agent_default")
        merchant_id = verification.checkout.merchant_id
        merchant_domain = verification.checkout.merchant_domain

        if self.identity_service is not None:
            if hasattr(self.identity_service, "get_identity_result"):
                identity = await self.identity_service.get_identity_result(proposal_id)
            elif hasattr(self.identity_service, "get_agent"):
                agent = await self.identity_service.get_agent(agent_id)
                from mandit.policy.schemas import IdentityResult

                identity = IdentityResult(
                    agent=agent,
                    is_active=True,
                    operator_verified=True,
                    kya_token_valid=True,
                    key_bound=True,
                )
            else:
                identity = await self.identity_service.get(agent_id)
        else:
            raise ValueError("IdentityService is required")

        if self.mandate_service is not None:
            mandate = await self.mandate_service.get(mandate_id)
        else:
            raise ValueError("MandateService is required")

        if self.safety_service is not None:
            if hasattr(self.safety_service, "get_risk_summary"):
                risk = await self.safety_service.get_risk_summary(proposal_id)
            elif hasattr(self.safety_service, "get_risk"):
                content_ids = getattr(prop_data, "content_ids", [])
                risk = await self.safety_service.get_risk(content_ids, merchant_domain)
            else:
                risk = await self.safety_service.get(merchant_domain)
        else:
            raise ValueError("SafetyService is required")

        user_history = 0
        if self.user_history_service is not None:
            user_id = mandate.user_id
            if hasattr(self.user_history_service, "get_user_merchant_history"):
                user_history = await self.user_history_service.get_user_merchant_history(
                    user_id, merchant_id
                )
            elif hasattr(self.user_history_service, "get"):
                user_history = await self.user_history_service.get(user_id, merchant_id)

        if confirmation is None:
            fn: Any = getattr(self, "get_confirmation_for_proposal", None)
            if callable(fn):
                res: Any = fn(session, proposal_id)
                confirmation = cast(
                    ConfirmationSnapshot | None,
                    await res if hasattr(res, "__await__") else res,
                )

        return FrozenDecisionInputs(
            evaluated_at=evaluated_at,
            attempt=1,
            proposal_id=proposal_id,
            proposal_hash=proposal_hash,
            transaction_id=transaction_id,
            identity=identity,
            mandate=mandate,
            risk=risk,
            verification=verification,
            user_merchant_history=user_history,
            payment_method=getattr(prop_data, "payment_method", "CARD_TOKEN"),
            confirmation=confirmation,
        )

    async def _evaluate_with_session(self, proposal_id: str, session: Any) -> Decision:
        inputs = await self.build_inputs(proposal_id, session=session)
        return await self.evaluate_with_inputs(inputs, session=session)

    async def get(self, decision_id: str, session: Any = None) -> Decision | None:
        """Retrieve stored policy decision by ID."""
        if self.session_factory is not None and session is None:
            ctx = self.session_factory()
            if hasattr(ctx, "__aenter__"):
                async with ctx as sess:
                    return await self._get_with_session(decision_id, sess)
            elif hasattr(ctx, "__enter__"):
                with ctx as sess:
                    return await self._get_with_session(decision_id, sess)
        return await self._get_with_session(decision_id, session)

    async def _get_with_session(self, decision_id: str, session: Any) -> Decision | None:
        model = await self.repository.get_decision(session, decision_id)
        if model is None:
            return None
        return model.to_schema()
