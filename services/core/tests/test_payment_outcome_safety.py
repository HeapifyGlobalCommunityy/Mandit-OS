"""Regression tests: a payment is never marked FAILED (and its spend released) unless the PSP
definitely did not act; the charge is bound to the approved proposal and verified checkout;
reconciliation resolves payments whose PSP answer was lost.

Per docs/modules/04-policy-and-payments.md §8.1 and §8.2.
"""

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
import test_payment_orchestrator as orchestrator_tests
from sqlalchemy import select

from mandit.payments.models import PaymentModel
from mandit.payments.psp_client import (
    HttpPspClient,
    PspConnectionError,
    PspInvalidResponseError,
    PspOutcomeUnknownError,
    PspPaymentStatusResponse,
    PspResponseError,
    PspServerError,
)
from mandit.payments.schemas import PaymentStatus
from mandit.payments.service import CheckoutChangedError, PaymentError
from mandit.tokens.models import PaymentTokenModel

# Reuse the orchestrator test doubles and fixtures.
MockPspClient = orchestrator_tests.MockPspClient
db_session = orchestrator_tests.db_session
orchestrator_setup = orchestrator_tests.orchestrator_setup


class FailingAuthorizePspClient(MockPspClient):
    """Mock PSP whose authorize call raises a given exception."""

    def __init__(self, error: Exception) -> None:
        super().__init__()
        self.error = error

    async def authorize_card(self, req: Any) -> Any:
        raise self.error


async def _stored_payment(db_session: Any, payment_id: str) -> PaymentModel:
    res = await db_session.execute(
        select(PaymentModel).where(PaymentModel.payment_id == payment_id)
    )
    return res.scalar_one()


# --- Ambiguous PSP outcomes keep the spend reserved -------------------------------------


@pytest.mark.anyio
@pytest.mark.parametrize(
    "error",
    [
        PspOutcomeUnknownError("connection dropped after the request was sent"),
        PspServerError("PSP responded with status 503", status_code=503, error_code="PSP_ERROR"),
        PspInvalidResponseError("Invalid JSON response from PSP"),
        RuntimeError("internal detail that must not leak"),
    ],
    ids=["broken-off", "5xx", "unreadable-2xx", "unexpected"],
)
async def test_ambiguous_psp_failure_is_unknown_and_keeps_spend(
    orchestrator_setup, db_session, error
):
    orch = orchestrator_setup["orchestrator"]
    orch.psp_client = FailingAuthorizePspClient(error)
    mandate_client = orchestrator_setup["mandate_client"]

    resp = await orch.execute("prop_test_001", "idem_ambiguous", session=db_session)

    assert resp.status == PaymentStatus.UNKNOWN
    assert mandate_client.released_reservations == []
    assert mandate_client.committed_reservations == []
    stored = await _stored_payment(db_session, resp.payment_id)
    assert stored.failure_code in ("PSP_COMMUNICATION_ERROR", "PSP_TIMEOUT")
    assert "internal detail" not in (stored.failure_code or "")


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("error", "code"),
    [
        (
            PspResponseError("declined", status_code=402, error_code="INSUFFICIENT_FUNDS"),
            "INSUFFICIENT_FUNDS",
        ),
        (PspConnectionError("connection refused"), "PSP_COMMUNICATION_ERROR"),
    ],
    ids=["4xx", "never-connected"],
)
async def test_definite_psp_failure_is_failed_and_releases_spend(
    orchestrator_setup, db_session, error, code
):
    orch = orchestrator_setup["orchestrator"]
    orch.psp_client = FailingAuthorizePspClient(error)
    mandate_client = orchestrator_setup["mandate_client"]

    resp = await orch.execute("prop_test_001", "idem_definite", session=db_session)

    assert resp.status == PaymentStatus.FAILED
    assert mandate_client.released_reservations == ["res_test_001"]
    stored = await _stored_payment(db_session, resp.payment_id)
    assert stored.failure_code == code


# --- HTTP client: which transport failures are ambiguous ---------------------------------


def _http_client(handler: Any) -> HttpPspClient:
    return HttpPspClient(
        base_url="http://psp.test",
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("handler", "expected", "ambiguous"),
    [
        (lambda r: (_ for _ in ()).throw(httpx.ReadError("reset", request=r)), None, True),
        (
            lambda r: (_ for _ in ()).throw(httpx.ConnectError("refused", request=r)),
            PspConnectionError,
            False,
        ),
        (lambda r: httpx.Response(503, json={"code": "DOWN"}), PspServerError, True),
        (lambda r: httpx.Response(402, json={"code": "DECLINED"}), PspResponseError, False),
        (lambda r: httpx.Response(200, content=b"not json"), PspInvalidResponseError, True),
    ],
    ids=["read-error", "connect-error", "503", "402", "bad-json"],
)
async def test_http_client_classifies_failures(handler, expected, ambiguous):
    client = _http_client(handler)
    with pytest.raises(Exception) as exc_info:
        await client.get_payment_status("psp_x")
    if expected is not None:
        assert isinstance(exc_info.value, expected)
    assert isinstance(exc_info.value, PspOutcomeUnknownError) is ambiguous


@pytest.mark.anyio
async def test_http_client_find_payment_by_idempotency_key():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/psp/v1/payments"
        if request.url.params["idempotency_key"] == "pay_1:auth":
            return httpx.Response(
                200,
                json={
                    "psp_payment_id": "psp_1",
                    "status": "CAPTURED",
                    "amount_minor": 500000,
                    "currency": "INR",
                    "merchant_id": "mer_croma",
                },
            )
        return httpx.Response(404, json={"detail": {"code": "PAYMENT_NOT_FOUND"}})

    client = _http_client(handler)
    found = await client.find_payment_by_idempotency_key("pay_1:auth")
    assert found is not None and found.psp_payment_id == "psp_1"
    assert await client.find_payment_by_idempotency_key("pay_2:auth") is None


# --- The charge is bound to the approved proposal and verified checkout --------------------


@pytest.mark.anyio
@pytest.mark.parametrize("side", ["proposal", "checkout"])
async def test_missing_checkout_hash_refuses(orchestrator_setup, db_session, side):
    grounding = orchestrator_setup["grounding_client"]
    getattr(grounding, side).checkout_hash = None
    with pytest.raises(CheckoutChangedError):
        await orchestrator_setup["orchestrator"].execute(
            "prop_test_001", "idem_nohash", session=db_session
        )
    assert orchestrator_setup["token_service"].issued_tokens == []


@pytest.mark.anyio
async def test_decision_for_other_proposal_version_refuses(orchestrator_setup, db_session):
    orchestrator_setup["decision_provider"].decision.proposal_hash = "sha256:older_proposal"
    with pytest.raises(CheckoutChangedError):
        await orchestrator_setup["orchestrator"].execute(
            "prop_test_001", "idem_stale", session=db_session
        )
    assert orchestrator_setup["token_service"].issued_tokens == []


@pytest.mark.anyio
@pytest.mark.parametrize("field", ["amount_minor", "currency", "merchant_id"])
async def test_checkout_without_money_fields_refuses(orchestrator_setup, db_session, field):
    setattr(orchestrator_setup["grounding_client"].checkout, field, None)
    with pytest.raises(PaymentError) as exc_info:
        await orchestrator_setup["orchestrator"].execute(
            "prop_test_001", "idem_nofield", session=db_session
        )
    assert exc_info.value.code == "CHECKOUT_CHANGED"


@pytest.mark.anyio
async def test_unknown_rail_refuses(orchestrator_setup, db_session):
    orchestrator_setup["grounding_client"].proposal.rail = "WIRE"
    with pytest.raises(PaymentError) as exc_info:
        await orchestrator_setup["orchestrator"].execute(
            "prop_test_001", "idem_rail", session=db_session
        )
    assert exc_info.value.code == "VALIDATION_ERROR"


@pytest.mark.anyio
async def test_token_amount_mismatch_refuses_and_releases(orchestrator_setup, db_session):
    # The mock token carries 500000; the verified checkout now says 400000.
    orchestrator_setup["grounding_client"].checkout.amount_minor = 400000
    with pytest.raises(CheckoutChangedError):
        await orchestrator_setup["orchestrator"].execute(
            "prop_test_001", "idem_tokamt", session=db_session
        )
    assert orchestrator_setup["mandate_client"].released_reservations == ["res_test_001"]


# --- Reconciliation of payments whose PSP answer was lost --------------------------------


class LookupPspClient(MockPspClient):
    """Mock PSP that knows payments by idempotency key."""

    def __init__(self, by_key: dict[str, str]) -> None:
        super().__init__()
        self.by_key = by_key
        self.lookups: list[str] = []

    async def find_payment_by_idempotency_key(self, key: str) -> Any:
        self.lookups.append(key)
        status = self.by_key.get(key)
        if status is None:
            return None
        return PspPaymentStatusResponse(
            psp_payment_id=f"psp_for_{key}",
            status=status,
            amount_minor=500000,
            currency="INR",
            merchant_id="mer_croma",
        )


def _add_lost_payment(
    db_session: Any, payment_id: str, status: PaymentStatus, token_expires_at: datetime
) -> None:
    old = datetime.now(UTC) - timedelta(minutes=1)
    db_session.add(
        PaymentModel(
            payment_id=payment_id,
            proposal_id=f"prop_{payment_id}",
            token_id=f"ptok_{payment_id}",
            rail="CARD",
            psp_payment_id=None,
            status=status.value,
            amount_minor=500000,
            currency="INR",
            created_at=old,
            updated_at=old,
        )
    )
    db_session.add(
        PaymentTokenModel(
            token_id=f"ptok_{payment_id}",
            proposal_id=f"prop_{payment_id}",
            decision_id="dec_test_001",
            mandate_id="man_test_001",
            reservation_id=f"res_{payment_id}",
            merchant_id="mer_croma",
            payee_id="acq_croma_001",
            amount_minor=500000,
            currency="INR",
            checkout_hash="sha256:checkout_hash_abc",
            rail="CARD",
            status="ISSUED",
            expires_at=token_expires_at,
            issued_at=old,
        )
    )


@pytest.mark.anyio
@pytest.mark.parametrize("status", [PaymentStatus.UNKNOWN, PaymentStatus.CREATED])
async def test_reconcile_finds_lost_payment_by_idempotency_key(
    orchestrator_setup, db_session, status
):
    orch = orchestrator_setup["orchestrator"]
    orch.psp_client = LookupPspClient({"pay_lost:auth": "CAPTURED"})
    _add_lost_payment(db_session, "pay_lost", status, datetime.now(UTC) + timedelta(minutes=5))

    reconciled = await orch.reconcile(timeout_threshold_seconds=15, session=db_session)

    assert [r.status for r in reconciled] == [PaymentStatus.CAPTURED]
    assert orchestrator_setup["mandate_client"].committed_reservations == ["res_pay_lost"]
    stored = await _stored_payment(db_session, "pay_lost")
    assert stored.psp_payment_id == "psp_for_pay_lost:auth"


@pytest.mark.anyio
async def test_reconcile_fails_lost_payment_only_after_token_expiry(orchestrator_setup, db_session):
    orch = orchestrator_setup["orchestrator"]
    orch.psp_client = LookupPspClient({})
    mandate_client = orchestrator_setup["mandate_client"]
    now = datetime.now(UTC)
    _add_lost_payment(db_session, "pay_live", PaymentStatus.UNKNOWN, now + timedelta(minutes=5))
    _add_lost_payment(db_session, "pay_dead", PaymentStatus.UNKNOWN, now - timedelta(minutes=1))

    reconciled = await orch.reconcile(timeout_threshold_seconds=15, session=db_session)

    # The expired token can no longer charge: that payment failed and its spend is released.
    assert [(r.payment_id, r.status) for r in reconciled] == [("pay_dead", PaymentStatus.FAILED)]
    assert mandate_client.released_reservations == ["res_pay_dead"]
    # The live token could still arrive at the PSP: keep it UNKNOWN with spend reserved.
    assert (await _stored_payment(db_session, "pay_live")).status == PaymentStatus.UNKNOWN.value
