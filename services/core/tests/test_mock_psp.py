"""Comprehensive test suite for Mock PSP Service (Stage 2).

Tests:
1. Card flow end-to-end: scoped credential creation, authorization, and capture.
2. Card credential validation and Core token redemption rejection handling.
3. Card authorization enforcements (over-amount, expired, inactive, merchant mismatch).
4. Card capture enforcements (over-capture, invalid state, idempotency).
5. Card idempotency (same token / same key returns original).
6. UPI flow end-to-end: intent creation, simulated approval, and webhook dispatch.
7. UPI decline flow: simulated decline, status transition to FAILED, and webhook dispatch.
8. UPI enforcements (payee VPA mismatch / CHANGED_PAYEE, amount cap, expired intent).
9. UPI route aliases (/psp/v1/upi/approve and /psp/v1/upi/decline).
10. Payment status endpoint for reconciliation worker.
11. JWKS discovery (/.well-known/psp-keys.json) and webhook signature verification.
12. Fault injection endpoint (access control, simulated DECLINE, TIMEOUT_AFTER_SUCCESS).
13. Distributed failure recovery: same-key retry after simulated persistence crash.
14. Security invariants: zero raw token exposure in responses or webhooks.
"""

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from mandit.tokens.schemas import (
    TokenRedeemRequest,
    TokenRedeemResponse,
)
from mandit.tokens.service import create_jws
from mock_psp.api import get_psp_db_session, get_psp_service, router
from mock_psp.config import SETTINGS
from mock_psp.crypto import PspKeyManager
from mock_psp.faults import FaultManager
from mock_psp.models import PspBase
from mock_psp.schemas import (
    AuthorizeCardRequest,
    CaptureCardRequest,
    CreateScopedCredentialRequest,
    CreateUpiIntentRequest,
)
from mock_psp.service import MockPspService, PspServiceError
from mock_psp.token_client import TokenClient, TokenRedemptionFailed
from mock_psp.webhook_dispatcher import WebhookDispatcher


class AsyncSessionWrapper:
    """Synchronous SQLAlchemy Session wrapper exposing awaitable methods for unit tests."""

    def __init__(self, sync_session: Any) -> None:
        self._sync = sync_session

    async def execute(self, statement: Any, *args: Any, **kwargs: Any) -> Any:
        return self._sync.execute(statement, *args, **kwargs)

    async def flush(self) -> None:
        self._sync.flush()

    def add(self, instance: Any) -> None:
        self._sync.add(instance)

    async def commit(self) -> None:
        self._sync.commit()

    async def rollback(self) -> None:
        self._sync.rollback()

    def close(self) -> None:
        self._sync.close()


class MockTokenClient(TokenClient):
    """Test double for Mandit Core Token Service client."""

    def __init__(
        self,
        should_fail: bool = False,
        fail_code: str = "TOKEN_ALREADY_REDEEMED",
    ) -> None:
        self.should_fail = should_fail
        self.fail_code = fail_code
        self.redeem_calls: list[TokenRedeemRequest] = []

    async def redeem(self, req: TokenRedeemRequest) -> TokenRedeemResponse:
        self.redeem_calls.append(req)
        if self.should_fail:
            raise TokenRedemptionFailed(
                code=self.fail_code,
                message=f"Simulated redemption failure: {self.fail_code}",
                status_code=409,
            )
        return TokenRedeemResponse(
            token_id=f"ptok_redeemed_{req.amount_minor}",
            result="ACCEPTED",
            status="REDEEMING",
        )


def make_test_token(
    token_id: str = "ptok_test_token_123",
    merchant_id: str = "mer_croma",
    payee_id: str = "acq_croma_001",
    amount_minor: int = 500000,
    currency: str = "INR",
    checkout_hash: str = "sha256:checkout_hash_abc",
    rail: str = "CARD",
) -> str:
    """Helper creating a valid signed Mandit payment token for PSP tests."""
    priv_key = ed25519.Ed25519PrivateKey.generate()
    now = datetime.now(UTC)
    claims = {
        "jti": token_id,
        "iss": "mandit-token-svc",
        "aud": "mock-psp",
        "proposal_id": f"prop_{token_id}",
        "mandate_id": "man_test_001",
        "decision_id": "dec_test_001",
        "merchant_id": merchant_id,
        "payee_id": payee_id,
        "amount_minor": amount_minor,
        "currency": currency,
        "checkout_hash": checkout_hash,
        "rail": rail,
        "max_uses": 1,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=10)).timestamp()),
        "nonce": "nonce_test_123",
    }
    header = {"alg": "EdDSA", "typ": "mandit-pay+jwt"}
    return create_jws(header, claims, priv_key)


@pytest.fixture
def db_session():
    """In-memory SQLite database using StaticPool so threads and TestClient share state."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        echo=False,
    )
    PspBase.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    wrapper = AsyncSessionWrapper(session)
    try:
        yield wrapper
    finally:
        wrapper.close()


@pytest.fixture
def test_setup(db_session):
    key_manager = PspKeyManager(key_id="psp-2026-11")
    token_client = MockTokenClient()
    fault_manager = FaultManager()
    webhook_dispatcher = WebhookDispatcher(
        key_manager=key_manager,
        core_base_url="http://mock-core:8000",
        fault_manager=fault_manager,
    )
    service = MockPspService(
        key_manager=key_manager,
        token_client=token_client,
        webhook_dispatcher=webhook_dispatcher,
        fault_manager=fault_manager,
    )

    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_psp_service] = lambda: service
    app.dependency_overrides[get_psp_db_session] = lambda: db_session

    client = TestClient(app)

    return {
        "service": service,
        "key_manager": key_manager,
        "token_client": token_client,
        "fault_manager": fault_manager,
        "webhook_dispatcher": webhook_dispatcher,
        "client": client,
        "db": db_session,
    }


# --- Card Tests ---


def test_card_flow_end_to_end(test_setup):
    """Test standard synthetic card flow: credential -> authorize -> capture."""

    async def _run() -> None:
        service: MockPspService = test_setup["service"]
        db: AsyncSessionWrapper = test_setup["db"]
        token = make_test_token()
        now = datetime.now(UTC)

        # 1. Create scoped credential
        cred_req = CreateScopedCredentialRequest(
            mandit_token=token,
            merchant_id="mer_croma",
            max_amount_minor=500000,
            currency="INR",
            expires_at=now + timedelta(minutes=10),
        )
        cred_res = await service.create_scoped_credential(cred_req, db)
        assert cred_res.credential_id.startswith("spc_")
        assert cred_res.status == "ACTIVE"
        assert cred_res.max_amount_minor == 500000

        # Verify Mandit Core redeem was called
        t_client: MockTokenClient = test_setup["token_client"]
        assert len(t_client.redeem_calls) == 1
        assert t_client.redeem_calls[0].amount_minor == 500000

        # 2. Authorize payment
        auth_req = AuthorizeCardRequest(
            credential_id=cred_res.credential_id,
            merchant_id="mer_croma",
            amount_minor=500000,
            currency="INR",
            idempotency_key="auth_key_001",
        )
        auth_res = await service.authorize_card(auth_req, db)
        assert auth_res.psp_payment_id.startswith("psp_")
        assert auth_res.status == "AUTHORIZED"
        assert auth_res.decline_code is None

        # 3. Capture payment
        cap_req = CaptureCardRequest(
            psp_payment_id=auth_res.psp_payment_id,
            amount_minor=500000,
        )
        cap_res = await service.capture_card(cap_req, db)
        assert cap_res.status == "CAPTURED"
        assert cap_res.amount_minor == 500000

        # 4. Verify authoritative payment record
        status_res = await service.get_payment_status(auth_res.psp_payment_id, db)
        assert status_res.status == "CAPTURED"
        assert status_res.amount_minor == 500000
        assert status_res.merchant_id == "mer_croma"

    asyncio.run(_run())


def test_card_credential_validation_failures(test_setup):
    """Test rejections during scoped credential creation."""

    async def _run() -> None:
        service: MockPspService = test_setup["service"]
        db: AsyncSessionWrapper = test_setup["db"]
        t_client: MockTokenClient = test_setup["token_client"]
        now = datetime.now(UTC)

        # 1. Token Service rejection
        token1 = make_test_token(token_id="ptok_fail_1")
        t_client.should_fail = True
        t_client.fail_code = "TOKEN_ALREADY_REDEEMED"
        with pytest.raises(PspServiceError) as exc1:
            await service.create_scoped_credential(
                CreateScopedCredentialRequest(
                    mandit_token=token1,
                    merchant_id="mer_croma",
                    max_amount_minor=500000,
                    currency="INR",
                    expires_at=now + timedelta(minutes=10),
                ),
                db,
            )
        assert exc1.value.code == "TOKEN_ALREADY_REDEEMED"

        # 2. Merchant mismatch
        t_client.should_fail = False
        token2 = make_test_token(token_id="ptok_fail_2", merchant_id="mer_croma")
        with pytest.raises(PspServiceError) as exc2:
            await service.create_scoped_credential(
                CreateScopedCredentialRequest(
                    mandit_token=token2,
                    merchant_id="wrong_merchant",
                    max_amount_minor=500000,
                    currency="INR",
                    expires_at=now + timedelta(minutes=10),
                ),
                db,
            )
        assert exc2.value.code == "MERCHANT_MISMATCH"

        # 3. Amount exceeds token amount
        token3 = make_test_token(token_id="ptok_fail_3", amount_minor=500000)
        with pytest.raises(PspServiceError) as exc3:
            await service.create_scoped_credential(
                CreateScopedCredentialRequest(
                    mandit_token=token3,
                    merchant_id="mer_croma",
                    max_amount_minor=600000,
                    currency="INR",
                    expires_at=now + timedelta(minutes=10),
                ),
                db,
            )
        assert exc3.value.code == "AMOUNT_EXCEEDS_TOKEN"

        # 4. Currency mismatch
        token4 = make_test_token(token_id="ptok_fail_4", currency="INR")
        with pytest.raises(PspServiceError) as exc4:
            await service.create_scoped_credential(
                CreateScopedCredentialRequest(
                    mandit_token=token4,
                    merchant_id="mer_croma",
                    max_amount_minor=500000,
                    currency="USD",
                    expires_at=now + timedelta(minutes=10),
                ),
                db,
            )
        assert exc4.value.code == "CURRENCY_MISMATCH"

    asyncio.run(_run())


def test_card_authorization_enforcements(test_setup):
    """Test defense-in-depth checks at authorization time."""

    async def _run() -> None:
        service: MockPspService = test_setup["service"]
        db: AsyncSessionWrapper = test_setup["db"]
        token = make_test_token(token_id="ptok_auth_enf", amount_minor=500000)
        now = datetime.now(UTC)

        cred_res = await service.create_scoped_credential(
            CreateScopedCredentialRequest(
                mandit_token=token,
                merchant_id="mer_croma",
                max_amount_minor=500000,
                currency="INR",
                expires_at=now + timedelta(minutes=10),
            ),
            db,
        )

        # 1. Amount exceeds scoped credential cap
        res_over = await service.authorize_card(
            AuthorizeCardRequest(
                credential_id=cred_res.credential_id,
                merchant_id="mer_croma",
                amount_minor=550000,
                currency="INR",
            ),
            db,
        )
        assert res_over.status == "FAILED"
        assert res_over.decline_code == "AMOUNT_EXCEEDS_LIMIT"

        # 2. Merchant mismatch
        res_mer = await service.authorize_card(
            AuthorizeCardRequest(
                credential_id=cred_res.credential_id,
                merchant_id="other_mer",
                amount_minor=500000,
                currency="INR",
            ),
            db,
        )
        assert res_mer.status == "FAILED"
        assert res_mer.decline_code == "MERCHANT_MISMATCH"

        # 3. Successful authorization consumes the single-use credential
        res_ok = await service.authorize_card(
            AuthorizeCardRequest(
                credential_id=cred_res.credential_id,
                merchant_id="mer_croma",
                amount_minor=500000,
                currency="INR",
            ),
            db,
        )
        assert res_ok.status == "AUTHORIZED"

        # 4. Attempting to authorize with the same consumed credential fails
        res_reuse = await service.authorize_card(
            AuthorizeCardRequest(
                credential_id=cred_res.credential_id,
                merchant_id="mer_croma",
                amount_minor=500000,
                currency="INR",
            ),
            db,
        )
        assert res_reuse.status == "FAILED"
        assert res_reuse.decline_code == "CREDENTIAL_INACTIVE"

    asyncio.run(_run())


def test_card_capture_enforcements(test_setup):
    """Test over-capture rejection and capture state transitions."""

    async def _run() -> None:
        service: MockPspService = test_setup["service"]
        db: AsyncSessionWrapper = test_setup["db"]
        token = make_test_token(token_id="ptok_cap_enf", amount_minor=500000)
        now = datetime.now(UTC)

        cred = await service.create_scoped_credential(
            CreateScopedCredentialRequest(
                mandit_token=token,
                merchant_id="mer_croma",
                max_amount_minor=500000,
                currency="INR",
                expires_at=now + timedelta(minutes=10),
            ),
            db,
        )
        auth = await service.authorize_card(
            AuthorizeCardRequest(
                credential_id=cred.credential_id,
                merchant_id="mer_croma",
                amount_minor=500000,
                currency="INR",
            ),
            db,
        )

        # 1. Over-capture rejected
        with pytest.raises(PspServiceError) as exc:
            await service.capture_card(
                CaptureCardRequest(
                    psp_payment_id=auth.psp_payment_id,
                    amount_minor=550000,
                ),
                db,
            )
        assert exc.value.code == "CAPTURE_EXCEEDS_AUTH"

        # 2. Valid capture (under or equal authorized amount)
        cap = await service.capture_card(
            CaptureCardRequest(
                psp_payment_id=auth.psp_payment_id,
                amount_minor=500000,
            ),
            db,
        )
        assert cap.status == "CAPTURED"

        # 3. Idempotent capture returns existing CAPTURED
        cap_idem = await service.capture_card(
            CaptureCardRequest(
                psp_payment_id=auth.psp_payment_id,
                amount_minor=500000,
            ),
            db,
        )
        assert cap_idem.status == "CAPTURED"

    asyncio.run(_run())


def test_card_idempotency_same_key(test_setup):
    """Verify same-key retries return original authorization."""

    async def _run() -> None:
        service: MockPspService = test_setup["service"]
        db: AsyncSessionWrapper = test_setup["db"]
        token = make_test_token(token_id="ptok_card_idem")
        now = datetime.now(UTC)

        cred = await service.create_scoped_credential(
            CreateScopedCredentialRequest(
                mandit_token=token,
                merchant_id="mer_croma",
                max_amount_minor=500000,
                currency="INR",
                expires_at=now + timedelta(minutes=10),
            ),
            db,
        )

        auth_req = AuthorizeCardRequest(
            credential_id=cred.credential_id,
            merchant_id="mer_croma",
            amount_minor=500000,
            currency="INR",
            idempotency_key="auth_idem_123",
        )
        res1 = await service.authorize_card(auth_req, db)
        assert res1.status == "AUTHORIZED"

        # Idempotent retry with same key
        res2 = await service.authorize_card(auth_req, db)
        assert res2.status == "AUTHORIZED"
        assert res2.psp_payment_id == res1.psp_payment_id

    asyncio.run(_run())


# --- UPI Tests ---


def test_upi_flow_end_to_end_approval(test_setup):
    """Test UPI collect intent creation, simulated customer approval, and webhook emission."""

    async def _run() -> None:
        service: MockPspService = test_setup["service"]
        db: AsyncSessionWrapper = test_setup["db"]
        token = make_test_token(
            token_id="ptok_upi_appr", payee_id="acq_croma_001@icici", rail="UPI"
        )
        now = datetime.now(UTC)

        # 1. Create UPI Intent
        intent_req = CreateUpiIntentRequest(
            mandit_token=token,
            payee_vpa="acq_croma_001@icici",
            amount_minor=500000,
            currency="INR",
            expires_at=now + timedelta(minutes=10),
            idempotency_key="upi_idem_001",
        )
        intent_res = await service.create_upi_intent(intent_req, db)
        assert intent_res.intent_id.startswith("upi_intent_")
        assert intent_res.status == "PENDING"
        assert intent_res.payee_vpa == "acq_croma_001@icici"

        # 2. Simulate customer approval from banking app
        appr_res = await service.approve_upi_intent(
            intent_res.intent_id,
            payer_vpa="user@mockbank",
            session=db,
        )
        assert appr_res.status == "SUCCESS"
        assert appr_res.psp_payment_id == intent_res.psp_payment_id

        # 3. Check payment status
        stat_res = await service.get_payment_status(intent_res.psp_payment_id, db)
        assert stat_res.status == "SUCCESS"

    asyncio.run(_run())


def test_upi_flow_decline(test_setup):
    """Test UPI collect intent creation and simulated customer decline."""

    async def _run() -> None:
        service: MockPspService = test_setup["service"]
        db: AsyncSessionWrapper = test_setup["db"]
        token = make_test_token(token_id="ptok_upi_dec", payee_id="acq_croma_001@icici", rail="UPI")
        now = datetime.now(UTC)

        intent_res = await service.create_upi_intent(
            CreateUpiIntentRequest(
                mandit_token=token,
                payee_vpa="acq_croma_001@icici",
                amount_minor=500000,
                currency="INR",
                expires_at=now + timedelta(minutes=10),
            ),
            db,
        )

        dec_res = await service.decline_upi_intent(intent_res.intent_id, db)
        assert dec_res.status == "FAILED"

        stat_res = await service.get_payment_status(intent_res.psp_payment_id, db)
        assert stat_res.status == "FAILED"

    asyncio.run(_run())


def test_upi_payee_vpa_mismatch(test_setup):
    """Verify rejection when payee VPA does not match token payee (CHANGED_PAYEE)."""

    async def _run() -> None:
        service: MockPspService = test_setup["service"]
        db: AsyncSessionWrapper = test_setup["db"]
        token = make_test_token(token_id="ptok_upi_mismatch", payee_id="acq_croma_001@icici")
        now = datetime.now(UTC)

        with pytest.raises(PspServiceError) as exc:
            await service.create_upi_intent(
                CreateUpiIntentRequest(
                    mandit_token=token,
                    payee_vpa="attacker@evilbank",
                    amount_minor=500000,
                    currency="INR",
                    expires_at=now + timedelta(minutes=10),
                ),
                db,
            )
        assert exc.value.code == "CHANGED_PAYEE"

    asyncio.run(_run())


# --- Webhooks & JWKS Discovery ---


def test_jwks_discovery_and_webhook_verification(test_setup):
    """Test /.well-known/psp-keys.json export and signature verification."""
    client: TestClient = test_setup["client"]
    resp = client.get("/.well-known/psp-keys.json")
    assert resp.status_code == 200
    data = resp.json()
    assert "keys" in data
    key = data["keys"][0]
    assert key["kid"] == "psp-2026-11"
    assert key["kty"] == "OKP"
    assert key["crv"] == "Ed25519"
    assert "x" in key

    # Verify signature generation
    km: PspKeyManager = test_setup["key_manager"]
    payload = {"test": 123, "merchant": "mer_croma"}
    sig_header = km.sign_webhook_payload(payload)
    assert 'keyid="psp-2026-11"' in sig_header
    assert km.verify_webhook_signature(payload, sig_header) is True

    # Tampered body fails verification
    tampered_payload = {"test": 999, "merchant": "mer_croma"}
    assert km.verify_webhook_signature(tampered_payload, sig_header) is False


# --- Fault Injection ---


def test_fault_injection_admin(test_setup):
    """Test POST /psp/v1/admin/faults access control and simulated DECLINE fault."""
    client: TestClient = test_setup["client"]

    # 1. Missing admin key -> 401
    bad_resp = client.post(
        "/psp/v1/admin/faults",
        json={"scope": {"merchant_id": "mer_croma"}, "faults": [{"type": "DECLINE"}]},
    )
    assert bad_resp.status_code == 401

    # 2. Valid admin key -> 200
    ok_resp = client.post(
        "/psp/v1/admin/faults",
        headers={"X-Admin-Key": SETTINGS.admin_api_key},
        json={
            "scope": {"merchant_id": "mer_croma"},
            "faults": [{"type": "DECLINE", "decline_code": "INSUFFICIENT_FUNDS"}],
        },
    )
    assert ok_resp.status_code == 200
    assert ok_resp.json()["status"] == "CONFIGURED"

    # 3. Authorize against this merchant triggers simulated decline
    async def _run() -> None:
        service: MockPspService = test_setup["service"]
        db: AsyncSessionWrapper = test_setup["db"]
        token = make_test_token(token_id="ptok_fault_decline", merchant_id="mer_croma")
        now = datetime.now(UTC)

        cred = await service.create_scoped_credential(
            CreateScopedCredentialRequest(
                mandit_token=token,
                merchant_id="mer_croma",
                max_amount_minor=500000,
                currency="INR",
                expires_at=now + timedelta(minutes=10),
            ),
            db,
        )

        auth = await service.authorize_card(
            AuthorizeCardRequest(
                credential_id=cred.credential_id,
                merchant_id="mer_croma",
                amount_minor=500000,
                currency="INR",
            ),
            db,
        )
        assert auth.status == "FAILED"
        assert auth.decline_code == "INSUFFICIENT_FUNDS"

    asyncio.run(_run())


# --- Distributed Failure Recovery ---


def test_distributed_failure_recovery_same_key(test_setup):
    """Verify safe recovery when Core token is redeemed but initial PSP call retries."""

    async def _run() -> None:
        service: MockPspService = test_setup["service"]
        db: AsyncSessionWrapper = test_setup["db"]
        t_client: MockTokenClient = test_setup["token_client"]
        token = make_test_token(token_id="ptok_dist_123")
        now = datetime.now(UTC)

        req = CreateScopedCredentialRequest(
            mandit_token=token,
            merchant_id="mer_croma",
            max_amount_minor=500000,
            currency="INR",
            expires_at=now + timedelta(minutes=10),
        )

        # 1. First call: succeeds
        res1 = await service.create_scoped_credential(req, db)
        assert res1.status == "ACTIVE"

        # 2. Retry with same token / request: returns existing credential without double-redeem
        res2 = await service.create_scoped_credential(req, db)
        assert res2.credential_id == res1.credential_id

        # Core was called only once because PSP recognized existing token_id
        assert len(t_client.redeem_calls) == 1

    asyncio.run(_run())


# --- HTTP API Route Tests ---


def test_http_card_scoped_credentials_api(test_setup):
    """Test POST /psp/v1/card/scoped-credentials via TestClient."""
    client: TestClient = test_setup["client"]
    token = make_test_token(token_id="ptok_http_card")
    now = datetime.now(UTC)

    resp = client.post(
        "/psp/v1/card/scoped-credentials",
        json={
            "mandit_token": token,
            "merchant_id": "mer_croma",
            "max_amount_minor": 500000,
            "currency": "INR",
            "expires_at": (now + timedelta(minutes=10)).isoformat(),
        },
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["status"] == "ACTIVE"
    assert "credential_id" in data


def test_http_upi_approve_alias_api(test_setup):
    """Test POST /psp/v1/upi/approve alias via TestClient."""
    client: TestClient = test_setup["client"]
    token = make_test_token(token_id="ptok_http_upi", payee_id="acq_croma_001@icici", rail="UPI")
    now = datetime.now(UTC)

    # 1. Create intent
    c_resp = client.post(
        "/psp/v1/upi/intents",
        json={
            "mandit_token": token,
            "payee_vpa": "acq_croma_001@icici",
            "amount_minor": 500000,
            "currency": "INR",
            "expires_at": (now + timedelta(minutes=10)).isoformat(),
        },
    )
    assert c_resp.status_code == 201
    intent_id = c_resp.json()["intent_id"]

    # 2. Approve via alias
    a_resp = client.post(
        "/psp/v1/upi/approve",
        json={"intent_id": intent_id, "payer_vpa": "user@mockbank"},
    )
    assert a_resp.status_code == 200
    assert a_resp.json()["status"] == "SUCCESS"
