"""Focused unit tests for PSP client adapters and Ed25519 webhook signature verification.

Stage 3 Milestone 2: Tests HttpPspClient, InProcessPspClient, and PspWebhookVerifier.
"""

from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from mandit.common import jcs
from mandit.common.crypto import b64url_encode
from mandit.payments.interface import PspClient
from mandit.payments.psp_client import (
    HttpPspClient,
    InProcessPspClient,
    PspAuthorizeCardRequest,
    PspCaptureCardRequest,
    PspConnectionError,
    PspCreateScopedCredentialRequest,
    PspCreateUpiIntentRequest,
    PspPayloadError,
    PspResponseError,
    PspTimeoutError,
)
from mandit.payments.webhook_verifier import (
    PspWebhookVerifier,
    WebhookSignatureError,
    get_webhook_verifier,
    set_webhook_verifier,
)

# --- Test Helpers & Fixtures ---


@pytest.fixture
def test_ed25519_keypair():
    """Generate ephemeral Ed25519 keypair for tests."""
    priv = ed25519.Ed25519PrivateKey.generate()
    return priv, priv.public_key()


def sign_test_payload(
    payload: dict[str, Any],
    private_key: ed25519.Ed25519PrivateKey,
    key_id: str = "psp-test-2026",
) -> str:
    """Helper to produce Mock-PSP-Signature header over JCS canonical body."""
    canonical_bytes = jcs.canonicalize(payload)
    sig_bytes = private_key.sign(canonical_bytes)
    sig_b64 = b64url_encode(sig_bytes)
    return f'keyid="{key_id}",sig="{sig_b64}"'


# --- 1. Webhook Signature Verifier Tests ---


def test_webhook_verifier_valid_signature(test_ed25519_keypair):
    """Test successful verification of valid Ed25519 signature over JCS body."""
    priv, pub = test_ed25519_keypair
    verifier = PspWebhookVerifier()
    verifier.register_trusted_key("psp-test-2026", pub)

    payload = {
        "psp_event_id": "pspevt_001",
        "type": "payment.captured",
        "psp_payment_id": "psp_001",
        "amount_minor": 500000,
        "currency": "INR",
        "status": "CAPTURED",
    }
    sig_header = sign_test_payload(payload, priv, "psp-test-2026")

    # Verify dict payload
    verified = verifier.verify(payload, sig_header)
    assert verified["psp_event_id"] == "pspevt_001"
    assert verified["status"] == "CAPTURED"


def test_webhook_verifier_canonicalization_consistency(test_ed25519_keypair):
    """Test verification passes regardless of key ordering or whitespace in JSON string."""
    priv, pub = test_ed25519_keypair
    verifier = PspWebhookVerifier({"psp-test-2026": pub})

    payload_dict = {"b": 2, "a": 1, "nested": {"y": "test", "x": [3, 2, 1]}}
    sig_header = sign_test_payload(payload_dict, priv, "psp-test-2026")

    # Pass as differently ordered JSON string with spaces
    raw_json_str = (
        '{\n  "nested": {\n    "y": "test",\n    "x": [3, 2, 1]\n  },\n  "a": 1,\n  "b": 2\n}'
    )
    verified = verifier.verify(raw_json_str, sig_header)
    assert verified["a"] == 1
    assert verified["nested"]["x"] == [3, 2, 1]

    # Pass as raw UTF-8 bytes
    verified_bytes = verifier.verify(raw_json_str.encode("utf-8"), sig_header)
    assert verified_bytes["b"] == 2


def test_webhook_verifier_payload_tampering(test_ed25519_keypair):
    """Test rejection when any field in the payload is modified after signing."""
    priv, pub = test_ed25519_keypair
    verifier = PspWebhookVerifier({"psp-test-2026": pub})

    payload = {
        "psp_event_id": "pspevt_001",
        "type": "payment.captured",
        "psp_payment_id": "psp_001",
        "amount_minor": 500000,
    }
    sig_header = sign_test_payload(payload, priv, "psp-test-2026")

    # Tamper amount
    tampered = dict(payload, amount_minor=500001)
    with pytest.raises(WebhookSignatureError) as exc:
        verifier.verify(tampered, sig_header)
    assert exc.value.code == "SIGNATURE_MISMATCH"
    assert exc.value.status_code == 401


def test_webhook_verifier_invalid_signature_bytes(test_ed25519_keypair):
    """Test rejection when signature bits are corrupted."""
    priv, pub = test_ed25519_keypair
    verifier = PspWebhookVerifier({"psp-test-2026": pub})

    payload = {"psp_event_id": "pspevt_001", "status": "CAPTURED"}
    sig_header = sign_test_payload(payload, priv, "psp-test-2026")

    # Corrupt last character
    corrupted_header = sig_header[:-2] + "AA"
    with pytest.raises(WebhookSignatureError) as exc:
        verifier.verify(payload, corrupted_header)
    assert exc.value.code in ("SIGNATURE_MISMATCH", "MALFORMED_SIGNATURE")
    assert exc.value.status_code == 401


def test_webhook_verifier_unknown_key_id(test_ed25519_keypair):
    """Test fail-closed rejection when key ID is not registered."""
    priv, _ = test_ed25519_keypair
    verifier = PspWebhookVerifier()  # empty key registry

    payload = {"psp_event_id": "pspevt_001"}
    sig_header = sign_test_payload(payload, priv, "untrusted-key-id")

    with pytest.raises(WebhookSignatureError) as exc:
        verifier.verify(payload, sig_header)
    assert exc.value.code == "UNKNOWN_KEY_ID"
    assert exc.value.status_code == 401


def test_webhook_verifier_missing_or_malformed_headers(test_ed25519_keypair):
    """Test rejection on missing, empty, or malformed signature headers."""
    _, pub = test_ed25519_keypair
    verifier = PspWebhookVerifier({"psp-test-2026": pub})
    payload = {"status": "SUCCESS"}

    # Missing header
    with pytest.raises(WebhookSignatureError) as exc1:
        verifier.verify(payload, None)
    assert exc1.value.code == "MISSING_SIGNATURE"

    # Empty header
    with pytest.raises(WebhookSignatureError) as exc2:
        verifier.verify(payload, "")
    assert exc2.value.code == "MISSING_SIGNATURE"

    # Malformed format (missing sig or keyid)
    with pytest.raises(WebhookSignatureError) as exc3:
        verifier.verify(payload, 'sig="abc123"')
    assert exc3.value.code == "MALFORMED_SIGNATURE"


def test_webhook_verifier_malformed_payload(test_ed25519_keypair):
    """Test rejection when payload is not valid JSON."""
    priv, pub = test_ed25519_keypair
    verifier = PspWebhookVerifier({"psp-test-2026": pub})
    sig_header = f'keyid="psp-test-2026",sig="{b64url_encode(b"0" * 64)}"'

    # Non-JSON string
    with pytest.raises(WebhookSignatureError) as exc:
        verifier.verify("not a json string", sig_header)
    assert exc.value.code == "MALFORMED_PAYLOAD"
    assert exc.value.status_code == 400

    # Unsupported type (e.g. integer)
    with pytest.raises(WebhookSignatureError) as exc2:
        verifier.verify(12345, sig_header)  # type: ignore[arg-type]
    assert exc2.value.code == "INVALID_PAYLOAD_TYPE"


def test_webhook_verifier_key_separation(test_ed25519_keypair):
    """Verify webhook keys are independent from service auth keys."""
    service_auth_key = ed25519.Ed25519PrivateKey.generate()
    _, webhook_pub = test_ed25519_keypair

    # Register only webhook_pub
    verifier = PspWebhookVerifier({"webhook-key": webhook_pub})

    payload = {"status": "SUCCESS"}
    # Sign using service auth private key under unknown key id
    sig_header = sign_test_payload(payload, service_auth_key, "service-auth-key")

    with pytest.raises(WebhookSignatureError) as exc:
        verifier.verify(payload, sig_header)
    assert exc.value.code == "UNKNOWN_KEY_ID"


def test_webhook_verifier_global_registry(test_ed25519_keypair):
    """Test global get_webhook_verifier and set_webhook_verifier helpers."""
    _, pub = test_ed25519_keypair
    original = get_webhook_verifier()
    try:
        custom = PspWebhookVerifier({"custom-key": pub})
        set_webhook_verifier(custom)
        assert get_webhook_verifier() is custom
        assert get_webhook_verifier().get_trusted_key("custom-key") is pub
    finally:
        set_webhook_verifier(original)


# --- 2. HTTP PSP Client Tests ---


@pytest.mark.anyio
async def test_http_psp_client_card_flow():
    """Test HttpPspClient card execution endpoints with mocked httpx transport."""
    now = datetime.now(UTC)

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url.endswith("/psp/v1/card/scoped-credentials"):
            assert request.method == "POST"
            return httpx.Response(
                201,
                json={
                    "credential_id": "spc_test_001",
                    "status": "ACTIVE",
                    "max_amount_minor": 500000,
                    "currency": "INR",
                    "expires_at": now.isoformat(),
                },
            )
        elif url.endswith("/psp/v1/card/authorize"):
            assert request.method == "POST"
            return httpx.Response(
                200,
                json={
                    "psp_payment_id": "psp_card_001",
                    "status": "AUTHORIZED",
                    "amount_minor": 500000,
                    "currency": "INR",
                    "decline_code": None,
                },
            )
        elif url.endswith("/psp/v1/card/capture"):
            assert request.method == "POST"
            return httpx.Response(
                200,
                json={
                    "psp_payment_id": "psp_card_001",
                    "status": "CAPTURED",
                    "amount_minor": 500000,
                    "currency": "INR",
                },
            )
        return httpx.Response(404, json={"code": "NOT_FOUND"})

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        psp_client = HttpPspClient(base_url="http://mock-psp:8200", http_client=client)

        # 1. Scoped credentials
        cred = await psp_client.create_scoped_credential(
            PspCreateScopedCredentialRequest(
                mandit_token="token_val",
                merchant_id="mer_croma",
                max_amount_minor=500000,
                currency="INR",
                expires_at=now,
            )
        )
        assert cred.credential_id == "spc_test_001"
        assert cred.status == "ACTIVE"

        # 2. Authorize
        auth = await psp_client.authorize_card(
            PspAuthorizeCardRequest(
                credential_id=cred.credential_id,
                merchant_id="mer_croma",
                amount_minor=500000,
                currency="INR",
            )
        )
        assert auth.status == "AUTHORIZED"
        assert auth.psp_payment_id == "psp_card_001"

        # 3. Capture
        cap = await psp_client.capture_card(
            PspCaptureCardRequest(psp_payment_id=auth.psp_payment_id, amount_minor=500000)
        )
        assert cap.status == "CAPTURED"


@pytest.mark.anyio
async def test_http_psp_client_upi_flow_and_status():
    """Test HttpPspClient UPI intent, status lookup, and JWKS discovery."""
    now = datetime.now(UTC)

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url.endswith("/psp/v1/upi/intents"):
            return httpx.Response(
                201,
                json={
                    "intent_id": "upi_intent_001",
                    "psp_payment_id": "psp_upi_001",
                    "status": "PENDING",
                    "amount_minor": 500000,
                    "currency": "INR",
                    "payee_vpa": "croma@icici",
                    "expires_at": now.isoformat(),
                },
            )
        elif "/psp/v1/payments/psp_upi_001" in url:
            return httpx.Response(
                200,
                json={
                    "psp_payment_id": "psp_upi_001",
                    "status": "SUCCESS",
                    "amount_minor": 500000,
                    "currency": "INR",
                    "merchant_id": "mer_croma",
                },
            )
        elif url.endswith("/.well-known/psp-keys.json"):
            return httpx.Response(
                200,
                json={
                    "keys": [
                        {
                            "kty": "OKP",
                            "crv": "Ed25519",
                            "kid": "psp-2026-11",
                            "x": "x_coord_test",
                        }
                    ]
                },
            )
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        psp_client = HttpPspClient(base_url="http://mock-psp:8200", http_client=client)

        intent = await psp_client.create_upi_intent(
            PspCreateUpiIntentRequest(
                mandit_token="token_val",
                payee_vpa="croma@icici",
                amount_minor=500000,
                currency="INR",
                expires_at=now,
            )
        )
        assert intent.intent_id == "upi_intent_001"
        assert intent.status == "PENDING"

        status_resp = await psp_client.get_payment_status("psp_upi_001")
        assert status_resp.status == "SUCCESS"

        jwks = await psp_client.get_public_jwks()
        assert len(jwks.keys) == 1
        assert jwks.keys[0].kid == "psp-2026-11"


@pytest.mark.anyio
async def test_http_psp_client_timeout_and_network_errors():
    """Test that timeouts and connection errors raise specific PspClientError subclasses."""

    def timeout_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("Simulated gateway timeout", request=request)

    def connect_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("Connection refused by mock PSP", request=request)

    # 1. Timeout -> PspTimeoutError (must NOT be retried)
    async with httpx.AsyncClient(transport=httpx.MockTransport(timeout_handler)) as client:
        psp = HttpPspClient(http_client=client)
        with pytest.raises(PspTimeoutError) as exc_timeout:
            await psp.get_payment_status("psp_timeout_test")
        assert "timed out" in str(exc_timeout.value)

    # 2. Connection failure -> PspConnectionError
    async with httpx.AsyncClient(transport=httpx.MockTransport(connect_handler)) as client:
        psp = HttpPspClient(http_client=client)
        with pytest.raises(PspConnectionError) as exc_conn:
            await psp.get_payment_status("psp_conn_test")
        assert "failed" in str(exc_conn.value)


@pytest.mark.anyio
async def test_http_psp_client_non_success_response():
    """Test 4xx and 5xx responses raise PspResponseError with extracted code and message."""

    def error_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            409,
            json={
                "detail": {
                    "code": "CREDENTIAL_INACTIVE",
                    "message": "Scoped credential has already been consumed",
                }
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(error_handler)) as client:
        psp = HttpPspClient(http_client=client)
        with pytest.raises(PspResponseError) as exc:
            await psp.authorize_card({"credential_id": "spc_001"})
        assert exc.value.status_code == 409
        assert exc.value.error_code == "CREDENTIAL_INACTIVE"
        assert "consumed" in str(exc.value)


@pytest.mark.anyio
async def test_http_psp_client_malformed_json_response():
    """Test invalid non-JSON response raises PspPayloadError."""

    def invalid_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<HTML>502 Bad Gateway</HTML>")

    async with httpx.AsyncClient(transport=httpx.MockTransport(invalid_handler)) as client:
        psp = HttpPspClient(http_client=client)
        with pytest.raises(PspPayloadError):
            await psp.get_payment_status("psp_test")


# --- 3. In-Process PSP Client Tests ---


class MockPspServiceDouble:
    """Mock test double mimicking MockPspService for in-process adapter testing."""

    def __init__(self, should_fail: bool = False) -> None:
        self.should_fail = should_fail

    async def create_scoped_credential(self, req: Any, session: Any) -> Any:
        if self.should_fail:
            from mock_psp.service import PspServiceError

            raise PspServiceError("TOKEN_ALREADY_REDEEMED", "Token already used", 409)
        return {
            "credential_id": "spc_inproc_001",
            "status": "ACTIVE",
            "max_amount_minor": 500000,
            "currency": "INR",
            "expires_at": datetime.now(UTC),
        }

    async def authorize_card(self, req: Any, session: Any) -> Any:
        return {
            "psp_payment_id": "psp_inproc_001",
            "status": "AUTHORIZED",
            "amount_minor": 500000,
            "currency": "INR",
            "decline_code": None,
        }

    async def capture_card(self, req: Any, session: Any) -> Any:
        return {
            "psp_payment_id": "psp_inproc_001",
            "status": "CAPTURED",
            "amount_minor": 500000,
            "currency": "INR",
        }

    async def create_upi_intent(self, req: Any, session: Any) -> Any:
        return {
            "intent_id": "upi_inproc_001",
            "psp_payment_id": "psp_inproc_001",
            "status": "PENDING",
            "amount_minor": 500000,
            "currency": "INR",
            "payee_vpa": "croma@icici",
            "expires_at": datetime.now(UTC),
        }

    async def get_payment_status(self, psp_payment_id: str, session: Any) -> Any:
        return {
            "psp_payment_id": psp_payment_id,
            "status": "SUCCESS",
            "amount_minor": 500000,
            "currency": "INR",
            "merchant_id": "mer_croma",
        }

    def get_jwks(self) -> Any:
        return {"keys": [{"kid": "psp-inproc", "kty": "OKP", "crv": "Ed25519", "x": "xyz"}]}


@pytest.mark.anyio
async def test_in_process_psp_client_operations():
    """Test InProcessPspClient executes operations directly and adheres to PspClient protocol."""
    service_double = MockPspServiceDouble(should_fail=False)
    client = InProcessPspClient(service_double)

    # 1. Scoped credentials
    now = datetime.now(UTC)
    cred = await client.create_scoped_credential(
        {
            "mandit_token": "token",
            "merchant_id": "mer_croma",
            "max_amount_minor": 500000,
            "currency": "INR",
            "expires_at": now,
        }
    )
    assert cred.credential_id == "spc_inproc_001"
    assert cred.status == "ACTIVE"

    # 2. Authorize
    auth = await client.authorize_card(
        {
            "credential_id": cred.credential_id,
            "merchant_id": "mer_croma",
            "amount_minor": 500000,
            "currency": "INR",
        }
    )
    assert auth.status == "AUTHORIZED"
    assert auth.psp_payment_id == "psp_inproc_001"

    # 3. Capture
    cap = await client.capture_card({"psp_payment_id": auth.psp_payment_id, "amount_minor": 500000})
    assert cap.status == "CAPTURED"

    # 4. UPI Intent
    intent = await client.create_upi_intent(
        {
            "mandit_token": "token",
            "payee_vpa": "croma@icici",
            "amount_minor": 500000,
            "currency": "INR",
            "expires_at": now,
        }
    )
    assert intent.intent_id == "upi_inproc_001"

    # 5. Status & JWKS
    stat = await client.get_payment_status("psp_inproc_001")
    assert stat.status == "SUCCESS"

    jwks = await client.get_public_jwks()
    assert jwks.keys[0].kid == "psp-inproc"

    # 6. Check structural subtyping
    psp_interface: PspClient = client
    assert psp_interface is not None


@pytest.mark.anyio
async def test_in_process_psp_client_error_handling():
    """Test that in-process service exceptions are translated into PspResponseError."""
    service_double = MockPspServiceDouble(should_fail=True)
    client = InProcessPspClient(service_double)

    now = datetime.now(UTC)
    with pytest.raises(PspResponseError) as exc:
        await client.create_scoped_credential(
            {
                "mandit_token": "token",
                "merchant_id": "mer_croma",
                "max_amount_minor": 500000,
                "currency": "INR",
                "expires_at": now,
            }
        )
    assert exc.value.status_code == 409
    assert exc.value.error_code == "TOKEN_ALREADY_REDEEMED"
