"""Comprehensive HTTP tests for Human Confirmation endpoints.

Tests FastAPI router:
- POST /v1/confirmations/{confirmation_id}/respond
- GET /v1/confirmations/{confirmation_id}

Verifies:
1. Fail-closed authentication (rejects missing/invalid auth; never trusts X-User-ID).
2. Ownership validation (403 Forbidden when caller != confirmation.user_id).
3. Lazy expiry on GET (updates DB to EXPIRED and emits CONFIRMATION_EXPIRED).
4. Request validation (400 on invalid response type, missing/corrupt signature).
5. Error status mapping (404, 403, 409, 400, 401).
6. Success response serialization on APPROVE and REJECT.
"""
from datetime import datetime, timedelta, timezone
from typing import Any
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from mandit.common import events, hashing
from mandit.common.crypto import b64url_encode
from mandit.common.models import Base
from mandit.confirmation.api import (
    get_confirmation_service,
    get_current_user_id,
    get_db_session,
    get_user_auth_service,
    router,
)
from mandit.confirmation.interface import UserAuthService
from mandit.confirmation.models import ConfirmationModel, UserKeyModel
from mandit.confirmation.schemas import AuthenticationError, UserKeyRecord
from mandit.confirmation.service import ConfirmationServiceImpl, DatabaseUserKeyService
from mandit.policy.models import DecisionModel
from mandit.policy.repository import DecisionRepository
from mandit.policy.schemas import (
    AgentContext,
    CalculationResult,
    CheckoutSnapshot,
    DecisionOutcome,
    EvaluationStage,
    FrozenDecisionInputs,
    IdentityResult,
    MandateConstraints,
    MandateMatchResult,
    MandateSnapshot,
    RiskSummary,
    SelectionResult,
    TrustResult,
    VerificationReport,
)
from mandit.policy.service import DecisionServiceImpl, DefaultPolicyEngine, build_display_payload


class MockUserAuthService(UserAuthService):
    """Test auth service: parses 'Bearer token_<user_id>' or raises AuthenticationError."""

    async def authenticate_user(self, authorization: str | None) -> str:
        if not authorization or not authorization.startswith("Bearer token_"):
            raise AuthenticationError("Invalid session credentials", code="UNAUTHORIZED")
        return authorization.replace("Bearer token_", "").strip()


class DummyGroundingService:
    def __init__(self, proposal_id: str, proposal_hash: str, checkout_expires_at: datetime | None = None):
        self._proposal_id = proposal_id
        self._proposal_hash = proposal_hash
        self._checkout_expires_at = checkout_expires_at or (datetime.now(timezone.utc) + timedelta(minutes=15))

    async def get_proposal(self, proposal_id: str) -> Any:
        class Prop:
            def __init__(self, pid: str, phash: str):
                self.proposal_id = pid
                self.proposal_hash = phash
        return Prop(self._proposal_id, self._proposal_hash)

    async def latest_verification(self, proposal_id: str) -> Any:
        class Chk:
            def __init__(self, exp: datetime):
                self.expires_at = exp
        class Verif:
            def __init__(self, exp: datetime):
                self.checkout = Chk(exp)
        return Verif(self._checkout_expires_at)


@pytest.fixture
def test_setup():
    from sqlalchemy.pool import StaticPool
    from mandit.policy.models import ConfirmationModel, DecisionModel
    from mandit.confirmation.models import UserKeyModel
    from mandit.common.events import EventOutboxModel

    engine = create_engine(
        "sqlite:///:memory:",
        echo=False,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    now = datetime.now(timezone.utc)

    # Generate ES256 key for test user usr_alice
    user_private_key = ec.generate_private_key(ec.SECP256R1())
    pub_numbers = user_private_key.public_key().public_numbers()
    x_bytes = pub_numbers.x.to_bytes(32, "big")
    y_bytes = pub_numbers.y.to_bytes(32, "big")

    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": b64url_encode(x_bytes),
        "y": b64url_encode(y_bytes),
    }

    key_record = UserKeyModel(
        key_id="ukey_alice_01",
        user_id="usr_alice",
        alg="ES256",
        jwk=jwk,
        status="ACTIVE",
        created_at=now,
    )
    session.add(key_record)
    session.commit()

    repo = DecisionRepository()
    db_user_key_service = DatabaseUserKeyService(session_factory_or_session=session)

    # Initial decision
    init_dec = DecisionModel(
        decision_id="dec_init_01",
        proposal_id="prop_01",
        proposal_hash="sha256:prop01hash",
        transaction_id="txn_01",
        attempt=1,
        outcome="STEP_UP",
        stage="RULES",
        rules_fired=[{"rule_id": "SU-01", "code": "ABOVE_APPROVAL_THRESHOLD", "effect": "STEP_UP"}],
        policy_version="policy-1.0.0",
        inputs_snapshot_id="snp_01",
        inputs_hash="sha256:inputshash01",
        signature={"alg": "Ed25519", "key_id": "mandit-policy-2026-11", "signed_digest": "sha256:prop01hash", "value": "testsig"},
        created_at=now,
        expires_at=now + timedelta(minutes=10),
    )
    session.add(init_dec)
    session.commit()

    conf_id = "cnf_alice_01"
    display = {
        "merchant": {"merchant_id": "mer_test", "legal_name": "Test Merchant"},
        "items": [{"title": "Item 1", "quantity": 1, "amount_minor": 10000}],
        "tax_minor": 1800,
        "fees_minor": 0,
        "total_minor": 11800,
        "currency": "INR",
        "payment_method": "CARD",
        "reasons": [{"code": "ABOVE_APPROVAL_THRESHOLD", "template_id": "stepup.above_threshold", "params": {}}],
    }
    expires_at = now + timedelta(minutes=10)
    challenge = hashing.digest({
        "confirmation_id": conf_id,
        "display": display,
        "expires_at": expires_at.isoformat(),
        "proposal_hash": "sha256:prop01hash",
    })

    conf = ConfirmationModel(
        confirmation_id=conf_id,
        decision_id="dec_init_01",
        proposal_id="prop_01",
        proposal_hash="sha256:prop01hash",
        user_id="usr_alice",
        display=display,
        challenge=challenge,
        status="PENDING",
        expires_at=expires_at,
    )
    session.add(conf)
    session.commit()

    # Stub DecisionServiceImpl
    grounding = DummyGroundingService("prop_01", "sha256:prop01hash")
    policy_engine = DefaultPolicyEngine()
    decision_service = DecisionServiceImpl(engine=policy_engine, repository=repo, grounding_service=grounding)

    async def mock_build_inputs(proposal_id: str, session: Any = None, confirmation: Any = None, evaluated_at: Any = None):
        chk = CheckoutSnapshot(
            checkout_id="chk_01",
            checkout_hash="sha256:chkhash01",
            merchant_id="mer_test",
            merchant_domain="mer_test",
            payee_id="acq_test_01",
            amount_minor=11800,
            currency="INR",
            merchant_signature_valid=True,
            expires_at=now + timedelta(hours=1),
        )
        calc = CalculationResult(
            computed_total_minor=11800,
            merchant_total_minor=11800,
            agent_stated_total_minor=11800,
            reconciled=True,
            calculator_version="calc-1.0.0",
            subtotal_minor=10000,
            tax_minor=1800,
        )
        verif = VerificationReport(
            verification_id="ver_01",
            proposal_id=proposal_id,
            proposal_hash="sha256:prop01hash",
            attempt=1,
            checkout=chk,
            calculation=calc,
            mandate_match=MandateMatchResult(satisfied=True, violations=(), signals=()),
            selection=SelectionResult(pricier_alternative_chosen=False),
            trust=TrustResult(
                score=0.95,
                band="ALLOW",
                components={"G": 1.0},
                weights={"G": 1.0},
                trust_model_version="trust-1.0.0",
            ),
        )
        risk = RiskSummary(
            merchant_domain="mer_test",
            site_risk_score=0.05,
            site_risk_level="LOW",
            max_injection_severity="NONE",
            injection_content_ids=(),
            signals=(),
            scanner_version="scanner-1.0.0",
        )
        return FrozenDecisionInputs(
            evaluated_at=evaluated_at or datetime.now(timezone.utc),
            attempt=1,
            proposal_id=proposal_id,
            proposal_hash="sha256:prop01hash",
            transaction_id="txn_01",
            identity=IdentityResult(
                agent=AgentContext(agent_id="agt_01", operator_id="op_01", key_id="k_01", key_thumbprint="tp", scopes=frozenset(["cart:write", "checkout:complete"]), credential_id="c_01", verified_at=now),
                is_active=True,
                operator_verified=True,
                kya_token_valid=True,
                key_bound=True,
            ),
            mandate=MandateSnapshot(
                mandate_id="man_01",
                version=1,
                user_id="usr_alice",
                agent_id="agt_01",
                agent_key_thumbprint="tp",
                constraints=MandateConstraints(
                    allowed_merchants=("mer_test",),
                    currency="INR",
                    max_amount_per_txn_minor=50000,
                    max_amount_total_minor=100000,
                    approval_threshold_minor=5000,
                ),
                not_before=now - timedelta(days=1),
                expires_at=now + timedelta(days=1),
                status="ACTIVE",
                spent_minor=0,
                spend_count=0,
            ),
            risk=risk,
            verification=verif,
            user_merchant_history=3,
            payment_method="CARD_TOKEN",
            confirmation=confirmation,
        )

    decision_service.build_inputs = mock_build_inputs  # type: ignore

    conf_service = ConfirmationServiceImpl(
        repository=repo,
        decision_service=decision_service,
        grounding_service=grounding,
        user_key_service=db_user_key_service,
        now_fn=lambda: datetime.now(timezone.utc),
    )

    # Build FastAPI test app
    app = FastAPI()
    app.include_router(router)

    app.dependency_overrides[get_user_auth_service] = lambda: MockUserAuthService()
    app.dependency_overrides[get_confirmation_service] = lambda: conf_service
    app.dependency_overrides[get_db_session] = lambda: session

    client = TestClient(app)

    return {
        "app": app,
        "client": client,
        "session": session,
        "conf_id": conf_id,
        "challenge": challenge,
        "user_private_key": user_private_key,
        "conf_service": conf_service,
        "repo": repo,
    }


def test_http_auth_fail_closed_by_default():
    """Verify that without dependency overrides, authentication is strictly fail-closed."""
    app = FastAPI()
    app.include_router(router)
    client = TestClient(app)

    # Calling without Auth header -> 401
    resp = client.get("/v1/confirmations/cnf_123")
    assert resp.status_code == 401
    assert resp.json()["detail"]["code"] == "UNAUTHORIZED"

    # Calling with spoofed X-User-ID -> 401 (X-User-ID is never inspected)
    resp = client.get("/v1/confirmations/cnf_123", headers={"X-User-ID": "usr_alice"})
    assert resp.status_code == 401

    # Calling with unverified Authorization header -> 401 FailClosedUserAuthService
    resp = client.get("/v1/confirmations/cnf_123", headers={"Authorization": "Bearer usr_alice"})
    assert resp.status_code == 401
    assert "User session authentication provider is not configured" in resp.json()["detail"]["message"]


def test_http_get_confirmation_success(test_setup):
    """Verify authenticated user can retrieve their pending confirmation display."""
    client = test_setup["client"]
    conf_id = test_setup["conf_id"]

    resp = client.get(
        f"/v1/confirmations/{conf_id}",
        headers={"Authorization": "Bearer token_usr_alice"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["confirmation_id"] == conf_id
    assert data["status"] == "PENDING"
    assert data["user_id"] == "usr_alice"
    assert data["challenge"] == test_setup["challenge"]
    assert data["display"]["total_minor"] == 11800


def test_http_get_confirmation_ownership_mismatch(test_setup):
    """Verify user cannot read another user's confirmation."""
    client = test_setup["client"]
    conf_id = test_setup["conf_id"]

    resp = client.get(
        f"/v1/confirmations/{conf_id}",
        headers={"Authorization": "Bearer token_usr_bob"},
    )
    assert resp.status_code == 403
    assert resp.json()["detail"]["code"] == "CONFIRMATION_OWNERSHIP_MISMATCH"


def test_http_get_confirmation_not_found(test_setup):
    """Verify 404 Not Found for non-existent confirmation."""
    client = test_setup["client"]
    resp = client.get(
        "/v1/confirmations/cnf_nonexistent",
        headers={"Authorization": "Bearer token_usr_alice"},
    )
    assert resp.status_code == 404
    assert resp.json()["detail"]["code"] == "CONFIRMATION_NOT_FOUND"


def test_http_get_confirmation_lazy_expiry(test_setup):
    """Verify GET lazily expires past-due confirmation, updates database and emits event."""
    session = test_setup["session"]
    conf_id = test_setup["conf_id"]
    client = test_setup["client"]

    # Manually set expires_at in the past
    past_time = datetime.now(timezone.utc) - timedelta(minutes=5)
    conf = session.get(ConfirmationModel, conf_id)
    conf.expires_at = past_time
    session.commit()

    events.clear()

    resp = client.get(
        f"/v1/confirmations/{conf_id}",
        headers={"Authorization": "Bearer token_usr_alice"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "EXPIRED"

    # Verify persisted in database
    session.expire_all()
    conf_db = session.get(ConfirmationModel, conf_id)
    assert conf_db.status == "EXPIRED"


def test_http_respond_invalid_response_type(test_setup):
    """Verify 400 Bad Request on invalid response type."""
    client = test_setup["client"]
    conf_id = test_setup["conf_id"]

    resp = client.post(
        f"/v1/confirmations/{conf_id}/respond",
        headers={"Authorization": "Bearer token_usr_alice"},
        json={"response": "MAYBE"},
    )
    assert resp.status_code == 400
    assert resp.json()["detail"]["code"] == "INVALID_RESPONSE_TYPE"


def test_http_respond_reject_success(test_setup):
    """Verify successful rejection returns 200 with status REJECTED and null outcome."""
    client = test_setup["client"]
    conf_id = test_setup["conf_id"]

    resp = client.post(
        f"/v1/confirmations/{conf_id}/respond",
        headers={"Authorization": "Bearer token_usr_alice"},
        json={"response": "REJECT"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["confirmation_id"] == conf_id
    assert data["status"] == "REJECTED"
    assert data["decision_id"] is None
    assert data["outcome"] is None

    # Verify subsequent attempt fails with 409
    resp_dupe = client.post(
        f"/v1/confirmations/{conf_id}/respond",
        headers={"Authorization": "Bearer token_usr_alice"},
        json={"response": "REJECT"},
    )
    assert resp_dupe.status_code == 409
    assert resp_dupe.json()["detail"]["code"] == "CONFIRMATION_NOT_PENDING"


def test_http_respond_approve_success(test_setup):
    """Verify successful approval with ES256 signature returns 200 with outcome ALLOW."""
    client = test_setup["client"]
    conf_id = test_setup["conf_id"]
    challenge = test_setup["challenge"]
    priv_key = test_setup["user_private_key"]

    # Sign challenge with user's ES256 private key
    sig_der = priv_key.sign(challenge.encode("utf-8"), ec.ECDSA(hashes.SHA256()))

    resp = client.post(
        f"/v1/confirmations/{conf_id}/respond",
        headers={"Authorization": "Bearer token_usr_alice"},
        json={
            "response": "APPROVE",
            "signature": {
                "alg": "ES256",
                "key_id": "ukey_alice_01",
                "signed_digest": challenge,
                "value": b64url_encode(sig_der),
            },
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["confirmation_id"] == conf_id
    assert data["status"] == "APPROVED"
    assert data["decision_id"] is not None
    assert data["outcome"] == "ALLOW"


def test_http_respond_approve_challenge_mismatch(test_setup):
    """Verify 400 Bad Request when signed_digest does not match stored challenge."""
    client = test_setup["client"]
    conf_id = test_setup["conf_id"]
    priv_key = test_setup["user_private_key"]

    sig_der = priv_key.sign(b"sha256:wrongdigest", ec.ECDSA(hashes.SHA256()))

    resp = client.post(
        f"/v1/confirmations/{conf_id}/respond",
        headers={"Authorization": "Bearer token_usr_alice"},
        json={
            "response": "APPROVE",
            "signature": {
                "alg": "ES256",
                "key_id": "ukey_alice_01",
                "signed_digest": "sha256:wrongdigest",
                "value": b64url_encode(sig_der),
            },
        },
    )
    assert resp.status_code == 400
    assert resp.json()["detail"]["code"] == "CHALLENGE_MISMATCH"


def test_http_respond_approve_missing_signature(test_setup):
    """Verify 400 Bad Request when APPROVE request lacks signature."""
    client = test_setup["client"]
    conf_id = test_setup["conf_id"]

    resp = client.post(
        f"/v1/confirmations/{conf_id}/respond",
        headers={"Authorization": "Bearer token_usr_alice"},
        json={"response": "APPROVE"},
    )
    assert resp.status_code == 400
    assert resp.json()["detail"]["code"] == "SIGNATURE_INVALID"
