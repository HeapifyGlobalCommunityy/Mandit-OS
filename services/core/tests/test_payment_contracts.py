"""Focused tests for Payment Orchestrator contracts, storage models, and schemas.

Stage 3 Milestone 1: Verifies models.py, schemas.py, and interface.py.
"""

from datetime import UTC, datetime
from typing import Any

import pytest
from pydantic import ValidationError
from sqlalchemy import (
    BigInteger,
    DateTime,
    Integer,
    String,
    Text,
    create_engine,
    select,
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from mandit.common.models import Base
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
    PspWebhookEventModel,
)
from mandit.payments.schemas import (
    MockPspWebhookPayload,
    Payment,
    PaymentErrorCode,
    PaymentExecuteRequest,
    PaymentExecuteResponse,
    PaymentRail,
    PaymentReceipt,
    PaymentReceiptSchema,
    PaymentStatus,
    PaymentStatusResponse,
)


@pytest.fixture
def db_session():
    """In-memory SQLite session with table creation."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        echo=False,
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    try:
        yield session
    finally:
        session.close()


# --- 1. Model & Migration Compatibility Tests ---


def test_payment_model_table_and_columns():
    """Test PaymentModel matches migration 0004 table schema exactly."""
    table = PaymentModel.__table__
    assert table.name == "payments"

    cols = table.columns
    assert "payment_id" in cols
    assert cols["payment_id"].primary_key is True
    assert isinstance(cols["payment_id"].type, Text)

    assert "proposal_id" in cols
    assert cols["proposal_id"].nullable is False
    assert cols["proposal_id"].unique is True

    assert "token_id" in cols
    assert cols["token_id"].nullable is True

    assert "rail" in cols
    assert cols["rail"].nullable is False

    assert "psp_payment_id" in cols
    assert cols["psp_payment_id"].nullable is True

    assert "status" in cols
    assert cols["status"].nullable is False

    assert "amount_minor" in cols
    assert isinstance(cols["amount_minor"].type, BigInteger)
    assert cols["amount_minor"].nullable is False

    assert "currency" in cols
    assert isinstance(cols["currency"].type, String)
    assert cols["currency"].type.length == 3
    assert cols["currency"].nullable is False

    assert "failure_code" in cols
    assert cols["failure_code"].nullable is True

    assert "created_at" in cols
    assert isinstance(cols["created_at"].type, DateTime)

    assert "updated_at" in cols
    assert isinstance(cols["updated_at"].type, DateTime)


def test_psp_webhook_event_model_table_and_columns():
    """Test PspWebhookEventModel matches migration 0004 table schema."""
    table = PspWebhookEventModel.__table__
    assert table.name == "psp_webhook_events"

    cols = table.columns
    assert "psp_event_id" in cols
    assert cols["psp_event_id"].primary_key is True
    assert "payment_id" in cols
    assert cols["payment_id"].nullable is False
    assert "body_hash" in cols
    assert cols["body_hash"].nullable is False
    assert "received_at" in cols
    assert isinstance(cols["received_at"].type, DateTime)


def test_idempotency_key_model_table_and_columns():
    """Test IdempotencyKeyModel matches migration 0004 table schema."""
    table = IdempotencyKeyModel.__table__
    assert table.name == "idempotency_keys"

    cols = table.columns
    assert "key" in cols
    assert cols["key"].primary_key is True
    assert "route" in cols
    assert cols["route"].nullable is False
    assert "request_hash" in cols
    assert cols["request_hash"].nullable is False
    assert "response_status" in cols
    assert isinstance(cols["response_status"].type, Integer)
    assert cols["response_status"].nullable is True
    assert "response_body" in cols
    assert cols["response_body"].nullable is True
    assert "created_at" in cols
    assert isinstance(cols["created_at"].type, DateTime)


def test_payment_model_orm_lifecycle_and_uniqueness(db_session):
    """Test inserting, querying, unique constraints, and to_schema() conversion."""
    now = datetime.now(UTC)
    pm = PaymentModel(
        payment_id="pay_test_001",
        proposal_id="prop_test_001",
        token_id="ptok_test_001",
        rail="CARD",
        psp_payment_id="psp_test_001",
        status="AUTHORIZED",
        amount_minor=500000,
        currency="INR",
        failure_code=None,
        created_at=now,
        updated_at=now,
    )
    db_session.add(pm)
    db_session.commit()

    retrieved = db_session.execute(
        select(PaymentModel).where(PaymentModel.payment_id == "pay_test_001")
    ).scalar_one()
    assert retrieved.payment_id == "pay_test_001"
    assert retrieved.amount_minor == 500000

    # Test conversion to domain dataclass
    domain_obj = retrieved.to_schema()
    assert isinstance(domain_obj, Payment)
    assert domain_obj.payment_id == "pay_test_001"
    assert domain_obj.rail == PaymentRail.CARD
    assert domain_obj.status == PaymentStatus.AUTHORIZED

    # Test proposal_id uniqueness constraint
    duplicate = PaymentModel(
        payment_id="pay_test_002",
        proposal_id="prop_test_001",  # Duplicate proposal_id
        token_id=None,
        rail="UPI",
        psp_payment_id=None,
        status="CREATED",
        amount_minor=100000,
        currency="INR",
        failure_code=None,
        created_at=now,
        updated_at=now,
    )
    db_session.add(duplicate)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_idempotency_key_model_persistence(db_session):
    """Test IdempotencyKeyModel insertion and query with JSON response_body."""
    now = datetime.now(UTC)
    key_entry = IdempotencyKeyModel(
        key="idem_key_001",
        route="/v1/payments/execute",
        request_hash="sha256:request_hash_abc",
        response_status=200,
        response_body={"payment_id": "pay_test_001", "status": "CAPTURED"},
        created_at=now,
    )
    db_session.add(key_entry)
    db_session.commit()

    saved = db_session.execute(
        select(IdempotencyKeyModel).where(IdempotencyKeyModel.key == "idem_key_001")
    ).scalar_one()
    assert saved.response_status == 200
    assert saved.response_body["payment_id"] == "pay_test_001"


# --- 2. Schema Validation Tests ---


def test_payment_receipt_and_error_codes():
    """Test PaymentReceipt dataclass and PaymentErrorCode enum values."""
    receipt = PaymentReceipt(transaction_id="txn_001", evidence_url="/v1/evidence/txn_001")
    assert receipt.transaction_id == "txn_001"
    assert receipt.evidence_url == "/v1/evidence/txn_001"

    assert PaymentErrorCode.DECISION_NOT_ALLOW == "DECISION_NOT_ALLOW"
    assert PaymentErrorCode.CHECKOUT_CHANGED == "CHECKOUT_CHANGED"
    assert PaymentErrorCode.PSP_DECLINED == "PSP_DECLINED"

    req = PaymentExecuteRequest(proposal_id="prop_01JD43")
    assert req.proposal_id == "prop_01JD43"

    with pytest.raises(ValidationError):
        PaymentExecuteRequest(proposal_id="")


def test_payment_execute_response_validation():
    """Test PaymentExecuteResponse serialization and constraints."""
    resp = PaymentExecuteResponse(
        payment_id="pay_01JD4C",
        proposal_id="prop_01JD43",
        rail=PaymentRail.CARD,
        status=PaymentStatus.CAPTURED,
        amount_minor=7649900,
        currency="INR",
        merchant_id="mer_croma",
        receipt=PaymentReceiptSchema(
            transaction_id="txn_01JD3Y",
            evidence_url="/v1/evidence/txn_01JD3Y",
        ),
    )
    assert resp.status == PaymentStatus.CAPTURED
    assert resp.receipt is not None
    assert resp.receipt.transaction_id == "txn_01JD3Y"

    # Invalid currency length
    with pytest.raises(ValidationError):
        PaymentExecuteResponse(
            payment_id="pay_1",
            proposal_id="prop_1",
            rail=PaymentRail.CARD,
            status=PaymentStatus.CAPTURED,
            amount_minor=100,
            currency="US",  # < 3 chars
            merchant_id="mer_1",
        )

    # Invalid amount <= 0
    with pytest.raises(ValidationError):
        PaymentExecuteResponse(
            payment_id="pay_1",
            proposal_id="prop_1",
            rail=PaymentRail.CARD,
            status=PaymentStatus.CAPTURED,
            amount_minor=0,
            currency="USD",
            merchant_id="mer_1",
        )


def test_payment_domain_dataclass_validation():
    """Test Payment dataclass enforces timezone-aware datetimes and validation."""
    now = datetime.now(UTC)
    p = Payment(
        payment_id="pay_1",
        proposal_id="prop_1",
        token_id=None,
        rail=PaymentRail.UPI,
        psp_payment_id=None,
        status=PaymentStatus.PENDING,
        amount_minor=1000,
        currency="INR",
        failure_code=None,
        created_at=now,
        updated_at=now,
    )
    assert p.rail == PaymentRail.UPI
    assert p.status == PaymentStatus.PENDING

    # Naive datetime rejection
    naive_dt = datetime(2026, 11, 27, 10, 0, 0)
    with pytest.raises(ValueError, match="timezone-aware"):
        Payment(
            payment_id="pay_1",
            proposal_id="prop_1",
            token_id=None,
            rail=PaymentRail.UPI,
            psp_payment_id=None,
            status=PaymentStatus.PENDING,
            amount_minor=1000,
            currency="INR",
            failure_code=None,
            created_at=naive_dt,
            updated_at=now,
        )


def test_mock_psp_webhook_payload_schema():
    """Test MockPspWebhookPayload parses actual webhook dispatcher output."""
    raw_payload = {
        "psp_event_id": "pspevt_01JD4D",
        "type": "payment.captured",
        "psp_payment_id": "psp_01JD4E",
        "payment_ref": "pay_01JD4C",
        "amount_minor": 7649900,
        "currency": "INR",
        "status": "CAPTURED",
        "occurred_at": "2026-11-27T10:14:05.000Z",
    }
    webhook = MockPspWebhookPayload.model_validate(raw_payload)
    assert webhook.psp_event_id == "pspevt_01JD4D"
    assert webhook.type == "payment.captured"
    assert webhook.amount_minor == 7649900
    assert webhook.status == "CAPTURED"


# --- 3. Protocol Implementation Compatibility Tests ---


def test_protocol_adherence_with_test_doubles():
    """Verify that test doubles correctly adhere to declared Protocol interfaces."""

    class DummyMandateClient:
        async def reserve_spend(
            self,
            mandate_id: str,
            proposal_id: str,
            amount_minor: int,
            currency: str,
            session: Any = None,
        ) -> Any:
            return {"reservation_id": "res_001", "status": "RESERVED"}

        async def commit_spend(self, reservation_id: str, session: Any = None) -> Any:
            return True

        async def release_spend(self, reservation_id: str, session: Any = None) -> Any:
            return True

        async def assert_usable(self, mandate_id: str, session: Any = None) -> Any:
            return True

    class DummyGroundingClient:
        async def get_proposal(self, proposal_id: str, session: Any = None) -> Any:
            return {"proposal_id": proposal_id}

        async def refetch_checkout(self, checkout_id: str, session: Any = None) -> Any:
            return {"checkout_id": checkout_id}

        async def complete_checkout(
            self, checkout_id: str, psp_payment_id: str, session: Any = None
        ) -> Any:
            return True

    class DummyDecisionProvider:
        async def get(self, decision_id: str, session: Any = None) -> Any:
            return {"decision_id": decision_id, "outcome": "ALLOW"}

        async def get_latest_for_proposal(self, proposal_id: str, session: Any = None) -> Any:
            return {"decision_id": "dec_001", "proposal_id": proposal_id, "outcome": "ALLOW"}

    class DummyPspClient:
        async def create_scoped_credential(self, req: Any) -> Any:
            return {"credential_id": "spc_001"}

        async def authorize_card(self, req: Any) -> Any:
            return {"status": "AUTHORIZED", "psp_payment_id": "psp_001"}

        async def capture_card(self, req: Any) -> Any:
            return {"status": "CAPTURED", "psp_payment_id": "psp_001"}

        async def create_upi_intent(self, req: Any) -> Any:
            return {"intent_id": "upi_001", "status": "PENDING"}

        async def get_payment_status(self, psp_payment_id: str) -> Any:
            return {"status": "SUCCESS"}

        async def get_public_jwks(self) -> Any:
            return {"keys": []}

    class DummyPaymentOrchestrator:
        async def execute(
            self, proposal_id: str, idempotency_key: str, session: Any = None
        ) -> PaymentExecuteResponse:
            return PaymentExecuteResponse(
                payment_id="pay_001",
                proposal_id=proposal_id,
                rail=PaymentRail.CARD,
                status=PaymentStatus.CAPTURED,
                amount_minor=100000,
                currency="INR",
                merchant_id="mer_croma",
            )

        async def get(self, payment_id: str, session: Any = None) -> PaymentStatusResponse | None:
            return None

        async def get_by_proposal(
            self, proposal_id: str, session: Any = None
        ) -> PaymentStatusResponse | None:
            return None

        async def process_webhook(
            self,
            payload: dict[str, Any],
            signature_header: str | None,
            session: Any = None,
        ) -> dict[str, Any]:
            return {"status": "ACCEPTED"}

        async def reconcile(
            self, timeout_threshold_seconds: int = 15, session: Any = None
        ) -> list[PaymentStatusResponse]:
            return []

    # Check structural subtyping
    mandate_client: MandateClient = DummyMandateClient()
    grounding_client: GroundingClient = DummyGroundingClient()
    decision_provider: DecisionProvider = DummyDecisionProvider()
    psp_client: PspClient = DummyPspClient()
    orchestrator: PaymentOrchestrator = DummyPaymentOrchestrator()

    assert mandate_client is not None
    assert grounding_client is not None
    assert decision_provider is not None
    assert psp_client is not None
    assert orchestrator is not None
