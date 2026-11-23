"""Team 4: decisions, confirmations, tokens, payments (modules/04 section 4)

Revision ID: 0004
Revises: 0003
"""
from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None

TABLES = [
    "idempotency_keys", "psp_webhook_events", "payments",
    "payment_tokens", "confirmations", "decisions",
]

STATEMENTS = [
    """CREATE TABLE decisions (
  decision_id         TEXT PRIMARY KEY,
  proposal_id         TEXT NOT NULL,
  proposal_hash       TEXT NOT NULL,
  transaction_id      TEXT NOT NULL,
  attempt             INT  NOT NULL,
  outcome             TEXT NOT NULL CHECK (outcome IN ('ALLOW','STEP_UP','RETRIEVE_MORE','BLOCK')),
  stage               TEXT NOT NULL CHECK (stage IN ('HARD_GATE','RULE','TRUST_SCORE','CONFIRMATION')),
  rules_fired         JSONB NOT NULL,
  trust_score         NUMERIC(4,3),
  policy_version      TEXT NOT NULL,
  trust_model_version TEXT,
  inputs_snapshot_id  TEXT NOT NULL,
  inputs_hash         TEXT NOT NULL,
  confirmation_id     TEXT,
  expires_at          TIMESTAMPTZ NOT NULL,
  signature           JSONB NOT NULL,
  created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
)""",
    """CREATE TABLE confirmations (
  confirmation_id     TEXT PRIMARY KEY,
  decision_id         TEXT NOT NULL,
  proposal_id         TEXT NOT NULL,
  proposal_hash       TEXT NOT NULL,
  user_id             TEXT NOT NULL,
  display             JSONB NOT NULL,
  challenge           TEXT NOT NULL,
  status              TEXT NOT NULL CHECK (status IN ('PENDING','APPROVED','REJECTED','EXPIRED','INVALIDATED')),
  response_signature  JSONB,
  responded_at        TIMESTAMPTZ,
  expires_at          TIMESTAMPTZ NOT NULL
)""",
    """CREATE TABLE payment_tokens (
  token_id        TEXT PRIMARY KEY,
  proposal_id     TEXT NOT NULL UNIQUE,
  decision_id     TEXT NOT NULL,
  mandate_id      TEXT NOT NULL,
  reservation_id  TEXT NOT NULL,
  merchant_id     TEXT NOT NULL,
  payee_id        TEXT NOT NULL,
  amount_minor    BIGINT NOT NULL CHECK (amount_minor > 0),
  currency        CHAR(3) NOT NULL,
  checkout_hash   TEXT NOT NULL,
  rail            TEXT NOT NULL CHECK (rail IN ('CARD','UPI')),
  status          TEXT NOT NULL CHECK (status IN
                    ('ISSUED','REDEEMING','REDEEMED','FAILED','UNKNOWN','EXPIRED','REVOKED')),
  idem_key        TEXT,
  expires_at      TIMESTAMPTZ NOT NULL,
  issued_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  redeemed_at     TIMESTAMPTZ
)""",
    """CREATE TABLE payments (
  payment_id      TEXT PRIMARY KEY,
  proposal_id     TEXT NOT NULL UNIQUE,
  token_id        TEXT,
  rail            TEXT NOT NULL,
  psp_payment_id  TEXT,
  status          TEXT NOT NULL,
  amount_minor    BIGINT NOT NULL,
  currency        CHAR(3) NOT NULL,
  failure_code    TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
)""",
    """CREATE TABLE psp_webhook_events (
  psp_event_id    TEXT PRIMARY KEY,
  payment_id      TEXT NOT NULL,
  body_hash       TEXT NOT NULL,
  received_at     TIMESTAMPTZ NOT NULL DEFAULT now()
)""",
    """CREATE TABLE idempotency_keys (
  key             TEXT PRIMARY KEY,
  route           TEXT NOT NULL,
  request_hash    TEXT NOT NULL,
  response_status INT,
  response_body   JSONB,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
)""",
]


def upgrade() -> None:
    conn = op.get_bind()
    for stmt in STATEMENTS:
        conn.exec_driver_sql(stmt)


def downgrade() -> None:
    conn = op.get_bind()
    for t in TABLES:
        conn.exec_driver_sql(f"DROP TABLE IF EXISTS {t}")
