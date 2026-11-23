"""Team 5: transactions and the append-only evidence ledger (modules/05 section 4)

Revision ID: 0005
Revises: 0004
"""
from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None

STATEMENTS = [
    """CREATE TABLE transactions (
  transaction_id  TEXT PRIMARY KEY,
  mandate_id      TEXT NOT NULL,
  agent_id        TEXT NOT NULL,
  user_id         TEXT NOT NULL,
  status          TEXT NOT NULL CHECK (status IN ('OPEN','PAID','BLOCKED','ABANDONED','FAILED')),
  final_outcome   TEXT,
  opened_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  closed_at       TIMESTAMPTZ
)""",
    """CREATE TABLE ledger_events (
  seq             BIGINT PRIMARY KEY,
  event_id        TEXT UNIQUE NOT NULL,
  transaction_id  TEXT,
  event_type      TEXT NOT NULL,
  schema_version  INT  NOT NULL,
  producer        TEXT NOT NULL,
  actor           JSONB NOT NULL,
  refs            JSONB NOT NULL,
  payload_hash    TEXT NOT NULL,
  prev_hash       TEXT NOT NULL,
  event_hash      TEXT NOT NULL UNIQUE,
  signer_key_id   TEXT NOT NULL,
  signature       TEXT NOT NULL,
  occurred_at     TIMESTAMPTZ NOT NULL
)""",
    """CREATE TABLE ledger_payloads (
  payload_hash    TEXT PRIMARY KEY,
  payload         JSONB NOT NULL
)""",
    """CREATE TABLE snapshots (
  snapshot_id     TEXT PRIMARY KEY,
  transaction_id  TEXT NOT NULL,
  kind            TEXT NOT NULL,
  digest          TEXT NOT NULL,
  body            JSONB NOT NULL,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
)""",
    """CREATE TABLE replays (
  replay_id        TEXT PRIMARY KEY,
  transaction_id   TEXT NOT NULL,
  decision_id      TEXT NOT NULL,
  policy_version   TEXT NOT NULL,
  original_outcome TEXT NOT NULL,
  replayed_outcome TEXT NOT NULL,
  match            BOOLEAN NOT NULL,
  diff             JSONB,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
)""",
    """CREATE TABLE event_outbox (
  outbox_id       BIGSERIAL PRIMARY KEY,
  event_draft     JSONB NOT NULL,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  appended_at     TIMESTAMPTZ
)""",
    """CREATE FUNCTION raise_immutable() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'ledger_events is append-only (%% blocked)', TG_OP;
END;
$$ LANGUAGE plpgsql""",
    """CREATE TRIGGER ledger_no_mutation BEFORE UPDATE OR DELETE ON ledger_events
  FOR EACH ROW EXECUTE FUNCTION raise_immutable()""",
    # Append-only for the application role (when that role exists).
    """DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mandit_app') THEN
    REVOKE UPDATE, DELETE, TRUNCATE ON ledger_events, ledger_payloads, snapshots FROM mandit_app;
    GRANT INSERT, SELECT ON ledger_events, ledger_payloads, snapshots TO mandit_app;
  END IF;
END
$$""",
]


def upgrade() -> None:
    conn = op.get_bind()
    for stmt in STATEMENTS:
        conn.exec_driver_sql(stmt)


def downgrade() -> None:
    conn = op.get_bind()
    conn.exec_driver_sql("DROP TRIGGER IF EXISTS ledger_no_mutation ON ledger_events")
    conn.exec_driver_sql("DROP FUNCTION IF EXISTS raise_immutable()")
    for t in ["event_outbox", "replays", "snapshots", "ledger_payloads", "ledger_events", "transactions"]:
        conn.exec_driver_sql(f"DROP TABLE IF EXISTS {t}")
