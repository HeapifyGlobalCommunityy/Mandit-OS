"""Team 2: gateway and safety scanning (modules/02 section 4)

Revision ID: 0002
Revises: 0001
"""
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

TABLES = ["domain_reputation", "injection_findings", "scan_reports", "content_records", "tool_calls"]

STATEMENTS = [
    """CREATE TABLE tool_calls (
  tool_call_id    TEXT PRIMARY KEY,
  transaction_id  TEXT NOT NULL,
  agent_id        TEXT NOT NULL,
  tool_name       TEXT NOT NULL,
  args_hash       TEXT NOT NULL,
  args            JSONB NOT NULL,
  outcome         TEXT NOT NULL CHECK (outcome IN ('OK','DENIED','ERROR')),
  deny_code       TEXT,
  latency_ms      INT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
)""",
    """CREATE TABLE content_records (
  content_id      TEXT PRIMARY KEY,
  transaction_id  TEXT NOT NULL,
  tool_call_id    TEXT,
  source_type     TEXT NOT NULL CHECK (source_type IN
                    ('MERCHANT_API','WEB_PAGE','SEARCH_RESULT','TOOL_RESPONSE')),
  source_url      TEXT NOT NULL,
  domain          TEXT NOT NULL,
  content_hash    TEXT NOT NULL,
  blob_ref        TEXT NOT NULL,
  classification  TEXT NOT NULL,
  trust_label     TEXT NOT NULL DEFAULT 'UNTRUSTED' CHECK (trust_label = 'UNTRUSTED'),
  fetched_at      TIMESTAMPTZ NOT NULL,
  scan_id         TEXT
)""",
    """CREATE TABLE scan_reports (
  scan_id             TEXT PRIMARY KEY,
  content_id          TEXT NOT NULL,
  site_risk_score     NUMERIC(4,3) NOT NULL,
  site_risk_level     TEXT NOT NULL,
  site_signals        JSONB NOT NULL,
  injection_detected  BOOLEAN NOT NULL,
  injection_severity  TEXT NOT NULL,
  scanner_version     TEXT NOT NULL,
  detectors_enabled   TEXT[] NOT NULL,
  created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
)""",
    """CREATE TABLE injection_findings (
  finding_id      TEXT PRIMARY KEY,
  scan_id         TEXT NOT NULL,
  technique       TEXT NOT NULL,
  severity        TEXT NOT NULL,
  targets         TEXT[] NOT NULL,
  locator         JSONB NOT NULL,
  excerpt         TEXT NOT NULL,
  confidence      NUMERIC(4,3) NOT NULL
)""",
    """CREATE TABLE domain_reputation (
  domain          TEXT PRIMARY KEY,
  first_seen      DATE,
  reputation      TEXT NOT NULL CHECK (reputation IN ('GOOD','UNKNOWN','BAD')),
  source          TEXT NOT NULL,
  updated_at      TIMESTAMPTZ NOT NULL
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
