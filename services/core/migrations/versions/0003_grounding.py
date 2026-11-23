"""Team 3: merchant registry and grounded fact ledger (modules/03 sections 5 and 9)

Revision ID: 0003
Revises: 0002
"""
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None

STATEMENTS = [
    """CREATE TABLE merchants (
  merchant_id     TEXT PRIMARY KEY,
  legal_name      TEXT NOT NULL,
  domains         TEXT[] NOT NULL,
  payees          JSONB NOT NULL,
  categories      TEXT[] NOT NULL,
  base_url        TEXT NOT NULL,
  status          TEXT NOT NULL CHECK (status IN ('VERIFIED','SUSPENDED')),
  onboarded_at    TIMESTAMPTZ NOT NULL
)""",
    """CREATE TABLE merchant_keys (
  kid         TEXT PRIMARY KEY,
  merchant_id TEXT NOT NULL,
  jwk         JSONB NOT NULL,
  status      TEXT NOT NULL
)""",
    """CREATE TABLE facts (
  fact_id         TEXT PRIMARY KEY,
  proposal_id     TEXT NOT NULL,
  claim_id        TEXT NOT NULL,
  statement       JSONB NOT NULL,
  source_type     TEXT NOT NULL,
  source_ref      TEXT NOT NULL,
  source_hash     TEXT NOT NULL,
  observed_at     TIMESTAMPTZ NOT NULL,
  status          TEXT NOT NULL,
  confidence      NUMERIC(4,3) NOT NULL,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
)""",
    # The facts table is insert-only for the application role (when that role exists).
    """DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mandit_app') THEN
    REVOKE UPDATE, DELETE, TRUNCATE ON facts FROM mandit_app;
    GRANT INSERT, SELECT ON facts TO mandit_app;
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
    for t in ["facts", "merchant_keys", "merchants"]:
        conn.exec_driver_sql(f"DROP TABLE IF EXISTS {t}")
