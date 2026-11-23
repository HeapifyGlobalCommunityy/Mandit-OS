"""Team 1: identity and mandates (modules/01 section 4)

Revision ID: 0001
Revises:
"""
from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

TABLES = [
    "mandate_spend", "mandates", "user_keys", "agent_credentials",
    "agent_challenges", "agent_keys", "agents", "operators",
]

STATEMENTS = [
    """CREATE TABLE operators (
  operator_id     TEXT PRIMARY KEY,
  legal_name      TEXT NOT NULL,
  domain          TEXT NOT NULL,
  contact_email   TEXT NOT NULL,
  status          TEXT NOT NULL CHECK (status IN ('PENDING','VERIFIED','SUSPENDED')),
  verified_at     TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
)""",
    """CREATE TABLE agents (
  agent_id        TEXT PRIMARY KEY,
  operator_id     TEXT NOT NULL REFERENCES operators(operator_id),
  name            TEXT NOT NULL,
  version         TEXT NOT NULL,
  model_declared  TEXT,
  scopes          TEXT[] NOT NULL,
  status          TEXT NOT NULL CHECK (status IN ('ACTIVE','REVOKED')),
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_at      TIMESTAMPTZ,
  revoked_reason  TEXT
)""",
    """CREATE TABLE agent_keys (
  key_id          TEXT PRIMARY KEY,
  agent_id        TEXT NOT NULL REFERENCES agents(agent_id),
  jwk             JSONB NOT NULL,
  thumbprint      TEXT NOT NULL UNIQUE,
  status          TEXT NOT NULL CHECK (status IN ('ACTIVE','RETIRED','REVOKED')),
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  retired_at      TIMESTAMPTZ
)""",
    """CREATE TABLE agent_challenges (
  challenge_id    TEXT PRIMARY KEY,
  agent_id        TEXT NOT NULL,
  key_id          TEXT NOT NULL,
  nonce           TEXT NOT NULL,
  expires_at      TIMESTAMPTZ NOT NULL,
  consumed_at     TIMESTAMPTZ
)""",
    """CREATE TABLE agent_credentials (
  jti             TEXT PRIMARY KEY,
  agent_id        TEXT NOT NULL,
  key_id          TEXT NOT NULL,
  issued_at       TIMESTAMPTZ NOT NULL,
  expires_at      TIMESTAMPTZ NOT NULL
)""",
    """CREATE TABLE user_keys (
  key_id          TEXT PRIMARY KEY,
  user_id         TEXT NOT NULL,
  alg             TEXT NOT NULL CHECK (alg IN ('ES256')),
  jwk             JSONB NOT NULL,
  status          TEXT NOT NULL CHECK (status IN ('ACTIVE','REVOKED')),
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
)""",
    """CREATE TABLE mandates (
  mandate_id            TEXT NOT NULL,
  version               INT  NOT NULL,
  user_id               TEXT NOT NULL,
  agent_id              TEXT NOT NULL,
  agent_key_thumbprint  TEXT NOT NULL,
  task_description      TEXT NOT NULL,
  constraints           JSONB NOT NULL,
  not_before            TIMESTAMPTZ NOT NULL,
  expires_at            TIMESTAMPTZ NOT NULL,
  nonce                 TEXT NOT NULL,
  supersedes            TEXT,
  signature             JSONB NOT NULL,
  digest                TEXT NOT NULL,
  status                TEXT NOT NULL CHECK (status IN
                          ('ACTIVE','EXPIRED','REVOKED','SUPERSEDED','EXHAUSTED','REJECTED')),
  created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (mandate_id, version)
)""",
    """CREATE TABLE mandate_spend (
  reservation_id  TEXT PRIMARY KEY,
  mandate_id      TEXT NOT NULL,
  proposal_id     TEXT NOT NULL UNIQUE,
  amount_minor    BIGINT NOT NULL CHECK (amount_minor > 0),
  currency        CHAR(3) NOT NULL,
  status          TEXT NOT NULL CHECK (status IN ('RESERVED','COMMITTED','RELEASED')),
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
