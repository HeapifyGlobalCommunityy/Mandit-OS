"""CI `migrations` check (CONTRIBUTING §8.6): migrations apply and roll back cleanly.

Against an EMPTY database at DATABASE_URL:
  1. upgrade to head and record the schema;
  2. downgrade to base and require that nothing but alembic_version is left behind;
  3. upgrade to head again and require the same schema as step 1.

Step 2 catches a downgrade() that forgets a table, trigger or function. Step 3 catches a downgrade
that leaves state which changes the next upgrade.

Usage: DATABASE_URL=postgresql+psycopg://... python scripts/ci/check_migrations.py
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text

ROOT = Path(__file__).resolve().parents[2]

# Everything a migration can create in the public schema, as comparable rows.
SCHEMA_QUERIES = {
    "columns": """
        SELECT table_name, column_name, data_type, is_nullable, column_default
        FROM information_schema.columns WHERE table_schema = 'public'""",
    "constraints": """
        SELECT conrelid::regclass::text, conname, pg_get_constraintdef(oid)
        FROM pg_constraint WHERE connamespace = 'public'::regnamespace""",
    "indexes": "SELECT tablename, indexname, indexdef FROM pg_indexes WHERE schemaname = 'public'",
    "triggers": """
        SELECT tgrelid::regclass::text, tgname, pg_get_triggerdef(oid)
        FROM pg_trigger WHERE NOT tgisinternal""",
    "functions": """
        SELECT p.proname, pg_get_function_identity_arguments(p.oid)
        FROM pg_proc p WHERE p.pronamespace = 'public'::regnamespace""",
    "sequences": """
        SELECT sequence_name FROM information_schema.sequences
        WHERE sequence_schema = 'public'""",
    "views": "SELECT table_name FROM information_schema.views WHERE table_schema = 'public'",
    "types": """
        SELECT t.typname FROM pg_type t
        WHERE t.typnamespace = 'public'::regnamespace AND t.typtype IN ('e', 'd')""",
}

Schema = dict[str, list[tuple[object, ...]]]


def snapshot(url: str) -> Schema:
    engine = create_engine(url)
    try:
        with engine.connect() as conn:
            return {
                name: sorted(tuple(row) for row in conn.execute(text(sql)))
                for name, sql in SCHEMA_QUERIES.items()
            }
    finally:
        engine.dispose()


def without_alembic(schema: Schema) -> Schema:
    """Drop rows that belong to alembic's own bookkeeping table."""
    return {
        kind: [r for r in rows if not (r and str(r[0]).endswith("alembic_version"))]
        for kind, rows in schema.items()
    }


def diff(a: Schema, b: Schema) -> list[str]:
    lines = []
    for kind in SCHEMA_QUERIES:
        only_a, only_b = set(a[kind]) - set(b[kind]), set(b[kind]) - set(a[kind])
        lines += [f"  {kind}: missing after re-upgrade: {r}" for r in sorted(only_a, key=str)]
        lines += [f"  {kind}: new after re-upgrade: {r}" for r in sorted(only_b, key=str)]
    return lines


def main() -> int:
    url = os.environ.get("DATABASE_URL")
    if not url:
        print("DATABASE_URL is not set", file=sys.stderr)
        return 2

    if any(without_alembic(snapshot(url)).values()):
        print("Database is not empty; run this check against a fresh database.", file=sys.stderr)
        return 2

    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "services/core/migrations"))

    print("1/3 upgrade head")
    command.upgrade(cfg, "head")
    first = snapshot(url)
    print(f"    {len({r[0] for r in first['columns']})} tables created")

    print("2/3 downgrade base")
    command.downgrade(cfg, "base")
    leftovers = {k: v for k, v in without_alembic(snapshot(url)).items() if v}
    if leftovers:
        print("FAIL: downgrade to base left objects behind:")
        for kind, rows in leftovers.items():
            for row in rows:
                print(f"  {kind}: {row}")
        return 1

    print("3/3 upgrade head again")
    command.upgrade(cfg, "head")
    problems = diff(first, snapshot(url))
    if problems:
        print("FAIL: schema differs after a downgrade/upgrade round trip:")
        print("\n".join(problems))
        return 1

    print("OK: migrations apply, roll back and re-apply cleanly")
    return 0


if __name__ == "__main__":
    sys.exit(main())
