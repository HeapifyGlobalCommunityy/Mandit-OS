"""Alembic environment. The database URL comes from DATABASE_URL (see .env.example)."""

import os

from alembic import context
from dotenv import load_dotenv
from sqlalchemy import create_engine

load_dotenv()
config = context.config

# Phase 1 migrations are hand-written SQL, so there is no model metadata yet.
# Once SQLAlchemy models exist, point this at Base.metadata for autogenerate.
target_metadata = None


def _url() -> str:
    url = os.environ.get("DATABASE_URL")
    if not url:
        raise RuntimeError("DATABASE_URL is not set. Copy .env.example to .env.")
    return url


def run_migrations_offline() -> None:
    context.configure(url=_url(), target_metadata=target_metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    engine = create_engine(_url())
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
