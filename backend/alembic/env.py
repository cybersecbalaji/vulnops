"""
Alembic migration environment — configured for async SQLAlchemy + asyncpg.

Key design decisions:
- Uses create_async_engine with run_sync() to execute migrations synchronously
  within an async connection (required by asyncpg).
- Pulls DATABASE_URL from app settings to keep credentials in one place.
- Imports all models via app.models so autogenerate detects schema changes.
"""

from __future__ import annotations

import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy.ext.asyncio import create_async_engine

# Import settings early — this reads .env
from app.core.config import settings

# Import all models so Alembic autogenerate can detect them
import app.models  # noqa: F401
from app.db.base import Base

# Alembic Config object
config = context.config

# Override the sqlalchemy.url from alembic.ini with the real value from settings
config.set_main_option("sqlalchemy.url", settings.DATABASE_URL)

# Interpret the config file for Python logging
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


# ── Offline migrations ────────────────────────────────────────────────────────

def run_migrations_offline() -> None:
    """Generate SQL script without a live DB connection (useful for review)."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


# ── Online migrations ─────────────────────────────────────────────────────────

def do_run_migrations(connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    """Run migrations against a live async database connection."""
    connectable = create_async_engine(
        settings.DATABASE_URL,
        echo=False,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
