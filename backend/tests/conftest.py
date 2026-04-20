"""
Test configuration — in-memory SQLite + mocked Redis.

IMPORTANT: Environment variables MUST be set before any app imports because
pydantic-settings reads them at class instantiation time (module level).
We generate minimal valid secrets here so Settings() doesn't raise.
"""

from __future__ import annotations

# ── 1. Set env vars BEFORE any app import ────────────────────────────────────
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# Generate a real Fernet master key
_FERNET_KEY = Fernet.generate_key().decode()

# Generate a real RSA 2048 key pair (faster than 4096 for tests)
_RSA_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_RSA_PRIVATE_PEM = _RSA_KEY.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.TraditionalOpenSSL,
    serialization.NoEncryption(),
).decode()
_RSA_PUBLIC_PEM = _RSA_KEY.public_key().public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo,
).decode()

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("MASTER_ENCRYPTION_KEY", _FERNET_KEY)
os.environ.setdefault("JWT_PRIVATE_KEY", _RSA_PRIVATE_PEM)
os.environ.setdefault("JWT_PUBLIC_KEY", _RSA_PUBLIC_PEM)
os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")  # will be mocked
os.environ.setdefault("CORS_ORIGINS", '["http://localhost:3000"]')

# ── 2. Clear the lru_cache so Settings() re-reads our env vars ───────────────
from app.core.config import get_settings
get_settings.cache_clear()

# ── 3. Now import app components ──────────────────────────────────────────────
from typing import AsyncGenerator
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.db.base import Base
from app.db.session import get_db, get_redis
from app.main import app

# ── SQLite in-memory engine ───────────────────────────────────────────────────

@pytest_asyncio.fixture(scope="session")
async def test_engine():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture()
async def db_session(test_engine) -> AsyncGenerator[AsyncSession, None]:
    session_factory = async_sessionmaker(
        bind=test_engine,
        expire_on_commit=False,
        autoflush=False,
        autocommit=False,
    )
    async with session_factory() as session:
        yield session
        await session.rollback()


# ── Mock Redis ────────────────────────────────────────────────────────────────

@pytest.fixture()
def mock_redis():
    redis = AsyncMock()
    redis.get = AsyncMock(return_value=None)   # no lockout by default
    redis.incr = AsyncMock(return_value=1)
    redis.expire = AsyncMock()
    redis.setex = AsyncMock()
    redis.delete = AsyncMock()
    redis.ping = AsyncMock(return_value=True)
    redis.aclose = AsyncMock()
    return redis


# ── Test HTTP client ──────────────────────────────────────────────────────────

@pytest_asyncio.fixture()
async def client(db_session: AsyncSession, mock_redis) -> AsyncGenerator[AsyncClient, None]:
    """
    Provides an AsyncClient wired to the FastAPI app with:
    - SQLite in-memory database (no live Postgres needed)
    - Mocked Redis (no live Redis needed)
    """
    # Override FastAPI dependencies
    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_redis] = lambda: mock_redis

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as ac:
        yield ac

    app.dependency_overrides.clear()
