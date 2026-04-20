"""
Auth security utilities:
- Password hashing (bcrypt cost factor 12)
- JWT RS256 creation / verification
- Refresh token generation (opaque hex + SHA-256 hash)
- HaveIBeenPwned k-anonymity breach check
- Account lockout via Redis
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
from jose import JWTError, jwt
from passlib.context import CryptContext

from app.core.config import settings

# ── Password hashing ──────────────────────────────────────────────────────────
# bcrypt cost factor 12 per PRD requirement
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=12)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


# ── JWT ───────────────────────────────────────────────────────────────────────

def create_access_token(
    user_id: str,
    org_id: str,
    role: str,
) -> str:
    """Create a short-lived RS256 JWT access token."""
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
    payload: dict[str, Any] = {
        "sub": user_id,
        "org_id": org_id,
        "role": role,
        "type": "access",
        "iat": now,
        "exp": expire,
    }
    return jwt.encode(payload, settings.JWT_PRIVATE_KEY, algorithm=settings.JWT_ALGORITHM)


def verify_access_token(token: str) -> dict[str, Any]:
    """
    Verify and decode a JWT access token.
    Raises JWTError (from python-jose) on any failure.
    """
    payload = jwt.decode(
        token,
        settings.JWT_PUBLIC_KEY,
        algorithms=[settings.JWT_ALGORITHM],
    )
    if payload.get("type") != "access":
        raise JWTError("Token type mismatch")
    return payload


# ── Refresh token ─────────────────────────────────────────────────────────────

def generate_refresh_token() -> tuple[str, str]:
    """
    Generate a cryptographically random refresh token.

    Returns:
        (raw_token, sha256_hash)
        - raw_token: sent to client as HttpOnly cookie
        - sha256_hash: stored in DB (never the raw value)
    """
    raw = secrets.token_hex(32)  # 256-bit entropy
    token_hash = hashlib.sha256(raw.encode()).hexdigest()
    return raw, token_hash


def hash_refresh_token(raw: str) -> str:
    """Hash a raw refresh token for DB lookup."""
    return hashlib.sha256(raw.encode()).hexdigest()


# ── Password policy ───────────────────────────────────────────────────────────

def validate_password_strength(password: str) -> list[str]:
    """Return a list of policy violations. Empty list = valid."""
    errors: list[str] = []
    if len(password) < 12:
        errors.append("Password must be at least 12 characters long.")
    return errors


async def is_password_pwned(password: str) -> bool:
    """
    Check HaveIBeenPwned using k-anonymity (only first 5 hex chars of SHA-1 sent).
    Returns True if the password appears in a known breach.
    Never raises — network failures are treated as "not found" to avoid blocking UX.
    """
    sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(
                f"https://api.pwnedpasswords.com/range/{prefix}",
                headers={"Add-Padding": "true"},
            )
            if resp.status_code == 200:
                for line in resp.text.splitlines():
                    line_suffix, _ = line.split(":")
                    if line_suffix.strip() == suffix:
                        return True
    except httpx.RequestError:
        pass  # Network error — fail open (allow password)
    return False


# ── Account lockout (Redis) ───────────────────────────────────────────────────

async def is_account_locked(redis: Any, email: str) -> bool:
    """Return True if the account is currently locked out."""
    locked = await redis.get(f"auth:locked:{email}")
    return locked is not None


async def record_failed_login(redis: Any, email: str) -> int:
    """
    Increment the failed-attempt counter.
    Locks the account for LOCKOUT_MINUTES after MAX_LOGIN_ATTEMPTS failures.
    Returns the current attempt count.
    """
    key = f"auth:attempts:{email}"
    count = await redis.incr(key)
    # Reset TTL on each failure so the window slides
    await redis.expire(key, settings.LOCKOUT_MINUTES * 60)

    if count >= settings.MAX_LOGIN_ATTEMPTS:
        await redis.setex(
            f"auth:locked:{email}",
            settings.LOCKOUT_MINUTES * 60,
            "1",
        )
    return count


async def reset_failed_logins(redis: Any, email: str) -> None:
    """Clear counters on successful login."""
    await redis.delete(f"auth:attempts:{email}")
    await redis.delete(f"auth:locked:{email}")
