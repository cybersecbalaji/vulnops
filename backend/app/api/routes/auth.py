"""
Auth routes:
  POST /auth/register  — create org + admin user (first-user registration)
  POST /auth/login     — issue access token + set refresh-token HttpOnly cookie
  POST /auth/refresh   — rotate refresh token, issue new access token
  POST /auth/logout    — revoke refresh token, clear cookie
  GET  /auth/me        — return current user info + fresh access token
  POST /auth/change-password — change authenticated user's password
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timedelta, timezone

from fastapi.responses import Response as HTTPResponse

import redis.asyncio as aioredis
from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.core.config import settings
from app.core.encryption import FieldEncryption, MasterKeyEncryption
from app.core.security import (
    create_access_token,
    generate_refresh_token,
    hash_password,
    hash_refresh_token,
    is_account_locked,
    is_password_pwned,
    record_failed_login,
    reset_failed_logins,
    validate_password_strength,
    verify_password,
)
from app.db.session import get_db, get_redis
from app.models.organization import Organization, OrgSettings
from app.models.refresh_token import RefreshToken
from app.models.user import User
from app.schemas.auth import (
    LoginRequest,
    MeResponse,
    PasswordChangeRequest,
    RegisterRequest,
    SessionInfo,
    TokenResponse,
    UserPublic,
)

router = APIRouter()

# ── Cookie settings ───────────────────────────────────────────────────────────
REFRESH_COOKIE_NAME = "refresh_token"
REFRESH_COOKIE_MAX_AGE = settings.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60  # seconds


def _set_refresh_cookie(response: Response, raw_token: str) -> None:
    response.set_cookie(
        key=REFRESH_COOKIE_NAME,
        value=raw_token,
        max_age=REFRESH_COOKIE_MAX_AGE,
        httponly=True,
        secure=settings.APP_ENV != "development",  # Secure in prod; allow HTTP in dev
        samesite="strict",
        path="/",  # Root path so Next.js middleware can see the cookie for auth checks
    )


def _clear_refresh_cookie(response: Response) -> None:
    response.delete_cookie(
        key=REFRESH_COOKIE_NAME,
        path="/",
        httponly=True,
        samesite="strict",
    )


def _build_token_response(user: User) -> dict:
    access_token = create_access_token(
        user_id=str(user.id),
        org_id=str(user.org_id),
        role=user.role,
    )
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    }


def _slug_from_name(name: str) -> str:
    """Generate a URL-safe slug from an org name."""
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return slug[:50] + "-" + uuid.uuid4().hex[:6]


# ── POST /auth/register ───────────────────────────────────────────────────────

@router.post("/register", response_model=MeResponse, status_code=status.HTTP_201_CREATED)
async def register(
    body: RegisterRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
    redis: aioredis.Redis = Depends(get_redis),
) -> MeResponse:
    """
    Create a new organization and its first admin user.
    - Validates password strength
    - Checks HaveIBeenPwned (k-anonymity)
    - Creates org DEK encrypted with master key
    - Creates user with bcrypt(cost=12) password hash
    - Issues access token (body) + refresh token (HttpOnly cookie)
    """
    # ── Password policy ────────────────────────────────────────────────────
    errors = validate_password_strength(body.password)
    if errors:
        raise HTTPException(status_code=422, detail=errors[0])

    # ── HIBP breach check ──────────────────────────────────────────────────
    if await is_password_pwned(body.password):
        raise HTTPException(
            status_code=422,
            detail=(
                "This password has appeared in a known data breach. "
                "Please choose a different password."
            ),
        )

    # ── Check email uniqueness ─────────────────────────────────────────────
    existing = await db.execute(select(User).where(User.email == body.email))
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=409,
            detail="An account with this email address already exists.",
        )

    # ── Create organization + DEK ──────────────────────────────────────────
    master = MasterKeyEncryption(settings.MASTER_ENCRYPTION_KEY)
    dek = master.generate_dek()
    encrypted_dek = master.encrypt_dek(dek)

    org = Organization(
        name=body.org_name,
        slug=_slug_from_name(body.org_name),
        encrypted_dek=encrypted_dek,
    )
    db.add(org)
    await db.flush()  # get org.id without committing

    # ── Create org settings (defaults) ────────────────────────────────────
    org_settings = OrgSettings(org_id=org.id)
    db.add(org_settings)

    # ── Create admin user ──────────────────────────────────────────────────
    user = User(
        org_id=org.id,
        email=body.email,
        password_hash=hash_password(body.password),
        role="admin",
    )
    db.add(user)
    await db.flush()  # get user.id

    # ── Issue refresh token ────────────────────────────────────────────────
    raw_token, token_hash = generate_refresh_token()
    refresh_record = RefreshToken(
        user_id=user.id,
        token_hash=token_hash,
        expires_at=datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
        user_agent=request.headers.get("user-agent"),
        ip_address=request.client.host if request.client else None,
    )
    db.add(refresh_record)
    # Commit everything atomically
    await db.commit()

    # ── Build and return response ──────────────────────────────────────────
    token_data = _build_token_response(user)
    _set_refresh_cookie(response, raw_token)

    return MeResponse(user=UserPublic.model_validate(user), **token_data)


# ── POST /auth/login ──────────────────────────────────────────────────────────

@router.post("/login", response_model=MeResponse)
async def login(
    body: LoginRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
    redis: aioredis.Redis = Depends(get_redis),
) -> MeResponse:
    """
    Authenticate a user.
    - Checks account lockout (10 failures → 15-min lockout)
    - Verifies bcrypt password
    - Rotates any existing refresh tokens (issues new one)
    - Returns access token in body + refresh token as HttpOnly cookie
    """
    email_lower = body.email.lower().strip()

    # ── Lockout check ──────────────────────────────────────────────────────
    if await is_account_locked(redis, email_lower):
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail=(
                f"Account temporarily locked due to too many failed login attempts. "
                f"Please try again in {settings.LOCKOUT_MINUTES} minutes."
            ),
        )

    # ── Find user ──────────────────────────────────────────────────────────
    result = await db.execute(select(User).where(User.email == email_lower))
    user = result.scalar_one_or_none()

    # Constant-time failure path (avoid user enumeration via timing)
    if user is None or not verify_password(body.password, user.password_hash):
        await record_failed_login(redis, email_lower)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email address or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This account has been deactivated.",
        )

    # ── Successful auth — reset lockout counter ────────────────────────────
    await reset_failed_logins(redis, email_lower)

    # ── Update last_login ──────────────────────────────────────────────────
    user.last_login = datetime.now(timezone.utc)

    # ── Issue new refresh token ────────────────────────────────────────────
    raw_token, token_hash = generate_refresh_token()
    refresh_record = RefreshToken(
        user_id=user.id,
        token_hash=token_hash,
        expires_at=datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
        user_agent=request.headers.get("user-agent"),
        ip_address=request.client.host if request.client else None,
    )
    db.add(refresh_record)
    await db.commit()

    token_data = _build_token_response(user)
    _set_refresh_cookie(response, raw_token)

    return MeResponse(user=UserPublic.model_validate(user), **token_data)


# ── POST /auth/refresh ────────────────────────────────────────────────────────

@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
    refresh_token: str | None = Cookie(default=None, alias=REFRESH_COOKIE_NAME),
) -> TokenResponse:
    """
    Exchange a valid refresh token (HttpOnly cookie) for a new access token.
    The refresh token is rotated on every call — the old one is revoked.
    """
    invalid_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Refresh token is missing, invalid, or expired.",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if not refresh_token:
        raise invalid_exc

    token_hash = hash_refresh_token(refresh_token)

    # ── Look up token record ───────────────────────────────────────────────
    result = await db.execute(
        select(RefreshToken).where(RefreshToken.token_hash == token_hash)
    )
    record = result.scalar_one_or_none()

    if record is None or not record.is_active:
        # Possible token reuse — clear the cookie to help the client
        _clear_refresh_cookie(response)
        raise invalid_exc

    # ── Load user ──────────────────────────────────────────────────────────
    user = await db.get(User, record.user_id)
    if user is None or not user.is_active:
        _clear_refresh_cookie(response)
        raise invalid_exc

    # ── Rotate: revoke old token, issue new one (atomic) ──────────────────
    record.revoked_at = datetime.now(timezone.utc)

    raw_new, new_hash = generate_refresh_token()
    new_record = RefreshToken(
        user_id=user.id,
        token_hash=new_hash,
        expires_at=datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
        user_agent=request.headers.get("user-agent"),
        ip_address=request.client.host if request.client else None,
    )
    db.add(new_record)
    await db.commit()

    token_data = _build_token_response(user)
    _set_refresh_cookie(response, raw_new)

    return TokenResponse(**token_data)


# ── POST /auth/logout ─────────────────────────────────────────────────────────

@router.post("/logout")
async def logout(
    response: Response,
    db: AsyncSession = Depends(get_db),
    refresh_token: str | None = Cookie(default=None, alias=REFRESH_COOKIE_NAME),
) -> HTTPResponse:
    """
    Revoke the current refresh token and clear the HttpOnly cookie.
    Silently succeeds even if the token is already revoked or missing.
    """
    if refresh_token:
        token_hash = hash_refresh_token(refresh_token)
        result = await db.execute(
            select(RefreshToken).where(RefreshToken.token_hash == token_hash)
        )
        record = result.scalar_one_or_none()
        if record and record.revoked_at is None:
            record.revoked_at = datetime.now(timezone.utc)
            await db.commit()

    # Build the response first, then clear the cookie on IT (not on the injected
    # dependency `response`), so the Set-Cookie header is on the response FastAPI sends.
    resp = HTTPResponse(status_code=204)
    _clear_refresh_cookie(resp)
    return resp


# ── GET /auth/me ──────────────────────────────────────────────────────────────

@router.get("/me", response_model=MeResponse)
async def get_me(
    current_user: User = Depends(get_current_user),
) -> MeResponse:
    """Return the authenticated user's profile + a fresh access token."""
    token_data = _build_token_response(current_user)
    return MeResponse(
        user=UserPublic.model_validate(current_user),
        **token_data,
    )


# ── POST /auth/change-password ────────────────────────────────────────────────

@router.post("/change-password")
async def change_password(
    body: PasswordChangeRequest,
    response: Response,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    redis: aioredis.Redis = Depends(get_redis),
) -> HTTPResponse:
    """
    Change the authenticated user's password.
    - Verifies current password
    - Validates new password strength + HIBP check
    - Revokes ALL existing refresh tokens (force re-login everywhere)
    """
    if not verify_password(body.current_password, current_user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect.",
        )

    errors = validate_password_strength(body.new_password)
    if errors:
        raise HTTPException(status_code=422, detail=errors[0])

    if await is_password_pwned(body.new_password):
        raise HTTPException(
            status_code=422,
            detail=(
                "This password has appeared in a known data breach. "
                "Please choose a different password."
            ),
        )

    current_user.password_hash = hash_password(body.new_password)

    # Revoke all active refresh tokens for this user
    tokens_result = await db.execute(
        select(RefreshToken).where(
            RefreshToken.user_id == current_user.id,
            RefreshToken.revoked_at.is_(None),
        )
    )
    now = datetime.now(timezone.utc)
    for token in tokens_result.scalars().all():
        token.revoked_at = now

    await db.commit()
    resp = HTTPResponse(status_code=204)
    _clear_refresh_cookie(resp)
    return resp


# ── GET /auth/sessions ────────────────────────────────────────────────────────

@router.get("/sessions", response_model=list[SessionInfo])
async def list_sessions(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    refresh_token: str | None = Cookie(default=None, alias=REFRESH_COOKIE_NAME),
) -> list[SessionInfo]:
    """Return all active sessions for the current user."""
    result = await db.execute(
        select(RefreshToken).where(
            RefreshToken.user_id == current_user.id,
            RefreshToken.revoked_at.is_(None),
            RefreshToken.expires_at > datetime.now(timezone.utc),
        )
    )
    sessions = result.scalars().all()

    current_hash = hash_refresh_token(refresh_token) if refresh_token else None

    return [
        SessionInfo(
            id=s.id,
            created_at=s.created_at,
            expires_at=s.expires_at,
            user_agent=s.user_agent,
            ip_address=s.ip_address,
            is_current=(current_hash is not None and s.token_hash == current_hash),
        )
        for s in sessions
    ]


# ── DELETE /auth/sessions/{session_id} ───────────────────────────────────────

@router.delete("/sessions/{session_id}")
async def revoke_session(
    session_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> HTTPResponse:
    """Revoke a specific session by ID (own sessions only, unless admin)."""
    result = await db.execute(
        select(RefreshToken).where(RefreshToken.id == session_id)
    )
    session = result.scalar_one_or_none()

    if session is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found.")

    # Users can revoke their own sessions; admins can revoke any session in the org
    if session.user_id != current_user.id:
        if current_user.role != "admin":
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied.")
        # Admin: verify the target user is in the same org
        target_user = await db.get(User, session.user_id)
        if target_user is None or target_user.org_id != current_user.org_id:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found.")

    session.revoked_at = datetime.now(timezone.utc)
    await db.commit()
    return HTTPResponse(status_code=204)
