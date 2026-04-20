"""
Pydantic v2 schemas for auth endpoints.

Notes:
- Passwords are validated here (min length, policy).
- The access_token is returned in the response body (stored in memory on client).
- The refresh token is set as an HttpOnly cookie — it never appears in response JSON.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, EmailStr, Field, field_validator


# ── Registration ──────────────────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=12, max_length=128)
    org_name: str = Field(..., min_length=2, max_length=100)

    @field_validator("password")
    @classmethod
    def password_no_spaces_only(cls, v: str) -> str:
        if v.strip() == "":
            raise ValueError("Password cannot be blank or whitespace-only.")
        return v

    @field_validator("org_name")
    @classmethod
    def org_name_strip(cls, v: str) -> str:
        return v.strip()


# ── Login ─────────────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=1, max_length=128)


# ── Token responses ───────────────────────────────────────────────────────────

class TokenResponse(BaseModel):
    """
    Returned by /auth/login and /auth/refresh.
    The refresh token is NOT included here — it is set as an HttpOnly cookie.
    """
    access_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds until access token expires


class UserPublic(BaseModel):
    """Public user representation — never include password_hash or DEK."""
    id: uuid.UUID
    email: str
    role: str
    org_id: uuid.UUID
    created_at: datetime
    last_login: datetime | None

    model_config = {"from_attributes": True}


class MeResponse(BaseModel):
    user: UserPublic
    access_token: str
    token_type: str = "bearer"
    expires_in: int


# ── Session management ────────────────────────────────────────────────────────

class SessionInfo(BaseModel):
    id: uuid.UUID
    created_at: datetime
    expires_at: datetime
    user_agent: str | None
    ip_address: str | None
    is_current: bool = False

    model_config = {"from_attributes": True}


# ── Password reset ────────────────────────────────────────────────────────────

class PasswordChangeRequest(BaseModel):
    current_password: str = Field(..., min_length=1, max_length=128)
    new_password: str = Field(..., min_length=12, max_length=128)
