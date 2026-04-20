"""
User management schemas (admin operations).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, EmailStr, Field


class UserCreate(BaseModel):
    """Admin: invite a new user to the org."""
    email: EmailStr
    role: Literal["admin", "analyst", "readonly"] = "analyst"


class UserUpdate(BaseModel):
    """Admin: update a user's role or active status."""
    role: Literal["admin", "analyst", "readonly"] | None = None
    is_active: bool | None = None


class UserPublicFull(BaseModel):
    id: uuid.UUID
    email: str
    role: str
    org_id: uuid.UUID
    is_active: bool
    created_at: datetime
    last_login: datetime | None

    model_config = {"from_attributes": True}
