"""
Pydantic schemas for Asset CRUD and bulk import.

All text fields pass through basic sanitization (strip, length cap).
ip_address, hostname, and fqdn are lightly validated (length + strip only —
full IP/hostname regex would reject valid edge cases like IPv6 scoped addresses).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.asset import ASSET_TYPE_VALUES, CRITICALITY_VALUES, ENVIRONMENT_VALUES


# ── Helpers ───────────────────────────────────────────────────────────────────

def _clean(v: str | None, max_len: int = 255) -> str | None:
    if v is None:
        return None
    cleaned = v.strip()[:max_len]
    return cleaned or None


def _parse_bool(v: Any) -> bool:
    """Accept True/False/1/0/'true'/'false'/'yes'/'no' from CSV imports."""
    if isinstance(v, bool):
        return v
    if isinstance(v, int):
        return bool(v)
    if isinstance(v, str):
        return v.strip().lower() in ("true", "yes", "1")
    return False


# ── Input schemas ─────────────────────────────────────────────────────────────

class AssetCreate(BaseModel):
    name: str = Field(..., max_length=255)
    asset_type: str = "server"
    criticality: str = "medium"
    environment: str = "production"
    internet_facing: bool = False

    ip_address: str | None = Field(default=None, max_length=45)
    hostname: str | None = Field(default=None, max_length=255)
    fqdn: str | None = Field(default=None, max_length=255)
    operating_system: str | None = Field(default=None, max_length=255)
    owner: str | None = Field(default=None, max_length=255)
    tags: str | None = Field(default=None, max_length=500)
    notes: str | None = Field(default=None, max_length=4000)
    external_id: str | None = Field(default=None, max_length=255)

    @field_validator("name", mode="before")
    @classmethod
    def clean_name(cls, v: Any) -> str:
        if not isinstance(v, str) or not v.strip():
            raise ValueError("name is required")
        return v.strip()[:255]

    @field_validator("ip_address", "hostname", "fqdn", "operating_system", "owner", "tags", "notes", "external_id", mode="before")
    @classmethod
    def clean_optional(cls, v: Any) -> str | None:
        if v is None:
            return None
        if not isinstance(v, str):
            return None
        return v.strip() or None

    @field_validator("asset_type")
    @classmethod
    def validate_asset_type(cls, v: str) -> str:
        n = v.lower().strip().replace(" ", "_").replace("-", "_")
        if n not in ASSET_TYPE_VALUES:
            return "other"
        return n

    @field_validator("criticality")
    @classmethod
    def validate_criticality(cls, v: str) -> str:
        n = v.lower().strip()
        if n not in CRITICALITY_VALUES:
            return "medium"
        return n

    @field_validator("environment")
    @classmethod
    def validate_environment(cls, v: str) -> str:
        n = v.lower().strip()
        # Accept common aliases
        aliases = {"prod": "production", "dev": "development", "stg": "staging", "stage": "staging"}
        n = aliases.get(n, n)
        if n not in ENVIRONMENT_VALUES:
            return "other"
        return n

    @field_validator("internet_facing", mode="before")
    @classmethod
    def coerce_bool(cls, v: Any) -> bool:
        return _parse_bool(v)


class AssetUpdate(BaseModel):
    name: str | None = Field(default=None, max_length=255)
    asset_type: str | None = None
    criticality: str | None = None
    environment: str | None = None
    internet_facing: bool | None = None

    ip_address: str | None = Field(default=None, max_length=45)
    hostname: str | None = Field(default=None, max_length=255)
    fqdn: str | None = Field(default=None, max_length=255)
    operating_system: str | None = Field(default=None, max_length=255)
    owner: str | None = Field(default=None, max_length=255)
    tags: str | None = Field(default=None, max_length=500)
    notes: str | None = Field(default=None, max_length=4000)

    @field_validator("name", mode="before")
    @classmethod
    def clean_name(cls, v: Any) -> str | None:
        if v is None:
            return None
        if not isinstance(v, str) or not v.strip():
            return None
        return v.strip()[:255]

    @field_validator("ip_address", "hostname", "fqdn", "operating_system", "owner", "tags", "notes", mode="before")
    @classmethod
    def clean_optional(cls, v: Any) -> str | None:
        if v is None:
            return None
        if not isinstance(v, str):
            return None
        return v.strip() or None

    @field_validator("asset_type")
    @classmethod
    def validate_asset_type(cls, v: str | None) -> str | None:
        if v is None:
            return None
        n = v.lower().strip().replace(" ", "_").replace("-", "_")
        return n if n in ASSET_TYPE_VALUES else "other"

    @field_validator("criticality")
    @classmethod
    def validate_criticality(cls, v: str | None) -> str | None:
        if v is None:
            return None
        n = v.lower().strip()
        return n if n in CRITICALITY_VALUES else "medium"

    @field_validator("environment")
    @classmethod
    def validate_environment(cls, v: str | None) -> str | None:
        if v is None:
            return None
        n = v.lower().strip()
        aliases = {"prod": "production", "dev": "development", "stg": "staging", "stage": "staging"}
        n = aliases.get(n, n)
        return n if n in ENVIRONMENT_VALUES else "other"

    @field_validator("internet_facing", mode="before")
    @classmethod
    def coerce_bool(cls, v: Any) -> bool | None:
        if v is None:
            return None
        return _parse_bool(v)


# ── Response schemas ──────────────────────────────────────────────────────────

class AssetResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    org_id: uuid.UUID
    name: str
    asset_type: str
    criticality: str
    environment: str
    internet_facing: bool
    ip_address: str | None
    hostname: str | None
    fqdn: str | None
    operating_system: str | None
    owner: str | None
    tags: str | None
    notes: str | None
    external_id: str | None
    created_at: datetime
    updated_at: datetime


class AssetListResponse(BaseModel):
    items: list[AssetResponse]
    total: int
    page: int
    page_size: int


# ── Import result schema ──────────────────────────────────────────────────────

class AssetImportErrorSchema(BaseModel):
    row: int
    name: str | None
    error: str


class AssetImportResultSchema(BaseModel):
    imported: int
    updated: int
    skipped: int
    errors: list[AssetImportErrorSchema]
    assets: list[AssetResponse]
