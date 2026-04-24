"""Pydantic schemas for ScannerConnection."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, field_validator


class ScannerConnectionCreate(BaseModel):
    name: str
    provider: str
    config: dict[str, str]   # provider-specific key/value credentials

    @field_validator("provider")
    @classmethod
    def provider_known(cls, v: str) -> str:
        from app.core.clients.scanners.registry import SCANNER_CLIENTS
        if v not in SCANNER_CLIENTS:
            raise ValueError(
                f"Unknown provider '{v}'. Available: {sorted(SCANNER_CLIENTS)}"
            )
        return v


class ScannerConnectionUpdate(BaseModel):
    name: str | None = None
    enabled: bool | None = None
    config: dict[str, str] | None = None


class ScannerConnectionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    org_id: uuid.UUID
    name: str
    provider: str
    enabled: bool
    last_sync_at: datetime | None
    last_sync_status: str | None
    last_sync_error: str | None
    last_sync_count: int | None
    created_at: datetime
    updated_at: datetime


class SyncResult(BaseModel):
    connection_id: uuid.UUID
    status: str
    ingested: int
    errors: int
    message: str
