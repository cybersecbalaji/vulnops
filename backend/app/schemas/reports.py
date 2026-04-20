"""
Pydantic schemas for reporting dashboard and audit log endpoints.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict


# ── Dashboard ─────────────────────────────────────────────────────────────────

class DashboardStatsResponse(BaseModel):
    """Response for GET /reports/dashboard."""
    total: int
    duplicate_count: int
    kev_count: int
    scored_count: int
    by_severity: dict[str, int]
    by_status: dict[str, int]
    by_priority: dict[str, int]


# ── Audit log ─────────────────────────────────────────────────────────────────

class AuditLogEntry(BaseModel):
    """Single audit log entry as returned by the API."""
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    org_id: uuid.UUID
    user_id: uuid.UUID
    action: str
    resource_type: str
    resource_id: str | None
    details: str | None
    created_at: datetime


class AuditLogListResponse(BaseModel):
    """Paginated list of audit log entries."""
    items: list[AuditLogEntry]
    total: int
    page: int
    page_size: int
