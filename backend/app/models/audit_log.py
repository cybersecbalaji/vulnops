"""
AuditLog model — immutable append-only record of security-relevant events.

Every action is scoped to an org_id so the audit log is always tenant-isolated.
Queries MUST always filter by org_id (PRD non-negotiable).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(native_uuid=True), primary_key=True, default=uuid.uuid4
    )

    # ── Tenant scope — MUST be in every query ─────────────────────────────
    org_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(native_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # ── Actor ──────────────────────────────────────────────────────────────
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(native_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=False,
        index=True,
    )

    # ── Event descriptor ───────────────────────────────────────────────────
    action: Mapped[str] = mapped_column(
        String(100), nullable=False, index=True
        # e.g. "vulnerability.created", "vulnerability.deleted",
        #      "vulnerability.scored", "vulnerability.enriched"
    )
    resource_type: Mapped[str] = mapped_column(String(50), nullable=False)
    resource_id: Mapped[str | None] = mapped_column(String(100), nullable=True)

    # Optional JSON metadata (e.g. {"cve_id": "CVE-2024-1234", "count": 3})
    details: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Immutable timestamp — Python-side default avoids server_default expiry issues
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
