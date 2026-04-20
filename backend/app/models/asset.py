"""
Asset model — represents a business asset in the organisation's inventory.

Assets provide business context for vulnerability triage:
- internet_facing raises effective priority (exploitable from the internet)
- criticality / environment weight AI scoring decisions
- ip_address / hostname are used to correlate findings from scanner imports

All fields are stored plaintext so they can be filtered, sorted, and used
in SQL aggregations without an encryption context.  Asset metadata is
infrastructure data (IPs, hostnames, OS), not user-generated sensitive text.

Every query MUST be scoped to org_id — enforced by NOT NULL + index.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

ASSET_TYPE_VALUES = frozenset({
    "server", "database", "application", "network_device",
    "endpoint", "cloud_service", "container", "other",
})

CRITICALITY_VALUES = frozenset({"critical", "high", "medium", "low"})
ENVIRONMENT_VALUES = frozenset({"production", "staging", "development", "other"})


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(native_uuid=True), primary_key=True, default=uuid.uuid4
    )

    # ── Org scope ─────────────────────────────────────────────────────────────
    org_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(native_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # ── Identity ──────────────────────────────────────────────────────────────
    name: Mapped[str] = mapped_column(String(255), nullable=False)

    # Network identity — primary keys used by scanner tools for correlation
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True, index=True)  # IPv4/IPv6
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    fqdn: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # ── Classification ────────────────────────────────────────────────────────
    asset_type: Mapped[str] = mapped_column(String(30), nullable=False, default="server")
    criticality: Mapped[str] = mapped_column(String(20), nullable=False, default="medium")
    environment: Mapped[str] = mapped_column(String(20), nullable=False, default="production")
    internet_facing: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # ── Context ───────────────────────────────────────────────────────────────
    operating_system: Mapped[str | None] = mapped_column(String(255), nullable=True)
    owner: Mapped[str | None] = mapped_column(String(255), nullable=True)
    tags: Mapped[str | None] = mapped_column(String(500), nullable=True)   # comma-separated
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    # External ID for dedup when importing from CMDBs / scanners
    external_id: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)

    # ── Timestamps ────────────────────────────────────────────────────────────
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    # ── Relationships ─────────────────────────────────────────────────────────
    organization: Mapped["Organization"] = relationship(  # noqa: F821
        "Organization", lazy="raise"
    )
