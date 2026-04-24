"""
ScannerConnection model — stores API credentials and sync state for an
org's configured scanner integrations (Tenable, Qualys, etc.).

Credentials are stored as Fernet ciphertext via EncryptedString; every
read/write requires an active encryption_context() (injected by the
get_org_encryption FastAPI dependency).

Every query MUST be scoped to org_id — enforced by NOT NULL + index.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.encryption import EncryptedString
from app.db.base import Base


class ScannerConnection(Base):
    __tablename__ = "scanner_connections"

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
    provider: Mapped[str] = mapped_column(String(50), nullable=False)

    # ── Encrypted credentials ─────────────────────────────────────────────────
    # JSON blob of provider-specific config keys (e.g. access_key, secret_key)
    enc_config: Mapped[str] = mapped_column(EncryptedString, nullable=False)

    # ── Sync state ────────────────────────────────────────────────────────────
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    last_sync_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_sync_status: Mapped[str | None] = mapped_column(
        String(20), nullable=True   # "ok" | "error" | "running"
    )
    last_sync_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_sync_count: Mapped[int | None] = mapped_column(nullable=True)

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
