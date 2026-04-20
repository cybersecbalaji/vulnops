"""
Organization and OrgSettings models.

organizations.encrypted_dek stores the org's Data Encryption Key (DEK),
itself encrypted with the application master key. All sensitive column values
in other tables (enc_* columns) are encrypted with the org's decrypted DEK.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text, Uuid, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(native_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)

    # Org DEK encrypted with the application master key (Fernet).
    # Never decrypt this except through FieldEncryption helpers.
    encrypted_dek: Mapped[str] = mapped_column(Text, nullable=False)

    # ── Configurable scoring thresholds (PRD Decision 3) ──────────────────
    epss_immediate_threshold: Mapped[float] = mapped_column(Float, default=0.5)
    epss_this_week_threshold: Mapped[float] = mapped_column(Float, default=0.3)
    cvss_immediate_threshold: Mapped[float] = mapped_column(Float, default=9.0)
    cvss_this_week_threshold: Mapped[float] = mapped_column(Float, default=7.0)
    kev_sla_days: Mapped[int] = mapped_column(Integer, default=7)
    non_kev_critical_sla_days: Mapped[int] = mapped_column(Integer, default=30)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    # ── Relationships ──────────────────────────────────────────────────────
    users: Mapped[list["User"]] = relationship("User", back_populates="organization")  # noqa: F821
    settings: Mapped["OrgSettings"] = relationship(
        "OrgSettings", back_populates="organization", uselist=False
    )


class OrgSettings(Base):
    __tablename__ = "org_settings"

    org_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(native_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        primary_key=True,
    )

    # ── AI provider configuration ──────────────────────────────────────────
    ai_provider: Mapped[str] = mapped_column(String(50), default="anthropic")
    ai_model: Mapped[str] = mapped_column(String(100), default="claude-sonnet-4-5")

    # Provider API key encrypted with the org DEK — NEVER returned in API responses
    encrypted_ai_api_key: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Only used when ai_provider == "ollama"
    ollama_base_url: Mapped[str | None] = mapped_column(String(500), nullable=True)

    # ── Jira integration ───────────────────────────────────────────────────
    jira_base_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    jira_project_key: Mapped[str | None] = mapped_column(String(50), nullable=True)
    encrypted_jira_api_key: Mapped[str | None] = mapped_column(Text, nullable=True)

    # ── Relationships ──────────────────────────────────────────────────────
    organization: Mapped["Organization"] = relationship(
        "Organization", back_populates="settings"
    )
