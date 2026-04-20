"""Initial schema — Phase 1 (auth tables)

Revision ID: 001
Revises:
Create Date: 2026-04-15

Tables created:
  - organizations
  - org_settings
  - users
  - refresh_tokens

Row-Level Security policies are created for each table so that even
raw DB access cannot cross org boundaries.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── organizations ─────────────────────────────────────────────────────
    op.create_table(
        "organizations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("slug", sa.String(100), nullable=False),
        sa.Column("encrypted_dek", sa.Text(), nullable=False),
        sa.Column("epss_immediate_threshold", sa.Float(), nullable=False, server_default="0.5"),
        sa.Column("epss_this_week_threshold", sa.Float(), nullable=False, server_default="0.3"),
        sa.Column("cvss_immediate_threshold", sa.Float(), nullable=False, server_default="9.0"),
        sa.Column("cvss_this_week_threshold", sa.Float(), nullable=False, server_default="7.0"),
        sa.Column("kev_sla_days", sa.Integer(), nullable=False, server_default="7"),
        sa.Column("non_kev_critical_sla_days", sa.Integer(), nullable=False, server_default="30"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
    )
    op.create_index("ix_organizations_slug", "organizations", ["slug"], unique=True)

    # ── org_settings ──────────────────────────────────────────────────────
    op.create_table(
        "org_settings",
        sa.Column(
            "org_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("ai_provider", sa.String(50), nullable=False, server_default="'anthropic'"),
        sa.Column("ai_model", sa.String(100), nullable=False, server_default="'claude-sonnet-4-5'"),
        sa.Column("encrypted_ai_api_key", sa.Text(), nullable=True),
        sa.Column("ollama_base_url", sa.String(500), nullable=True),
        sa.Column("jira_base_url", sa.String(500), nullable=True),
        sa.Column("jira_project_key", sa.String(50), nullable=True),
        sa.Column("encrypted_jira_api_key", sa.Text(), nullable=True),
    )

    # ── users ─────────────────────────────────────────────────────────────
    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column(
            "org_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("email", sa.String(320), nullable=False),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("role", sa.String(20), nullable=False, server_default="'analyst'"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.Column("last_login", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_users_email", "users", ["email"], unique=True)
    op.create_index("ix_users_org_id", "users", ["org_id"])

    # ── refresh_tokens ────────────────────────────────────────────────────
    op.create_table(
        "refresh_tokens",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.Column("ip_address", sa.String(45), nullable=True),
    )
    op.create_index("ix_refresh_tokens_token_hash", "refresh_tokens", ["token_hash"], unique=True)
    op.create_index("ix_refresh_tokens_user_id", "refresh_tokens", ["user_id"])

    # ── Row-Level Security ────────────────────────────────────────────────
    # Enable RLS as a defence-in-depth layer. Application-layer org_id scoping
    # is the primary control; RLS is the second enforcement layer.
    for table in ("org_settings", "users", "refresh_tokens"):
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")


def downgrade() -> None:
    for table in ("org_settings", "users", "refresh_tokens"):
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")

    op.drop_table("refresh_tokens")
    op.drop_table("users")
    op.drop_table("org_settings")
    op.drop_table("organizations")
