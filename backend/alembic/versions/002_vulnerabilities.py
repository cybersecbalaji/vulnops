"""Phase 2 — vulnerabilities table

Revision ID: 002
Revises: 001
Create Date: 2026-04-15

New tables:
  - vulnerabilities

enc_* columns store Fernet ciphertext (application-layer encryption).
Score and flag columns are plaintext for SQL-level filtering.
Row-Level Security is enabled as a defence-in-depth layer.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "002"
down_revision: Union[str, None] = "001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "vulnerabilities",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        # Org scope — every query must filter on this column
        sa.Column(
            "org_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        # Plaintext identifier and classification
        sa.Column("cve_id", sa.String(30), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("status", sa.String(30), nullable=False, server_default="'open'"),
        sa.Column("source", sa.String(30), nullable=False),
        sa.Column("source_id", sa.String(255), nullable=True),
        # Scores (plaintext — needed for score-based filtering)
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("epss_score", sa.Float(), nullable=True),
        # Flags
        sa.Column("kev_listed", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("is_duplicate", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column(
            "duplicate_of_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("vulnerabilities.id", ondelete="SET NULL"),
            nullable=True,
        ),
        # Enrichment timestamps
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("kev_added_date", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        # Encrypted fields (Fernet ciphertext stored as TEXT)
        sa.Column("enc_title", sa.Text(), nullable=False),
        sa.Column("enc_description", sa.Text(), nullable=False),
        sa.Column("enc_affected_component", sa.Text(), nullable=True),
        sa.Column("enc_notes", sa.Text(), nullable=True),
        sa.Column("enc_remediation_advice", sa.Text(), nullable=True),
    )

    # Indexes for common query patterns
    op.create_index("ix_vulnerabilities_org_id", "vulnerabilities", ["org_id"])
    op.create_index("ix_vulnerabilities_cve_id", "vulnerabilities", ["cve_id"])
    op.create_index("ix_vulnerabilities_source_id", "vulnerabilities", ["source_id"])
    # Composite index for deduplication queries
    op.create_index(
        "ix_vulnerabilities_org_cve_source",
        "vulnerabilities",
        ["org_id", "cve_id", "source", "source_id"],
    )

    # Row-Level Security — defence-in-depth (application layer is primary control)
    op.execute("ALTER TABLE vulnerabilities ENABLE ROW LEVEL SECURITY")


def downgrade() -> None:
    op.execute("ALTER TABLE vulnerabilities DISABLE ROW LEVEL SECURITY")
    op.drop_table("vulnerabilities")
