"""Scanner connections table

Revision ID: 004
Revises: 003
Create Date: 2026-04-22

Changes:
  - Create `scanner_connections` table for storing scanner API credentials
    and sync state per org.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = '004'
down_revision: Union[str, None] = '003'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'scanner_connections',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('org_id', sa.Uuid(), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('provider', sa.String(length=50), nullable=False),
        sa.Column('enc_config', sa.Text(), nullable=False),
        sa.Column('enabled', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('last_sync_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_sync_status', sa.String(length=20), nullable=True),
        sa.Column('last_sync_error', sa.Text(), nullable=True),
        sa.Column('last_sync_count', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_scanner_connections_org_id', 'scanner_connections', ['org_id'])
    op.create_index('ix_scanner_connections_provider', 'scanner_connections', ['provider'])


def downgrade() -> None:
    op.drop_index('ix_scanner_connections_provider', 'scanner_connections')
    op.drop_index('ix_scanner_connections_org_id', 'scanner_connections')
    op.drop_table('scanner_connections')
