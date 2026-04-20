"""Assets table and vulnerability-asset mapping

Revision ID: 003
Revises: 215638744cc4
Create Date: 2026-04-17

Changes:
  - Create `assets` table with full CMDB fields
  - Add `asset_id` nullable FK on `vulnerabilities` (many vulns → one asset)
  - Add `affected_asset_ids` text column on `vulnerabilities` for multi-asset tracking
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = '003'
down_revision: Union[str, None] = '215638744cc4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'assets',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('org_id', sa.Uuid(), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('ip_address', sa.String(length=45), nullable=True),
        sa.Column('hostname', sa.String(length=255), nullable=True),
        sa.Column('fqdn', sa.String(length=255), nullable=True),
        sa.Column('asset_type', sa.String(length=30), nullable=False, server_default='server'),
        sa.Column('criticality', sa.String(length=20), nullable=False, server_default='medium'),
        sa.Column('environment', sa.String(length=20), nullable=False, server_default='production'),
        sa.Column('internet_facing', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('operating_system', sa.String(length=255), nullable=True),
        sa.Column('owner', sa.String(length=255), nullable=True),
        sa.Column('tags', sa.String(length=500), nullable=True),
        sa.Column('notes', sa.Text(), nullable=True),
        sa.Column('external_id', sa.String(length=255), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_assets_org_id', 'assets', ['org_id'])
    op.create_index('ix_assets_ip_address', 'assets', ['ip_address'])
    op.create_index('ix_assets_hostname', 'assets', ['hostname'])
    op.create_index('ix_assets_external_id', 'assets', ['external_id'])

    # Add asset linkage to vulnerabilities (nullable — not every vuln has a matched asset)
    op.add_column('vulnerabilities', sa.Column('asset_id', sa.Uuid(), nullable=True))
    op.create_foreign_key(
        'fk_vulnerabilities_asset_id',
        'vulnerabilities', 'assets',
        ['asset_id'], ['id'],
        ondelete='SET NULL',
    )
    op.create_index('ix_vulnerabilities_asset_id', 'vulnerabilities', ['asset_id'])


def downgrade() -> None:
    op.drop_index('ix_vulnerabilities_asset_id', 'vulnerabilities')
    op.drop_constraint('fk_vulnerabilities_asset_id', 'vulnerabilities', type_='foreignkey')
    op.drop_column('vulnerabilities', 'asset_id')
    op.drop_index('ix_assets_external_id', 'assets')
    op.drop_index('ix_assets_hostname', 'assets')
    op.drop_index('ix_assets_ip_address', 'assets')
    op.drop_index('ix_assets_org_id', 'assets')
    op.drop_table('assets')
