"""
Audit log service — creates append-only event records.

log_event() must be called BEFORE db.commit() so the audit entry is always
committed atomically with the action it describes.

All inserts are scoped to org_id (PRD non-negotiable).
"""

from __future__ import annotations

import json
import logging
import uuid
from typing import Any

from sqlalchemy import func as sqlfunc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_log import AuditLog

logger = logging.getLogger("vulnops.audit")


async def log_event(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    user_id: uuid.UUID,
    action: str,
    resource_type: str,
    resource_id: str | None = None,
    details: dict[str, Any] | None = None,
) -> AuditLog:
    """
    Append an audit log entry to the database.

    The entry is flushed but NOT committed — call db.commit() in the route
    handler after all mutations are complete.

    Args:
        db: Async database session.
        org_id: Tenant scope — every audit entry is org-scoped.
        user_id: ID of the user performing the action.
        action: Dot-separated action descriptor (e.g. "vulnerability.created").
        resource_type: Type of resource affected (e.g. "vulnerability").
        resource_id: String ID of the affected resource (optional).
        details: Optional dict of metadata — serialised to JSON.

    Returns:
        The newly-created AuditLog ORM object.
    """
    entry = AuditLog(
        org_id=org_id,
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=json.dumps(details) if details else None,
    )
    db.add(entry)
    await db.flush()
    return entry


async def list_audit_log(
    db: AsyncSession,
    org_id: uuid.UUID,
    *,
    skip: int = 0,
    limit: int = 50,
    action: str | None = None,
    resource_type: str | None = None,
) -> tuple[list[AuditLog], int]:
    """
    Return a paginated list of audit log entries for the org.

    All queries are scoped to org_id.

    Args:
        db: Async database session.
        org_id: Tenant scope.
        skip: Number of rows to skip (pagination offset).
        limit: Maximum rows to return.
        action: Optional filter by action string (exact match).
        resource_type: Optional filter by resource_type (exact match).

    Returns:
        Tuple of (entries, total_count).
    """
    base_filter = [AuditLog.org_id == org_id]
    if action:
        base_filter.append(AuditLog.action == action)
    if resource_type:
        base_filter.append(AuditLog.resource_type == resource_type)

    count_q = select(sqlfunc.count(AuditLog.id)).where(*base_filter)
    total = (await db.execute(count_q)).scalar_one()

    items_q = (
        select(AuditLog)
        .where(*base_filter)
        .order_by(AuditLog.created_at.desc())
        .offset(skip)
        .limit(limit)
    )
    rows = await db.execute(items_q)
    return list(rows.scalars().all()), total
