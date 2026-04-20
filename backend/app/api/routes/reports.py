"""
Reporting endpoints.

All routes require an authenticated user.

Endpoints:
  GET /reports/dashboard        — aggregate vulnerability statistics
  GET /reports/dashboard/pdf    — PDF export of dashboard
  GET /reports/audit-log        — paginated audit log (admin only)
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.db.session import get_db
from app.models.organization import Organization
from app.models.user import User
from app.schemas.reports import AuditLogEntry, AuditLogListResponse, DashboardStatsResponse
from app.services.audit_log import list_audit_log
from app.services.reports import DashboardStats, generate_dashboard_pdf, get_dashboard_stats

router = APIRouter()


@router.get("/dashboard", response_model=DashboardStatsResponse)
async def dashboard_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> DashboardStatsResponse:
    """
    Return aggregate vulnerability statistics for the current org.

    Reads only plaintext columns — no encryption context required.
    Counts are broken down by severity, status, and triage priority.
    """
    stats = await get_dashboard_stats(db, current_user.org_id)
    return DashboardStatsResponse(
        total=stats.total,
        duplicate_count=stats.duplicate_count,
        kev_count=stats.kev_count,
        scored_count=stats.scored_count,
        by_severity=stats.by_severity,
        by_status=stats.by_status,
        by_priority=stats.by_priority,
    )


@router.get("/dashboard/pdf")
async def dashboard_pdf(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """
    Export the dashboard as a PDF report.

    Returns application/pdf.  Reads only plaintext columns — no encryption
    context required.
    """
    # Fetch org name for the report header
    org_row = await db.execute(
        select(Organization).where(Organization.id == current_user.org_id)
    )
    org = org_row.scalar_one_or_none()
    org_name = org.name if org else "Organisation"

    stats = await get_dashboard_stats(db, current_user.org_id)
    pdf_bytes = generate_dashboard_pdf(stats, org_name=org_name)

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": "attachment; filename=vulnops-dashboard.pdf",
            "Content-Length": str(len(pdf_bytes)),
        },
    )


@router.get("/audit-log", response_model=AuditLogListResponse)
async def get_audit_log(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    action: str | None = Query(default=None),
    resource_type: str | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AuditLogListResponse:
    """
    List audit log entries for the current org.

    Admin role required.  Paginated, newest first.
    Optional filters: action (exact match), resource_type (exact match).
    """
    if current_user.role not in ("admin",):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This action requires one of the following roles: admin.",
        )

    skip = (page - 1) * page_size
    items, total = await list_audit_log(
        db,
        current_user.org_id,
        skip=skip,
        limit=page_size,
        action=action,
        resource_type=resource_type,
    )
    return AuditLogListResponse(
        items=[AuditLogEntry.model_validate(e) for e in items],
        total=total,
        page=page,
        page_size=page_size,
    )
