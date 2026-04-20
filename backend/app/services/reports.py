"""
Reporting service — dashboard statistics and PDF export.

get_dashboard_stats() reads only plaintext columns — no encryption context needed.
generate_dashboard_pdf() converts the stats dict to a PDF using fpdf2.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field

from sqlalchemy import func as sqlfunc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.vulnerability import Vulnerability


# ── Data types ─────────────────────────────────────────────────────────────────

@dataclass
class DashboardStats:
    total: int = 0
    duplicate_count: int = 0
    kev_count: int = 0
    scored_count: int = 0
    by_severity: dict[str, int] = field(default_factory=dict)
    by_status: dict[str, int] = field(default_factory=dict)
    by_priority: dict[str, int] = field(default_factory=dict)


# ── Dashboard statistics ───────────────────────────────────────────────────────

async def get_dashboard_stats(
    db: AsyncSession,
    org_id: uuid.UUID,
) -> DashboardStats:
    """
    Compute dashboard statistics for the org.

    Reads only plaintext columns — does NOT require an active encryption_context().
    All queries are scoped to org_id.
    """
    stats = DashboardStats()

    # Total non-duplicate / duplicate counts
    total_q = select(
        Vulnerability.is_duplicate,
        sqlfunc.count(Vulnerability.id).label("cnt"),
    ).where(Vulnerability.org_id == org_id).group_by(Vulnerability.is_duplicate)

    for row in await db.execute(total_q):
        if row.is_duplicate:
            stats.duplicate_count = row.cnt
        else:
            stats.total = row.cnt

    # KEV count (non-duplicates only)
    kev_q = select(sqlfunc.count(Vulnerability.id)).where(
        Vulnerability.org_id == org_id,
        Vulnerability.is_duplicate == False,  # noqa: E712
        Vulnerability.kev_listed == True,  # noqa: E712
    )
    stats.kev_count = (await db.execute(kev_q)).scalar_one()

    # Scored count (non-duplicates with scored_at set)
    scored_q = select(sqlfunc.count(Vulnerability.id)).where(
        Vulnerability.org_id == org_id,
        Vulnerability.is_duplicate == False,  # noqa: E712
        Vulnerability.scored_at.is_not(None),
    )
    stats.scored_count = (await db.execute(scored_q)).scalar_one()

    # By severity (non-duplicates)
    sev_q = select(
        Vulnerability.severity,
        sqlfunc.count(Vulnerability.id).label("cnt"),
    ).where(
        Vulnerability.org_id == org_id,
        Vulnerability.is_duplicate == False,  # noqa: E712
    ).group_by(Vulnerability.severity)
    for row in await db.execute(sev_q):
        stats.by_severity[row.severity] = row.cnt

    # By status (non-duplicates)
    status_q = select(
        Vulnerability.status,
        sqlfunc.count(Vulnerability.id).label("cnt"),
    ).where(
        Vulnerability.org_id == org_id,
        Vulnerability.is_duplicate == False,  # noqa: E712
    ).group_by(Vulnerability.status)
    for row in await db.execute(status_q):
        stats.by_status[row.status] = row.cnt

    # By triage priority (non-duplicates)
    priority_q = select(
        Vulnerability.triage_priority,
        sqlfunc.count(Vulnerability.id).label("cnt"),
    ).where(
        Vulnerability.org_id == org_id,
        Vulnerability.is_duplicate == False,  # noqa: E712
    ).group_by(Vulnerability.triage_priority)
    for row in await db.execute(priority_q):
        key = row.triage_priority or "unscored"
        stats.by_priority[key] = row.cnt

    return stats


# ── PDF generation ─────────────────────────────────────────────────────────────

def generate_dashboard_pdf(stats: DashboardStats, org_name: str = "Your Organisation") -> bytes:
    """
    Generate a PDF dashboard report from DashboardStats.

    Uses fpdf2 (pure Python, no system dependencies).

    Returns:
        Raw PDF bytes suitable for streaming as application/pdf.
    """
    from fpdf import FPDF

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # Title
    pdf.set_font("Helvetica", "B", 18)
    pdf.set_text_color(30, 30, 80)
    pdf.cell(0, 12, "VulnOps Triage Console - Dashboard Report", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(100, 100, 100)
    pdf.cell(0, 6, f"Organisation: {org_name}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    def section_header(title: str) -> None:
        pdf.set_font("Helvetica", "B", 13)
        pdf.set_text_color(30, 30, 80)
        pdf.set_fill_color(230, 235, 255)
        pdf.cell(0, 8, f"  {title}", new_x="LMARGIN", new_y="NEXT", fill=True)
        pdf.ln(2)

    def kv_row(key: str, value: str) -> None:
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(60, 60, 60)
        pdf.cell(60, 7, key)
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(0, 7, value, new_x="LMARGIN", new_y="NEXT")

    # ── Overview ──────────────────────────────────────────────────────────
    section_header("Overview")
    kv_row("Total Vulnerabilities:", str(stats.total))
    kv_row("Duplicates:", str(stats.duplicate_count))
    kv_row("KEV Listed:", str(stats.kev_count))
    kv_row("Scored:", str(stats.scored_count))
    pdf.ln(4)

    # ── By Severity ───────────────────────────────────────────────────────
    section_header("By Severity")
    severity_order = ["critical", "high", "medium", "low", "informational"]
    for sev in severity_order:
        count = stats.by_severity.get(sev, 0)
        kv_row(f"  {sev.capitalize()}:", str(count))
    pdf.ln(4)

    # ── By Status ─────────────────────────────────────────────────────────
    section_header("By Status")
    for status_key, count in sorted(stats.by_status.items()):
        kv_row(f"  {status_key.replace('_', ' ').capitalize()}:", str(count))
    pdf.ln(4)

    # ── By Triage Priority ────────────────────────────────────────────────
    section_header("By Triage Priority")
    priority_order = ["immediate", "this_week", "this_month", "monitor", "accept", "unscored"]
    for pri in priority_order:
        count = stats.by_priority.get(pri, 0)
        kv_row(f"  {pri.replace('_', ' ').capitalize()}:", str(count))
    pdf.ln(4)

    # Footer
    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(150, 150, 150)
    pdf.cell(0, 6, "Generated by VulnOps Triage Console", align="C")

    return bytes(pdf.output())
