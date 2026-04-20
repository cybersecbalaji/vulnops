"""
Remediation ticket drafter and bulk triage advisor.

Two public coroutines:
  - draft_ticket     — LLM-generated remediation ticket for a single vulnerability.
  - bulk_triage_advice — strategic triage plan across all org vulnerabilities.

draft_ticket REQUIRES an active encryption_context() (reads enc_* ORM fields).
bulk_triage_advice only reads plaintext columns and does NOT need an encryption
context.
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from dataclasses import dataclass

from sqlalchemy import func as sqlfunc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.llm.base import LLMClient, LLMMessage
from app.models.organization import Organization
from app.models.vulnerability import Vulnerability

logger = logging.getLogger("vulnops.remediation")

# Maps triage_priority values to Jira priority names
JIRA_PRIORITY_MAP: dict[str, str] = {
    "immediate": "Highest",
    "this_week": "High",
    "this_month": "Medium",
    "monitor": "Low",
    "accept": "Low",
}


# ── Result types ──────────────────────────────────────────────────────────────

@dataclass
class TicketDraft:
    summary: str
    markdown: str
    jira_summary: str
    jira_description: str
    jira_priority: str


@dataclass
class TriageAdvice:
    markdown: str
    total: int
    immediate_count: int
    this_week_count: int
    this_month_count: int
    monitor_count: int
    accept_count: int
    unscored_count: int


# ── JSON helpers ──────────────────────────────────────────────────────────────

def _parse_ticket_json(text: str) -> dict:
    """
    Extract ticket JSON from LLM response.

    Tries in order:
      1. Direct JSON parse of the full text.
      2. JSON inside a markdown ```json … ``` block.
      3. First bare JSON object containing a "summary" key.

    Raises ``ValueError`` if none succeed.
    """
    stripped = text.strip()

    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        pass

    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", stripped, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(1))
        except json.JSONDecodeError:
            pass

    m = re.search(r'\{[^{}]*"summary"[^{}]*\}', stripped, re.DOTALL)
    if m:
        try:
            return json.loads(m.group())
        except json.JSONDecodeError:
            pass

    raise ValueError(f"Cannot parse ticket JSON from LLM output: {stripped[:200]!r}")


# ── Markdown builder ──────────────────────────────────────────────────────────

def _build_markdown_ticket(
    vuln: Vulnerability,
    title: str,
    component: str,
    priority: str,
    llm_body: str,
) -> str:
    """Wrap the LLM-generated body with a structured header and reference footer."""
    kev = "Yes" if vuln.kev_listed else "No"
    cvss = vuln.cvss_score if vuln.cvss_score is not None else "N/A"
    epss = vuln.epss_score if vuln.epss_score is not None else "N/A"

    header = (
        f"# Remediation Ticket: {vuln.cve_id}\n\n"
        f"| Field | Value |\n"
        f"|-------|-------|\n"
        f"| **Title** | {title} |\n"
        f"| **Severity** | {vuln.severity} |\n"
        f"| **Triage Priority** | {priority} |\n"
        f"| **CVSS Score** | {cvss} |\n"
        f"| **EPSS Score** | {epss} |\n"
        f"| **KEV Listed** | {kev} |\n"
        f"| **Affected Component** | {component} |\n"
        f"| **Status** | {vuln.status} |\n\n"
        "---\n\n"
    )
    footer = (
        "\n\n---\n\n"
        "**References:**\n"
        f"- [NVD: {vuln.cve_id}](https://nvd.nist.gov/vuln/detail/{vuln.cve_id})\n"
        "- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)\n"
    )
    return header + llm_body + footer


# ── Ticket drafter ────────────────────────────────────────────────────────────

async def draft_ticket(
    llm: LLMClient,
    vuln: Vulnerability,
) -> TicketDraft:
    """
    Draft a remediation ticket for a single vulnerability using the LLM.

    Requires an active encryption_context() so enc_* attributes on the vuln
    are transparently decrypted when accessed.

    Args:
        llm: Configured LLMClient — temperature=0.2 for fluent writing.
        vuln: Fully-loaded Vulnerability ORM object (enc_* fields readable).

    Returns:
        TicketDraft with both Markdown and Jira-formatted content.
    """
    title = vuln.enc_title or vuln.cve_id
    description = (vuln.enc_description or "")[:800]
    component = vuln.enc_affected_component or "Not specified"
    rationale = (vuln.enc_score_rationale or "")[:300]
    priority = vuln.triage_priority or "unscored"
    jira_priority = JIRA_PRIORITY_MAP.get(priority, "Medium")

    system = (
        "You are a security engineer drafting a remediation ticket for a vulnerability. "
        "Return ONLY a valid JSON object with exactly these keys:\n"
        '  "summary": one-line ticket title (max 80 chars),\n'
        '  "description_markdown": full Markdown ticket body with sections '
        "Impact, Remediation Steps, and Additional Notes,\n"
        '  "jira_description": plain-text version for Jira (max 3000 chars).\n'
        "No text outside the JSON."
    )

    user_msg = (
        f"CVE ID: {vuln.cve_id}\n"
        f"Title: {title}\n"
        f"Description: {description}\n"
        f"Severity: {vuln.severity}\n"
        f"CVSS Score: {vuln.cvss_score if vuln.cvss_score is not None else 'N/A'}\n"
        f"EPSS Score: {vuln.epss_score if vuln.epss_score is not None else 'N/A'}\n"
        f"KEV Listed: {vuln.kev_listed}\n"
        f"Affected Component: {component}\n"
        f"Triage Priority: {priority}\n"
        f"Score Rationale: {rationale}\n\n"
        'Return JSON: {"summary": "...", "description_markdown": "...", "jira_description": "..."}'
    )

    response = await llm.complete(
        [LLMMessage(role="user", content=user_msg)],
        system=system,
        max_tokens=1024,
        temperature=0.2,
    )

    try:
        parsed = _parse_ticket_json(response.content)
        summary = str(parsed.get("summary", f"Remediate {vuln.cve_id}"))[:80]
        desc_md = str(parsed.get("description_markdown", ""))
        desc_jira = str(parsed.get("jira_description", desc_md))[:3000]
    except (ValueError, KeyError) as exc:
        logger.warning("Ticket draft parse error for %s: %s", vuln.cve_id, exc)
        summary = f"Remediate {vuln.cve_id} — {title[:55]}"
        desc_md = (
            f"## Impact\n\n{description}\n\n"
            "## Remediation Steps\n\n1. Review the vulnerability details.\n"
            "2. Apply vendor patches if available.\n"
            "3. Validate and test after remediation.\n"
        )
        desc_jira = f"Remediation required for {vuln.cve_id} ({vuln.severity}). {description[:500]}"

    markdown = _build_markdown_ticket(vuln, title, component, priority, desc_md)

    return TicketDraft(
        summary=summary,
        markdown=markdown,
        jira_summary=summary,
        jira_description=desc_jira,
        jira_priority=jira_priority,
    )


# ── Bulk triage advisor ───────────────────────────────────────────────────────

async def bulk_triage_advice(
    db: AsyncSession,
    llm: LLMClient,
    org_id: uuid.UUID,
) -> TriageAdvice:
    """
    Generate a strategic triage plan for all scored vulnerabilities in the org.

    Uses only plaintext columns — does NOT require an active encryption_context().

    Args:
        db: Async database session.
        llm: Configured LLMClient.
        org_id: Scope all queries to this org.

    Returns:
        TriageAdvice with a Markdown plan and per-priority counts.
    """
    # Load org for SLA thresholds (plaintext only)
    org_row = await db.execute(select(Organization).where(Organization.id == org_id))
    org = org_row.scalar_one()

    # Counts per triage priority (plaintext — no encryption context needed)
    count_query = (
        select(
            Vulnerability.triage_priority,
            sqlfunc.count(Vulnerability.id).label("cnt"),
        )
        .where(
            Vulnerability.org_id == org_id,
            Vulnerability.is_duplicate == False,  # noqa: E712
        )
        .group_by(Vulnerability.triage_priority)
    )
    rows = await db.execute(count_query)
    counts: dict[str, int] = {}
    for row in rows:
        key = row.triage_priority if row.triage_priority is not None else "unscored"
        counts[key] = row.cnt

    immediate = counts.get("immediate", 0)
    this_week = counts.get("this_week", 0)
    this_month = counts.get("this_month", 0)
    monitor = counts.get("monitor", 0)
    accept = counts.get("accept", 0)
    unscored = counts.get("unscored", 0)
    total = sum(counts.values())

    # Top immediate vulnerabilities (plaintext fields only)
    top_query = (
        select(
            Vulnerability.cve_id,
            Vulnerability.severity,
            Vulnerability.cvss_score,
            Vulnerability.epss_score,
            Vulnerability.kev_listed,
        )
        .where(
            Vulnerability.org_id == org_id,
            Vulnerability.is_duplicate == False,  # noqa: E712
            Vulnerability.triage_priority == "immediate",
        )
        .order_by(Vulnerability.cvss_score.desc().nullslast())
        .limit(10)
    )
    top_rows = await db.execute(top_query)
    top_vulns = [
        {
            "cve_id": r.cve_id,
            "severity": r.severity,
            "cvss": r.cvss_score,
            "epss": r.epss_score,
            "kev": r.kev_listed,
        }
        for r in top_rows
    ]

    system = (
        "You are a security operations manager. "
        "Write a strategic triage plan in Markdown. "
        "Include sections: Executive Summary, Priority Breakdown, "
        "Immediate Actions Required, SLA Guidance, Recommended Next Steps. "
        "Be concise and actionable. Use bullet points and headers."
    )

    top_lines = "\n".join(
        f"  - {v['cve_id']} | {v['severity']} | CVSS: {v['cvss']} | "
        f"EPSS: {v['epss']} | KEV: {v['kev']}"
        for v in top_vulns
    ) or "  (none)"

    user_msg = (
        "Organization vulnerability summary:\n"
        f"- Total (non-duplicate): {total}\n"
        f"- Immediate:   {immediate}\n"
        f"- This week:   {this_week}\n"
        f"- This month:  {this_month}\n"
        f"- Monitor:     {monitor}\n"
        f"- Accept:      {accept}\n"
        f"- Unscored:    {unscored}\n\n"
        "SLA thresholds:\n"
        f"- KEV SLA: {org.kev_sla_days} days\n"
        f"- Non-KEV critical SLA: {org.non_kev_critical_sla_days} days\n"
        f"- EPSS immediate threshold: {org.epss_immediate_threshold}\n"
        f"- CVSS immediate threshold: {org.cvss_immediate_threshold}\n\n"
        f"Top immediate vulnerabilities:\n{top_lines}\n\n"
        "Write a strategic triage plan in Markdown."
    )

    response = await llm.complete(
        [LLMMessage(role="user", content=user_msg)],
        system=system,
        max_tokens=1500,
        temperature=0.2,
    )

    return TriageAdvice(
        markdown=response.content,
        total=total,
        immediate_count=immediate,
        this_week_count=this_week,
        this_month_count=this_month,
        monitor_count=monitor,
        accept_count=accept,
        unscored_count=unscored,
    )
