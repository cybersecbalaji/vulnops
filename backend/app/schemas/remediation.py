"""
Pydantic schemas for remediation ticket drafting and bulk triage advice.
"""

from __future__ import annotations

import uuid

from pydantic import BaseModel, field_validator


# ── Request ───────────────────────────────────────────────────────────────────

class TicketRequest(BaseModel):
    """Body for POST /remediation/{vuln_id}/ticket."""

    format: str = "both"              # "markdown" | "jira" | "both"
    create_jira_issue: bool = False   # POST to Jira if org has Jira configured

    @field_validator("format")
    @classmethod
    def validate_format(cls, v: str) -> str:
        allowed = {"markdown", "jira", "both"}
        if v not in allowed:
            raise ValueError(f"format must be one of: {', '.join(sorted(allowed))}")
        return v


# ── Ticket response ───────────────────────────────────────────────────────────

class TicketDraftResponse(BaseModel):
    """Response for POST /remediation/{vuln_id}/ticket."""

    vuln_id: uuid.UUID
    cve_id: str
    format: str

    # Markdown output — present when format is "markdown" or "both"
    markdown: str | None

    # Jira output — present when format is "jira" or "both"
    jira_summary: str | None
    jira_description: str | None
    jira_priority: str | None

    # Set when create_jira_issue=True and issue was created successfully
    jira_issue_key: str | None = None
    jira_issue_url: str | None = None


# ── Triage advice response ────────────────────────────────────────────────────

class TriageAdviceResponse(BaseModel):
    """Response for POST /remediation/triage-advice."""

    markdown: str
    total: int
    immediate_count: int
    this_week_count: int
    this_month_count: int
    monitor_count: int
    accept_count: int
    unscored_count: int
