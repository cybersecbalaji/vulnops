"""
Context scoring agent — assigns triage priority to vulnerabilities using
org-configurable thresholds and LLM contextual reasoning.

PRD non-negotiables enforced here:
  - temperature=0.0 on every LLM call (deterministic scoring)
  - All LLM calls through LLMClient abstraction only
  - Every DB query scoped to org_id

Scoring pipeline per vulnerability:
  1. Rule-based pre-score from org thresholds (KEV → EPSS → CVSS → severity).
  2. LLM contextual score — sends decrypted vulnerability text + org thresholds
     to the LLM, which returns {"priority": "...", "rationale": "..."}.
  3. Persist triage_priority (plaintext) and enc_score_rationale (encrypted)
     back to the Vulnerability row.

Requires an active encryption_context() so encrypted vuln fields are readable
and the rationale can be re-encrypted before storage.
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.llm.base import LLMClient, LLMMessage
from app.models.organization import Organization
from app.models.vulnerability import Vulnerability

logger = logging.getLogger("vulnops.scoring")

TRIAGE_PRIORITIES: frozenset[str] = frozenset(
    {"immediate", "this_week", "this_month", "monitor", "accept"}
)


# ── Result type ────────────────────────────────────────────────────────────────

@dataclass
class ScoringOutput:
    priority: str
    rationale: str


@dataclass
class BulkScoringResult:
    scored: int = 0
    errors: list[str] = field(default_factory=list)


# ── Rule-based pre-scorer (no LLM) ────────────────────────────────────────────

def rule_based_priority(vuln: Vulnerability, org: Organization) -> str:
    """
    Compute an initial triage priority purely from org thresholds and vuln data.

    Used both as a fast-path for bulk scoring and as a hint in the LLM prompt
    so the model anchors its reasoning to the org's configuration.
    """
    if vuln.kev_listed:
        return "immediate"

    epss = vuln.epss_score or 0.0
    cvss = vuln.cvss_score or 0.0

    if epss >= org.epss_immediate_threshold or cvss >= org.cvss_immediate_threshold:
        return "immediate"
    if (
        epss >= org.epss_this_week_threshold
        or cvss >= org.cvss_this_week_threshold
        or vuln.severity == "critical"
    ):
        return "this_week"
    if vuln.severity == "high":
        return "this_month"
    return "monitor"


# ── LLM JSON parser ───────────────────────────────────────────────────────────

def parse_scoring_json(text: str) -> dict:
    """
    Extract ``{"priority": "...", "rationale": "..."}`` from LLM response text.

    Tries in order:
      1. Direct JSON parse of the full text.
      2. JSON inside a markdown ```json … ``` block.
      3. First bare JSON object containing a "priority" key.

    Raises ``ValueError`` if none of the strategies succeed.
    """
    stripped = text.strip()

    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        pass

    # Markdown code block
    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", stripped, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(1))
        except json.JSONDecodeError:
            pass

    # Any JSON object that contains "priority"
    m = re.search(r'\{[^{}]*"priority"[^{}]*\}', stripped, re.DOTALL)
    if m:
        try:
            return json.loads(m.group())
        except json.JSONDecodeError:
            pass

    raise ValueError(f"Cannot parse scoring JSON from LLM output: {stripped[:200]!r}")


# ── Single-vulnerability scorer ────────────────────────────────────────────────

async def score_single(
    llm: LLMClient,
    org: Organization,
    vuln: Vulnerability,
) -> ScoringOutput:
    """
    Score one vulnerability using the LLM and org thresholds.

    The encryption_context must already be active so that encrypted fields
    (enc_title, enc_description, enc_affected_component) are readable.

    Args:
        llm: Configured LLMClient — must be called with temperature=0.0.
        org: Organization row (provides scoring thresholds).
        vuln: Vulnerability row (requires enc_* fields to be decrypted).

    Returns:
        ScoringOutput with validated priority and rationale.
    """
    initial = rule_based_priority(vuln, org)

    system = (
        "You are a vulnerability triage assistant for a security operations team. "
        "Analyse the vulnerability data and return ONLY a valid JSON object with "
        'exactly two keys: "priority" and "rationale". '
        "priority must be one of: immediate, this_week, this_month, monitor, accept. "
        "rationale must be 1-3 sentences. "
        "No markdown, no extra text — JSON only."
    )

    title = vuln.enc_title or vuln.cve_id
    description = (vuln.enc_description or "")[:500]
    component = vuln.enc_affected_component or "N/A"

    user_msg = (
        f"CVE ID: {vuln.cve_id}\n"
        f"Title: {title}\n"
        f"Description: {description}\n"
        f"Severity: {vuln.severity}\n"
        f"CVSS Score: {vuln.cvss_score if vuln.cvss_score is not None else 'N/A'}\n"
        f"EPSS Score: {vuln.epss_score if vuln.epss_score is not None else 'N/A'}\n"
        f"KEV Listed: {vuln.kev_listed}\n"
        f"Affected Component: {component}\n"
        f"Status: {vuln.status}\n\n"
        f"Org thresholds — "
        f"EPSS immediate: {org.epss_immediate_threshold}, "
        f"EPSS this-week: {org.epss_this_week_threshold}, "
        f"CVSS immediate: {org.cvss_immediate_threshold}, "
        f"CVSS this-week: {org.cvss_this_week_threshold}\n\n"
        f"Rule-based hint (use as starting point): {initial}\n\n"
        'Return JSON: {"priority": "...", "rationale": "..."}'
    )

    response = await llm.complete(
        [LLMMessage(role="user", content=user_msg)],
        system=system,
        max_tokens=256,
        temperature=0.0,  # PRD non-negotiable
    )

    try:
        parsed = parse_scoring_json(response.content)
        priority = str(parsed.get("priority", initial)).lower().strip()
        if priority not in TRIAGE_PRIORITIES:
            logger.warning(
                "LLM returned invalid priority %r for %s — falling back to rule-based %r",
                priority, vuln.cve_id, initial,
            )
            priority = initial
        rationale = str(parsed.get("rationale", "")).strip()
    except ValueError as exc:
        logger.warning("LLM scoring parse error for %s: %s", vuln.cve_id, exc)
        priority = initial
        rationale = "Rule-based scoring applied (LLM response could not be parsed)."

    return ScoringOutput(priority=priority, rationale=rationale)


# ── Bulk scorer ────────────────────────────────────────────────────────────────

async def score_vulnerabilities(
    db: AsyncSession,
    llm: LLMClient,
    org_id: uuid.UUID,
    vuln_ids: list[uuid.UUID] | None = None,
) -> BulkScoringResult:
    """
    Score org vulnerabilities and persist triage_priority + enc_score_rationale.

    Requires an active encryption_context() so encrypted vuln fields are readable
    and enc_score_rationale can be written back.

    Args:
        db: Async database session.
        llm: Configured LLMClient.
        org_id: Scope all queries to this org.
        vuln_ids: Specific vuln IDs.  When ``None``, scores all non-duplicate
                  vulns for the org.
    """
    result = BulkScoringResult()

    # Load org for thresholds
    org_row = await db.execute(
        select(Organization).where(Organization.id == org_id)
    )
    org = org_row.scalar_one()

    # Load vulns
    query = select(Vulnerability).where(
        Vulnerability.org_id == org_id,
        Vulnerability.is_duplicate == False,  # noqa: E712
    )
    if vuln_ids:
        query = query.where(Vulnerability.id.in_(vuln_ids))

    rows = await db.execute(query)
    vulns = list(rows.scalars().all())

    now = datetime.now(timezone.utc)

    for vuln in vulns:
        try:
            output = await score_single(llm, org, vuln)
            vuln.triage_priority = output.priority
            vuln.enc_score_rationale = output.rationale
            vuln.scored_at = now
            await db.flush()
            result.scored += 1
        except Exception as exc:
            logger.warning("Scoring failed for %s: %s", vuln.cve_id, exc)
            result.errors.append(f"{vuln.cve_id}: {exc}")

    return result
