"""
Enrichment service — orchestrates CISA KEV, FIRST EPSS, and NVD data for org vulnerabilities.

All DB updates use SQL UPDATE statements (not ORM object loads), so this module
does NOT require an active encryption_context — encrypted columns are never read
or written here.  The caller does not need Depends(get_org_encryption).

For each non-duplicate vulnerability the service:
  1. Checks the KEV catalog  → sets kev_listed=True + kev_added_date if listed.
  2. Fetches EPSS score      → updates epss_score if available.
  3. Fetches NVD data        → updates cvss_score and published_at if available.

External API results are cached in Redis (TTLs per-client module), so repeated
enrichment runs within the same cache window are cheap.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

import redis.asyncio as aioredis
from sqlalchemy import select
from sqlalchemy import update as sql_update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.clients.epss import fetch_epss_scores
from app.core.clients.kev import fetch_kev_catalog
from app.core.clients.nvd import fetch_nvd_data
from app.core.config import settings
from app.models.vulnerability import Vulnerability

logger = logging.getLogger("vulnops.enrichment")


# ── Result type ────────────────────────────────────────────────────────────────

@dataclass
class EnrichmentResult:
    enriched: int = 0             # total vulns processed
    kev_updated: int = 0          # kev_listed set to True
    epss_updated: int = 0         # epss_score updated
    cvss_updated: int = 0         # cvss_score updated
    published_at_updated: int = 0  # published_at set
    errors: list[str] = field(default_factory=list)


# ── Helpers ────────────────────────────────────────────────────────────────────

async def vulnerability_exists(
    db: AsyncSession,
    org_id: uuid.UUID,
    vuln_id: uuid.UUID,
) -> bool:
    """
    Return True if a Vulnerability with the given ID belongs to org_id.

    Uses a column-level SELECT (not a full ORM object load) so no
    encryption_context is required.
    """
    result = await db.execute(
        select(Vulnerability.id).where(
            Vulnerability.id == vuln_id,
            Vulnerability.org_id == org_id,
        )
    )
    return result.scalar_one_or_none() is not None


# ── Core enrichment ────────────────────────────────────────────────────────────

async def enrich_vulnerabilities(
    db: AsyncSession,
    redis: aioredis.Redis,
    org_id: uuid.UUID,
    vuln_ids: list[uuid.UUID] | None = None,
    *,
    skip_duplicates: bool = True,
) -> EnrichmentResult:
    """
    Enrich org vulnerabilities with KEV, EPSS, and NVD data.

    Args:
        db: Async database session.
        redis: Redis client (used for API result caching).
        org_id: All DB queries are scoped to this org.
        vuln_ids: Specific vuln IDs to enrich.  When ``None``, every
                  non-duplicate vuln in the org is enriched.
        skip_duplicates: When ``True`` (default), duplicate rows are excluded.
                         Pass ``False`` to enrich a specific duplicate record.

    Returns:
        EnrichmentResult with counts of updates applied and any non-fatal errors.
    """
    result = EnrichmentResult()

    # ── 1. Resolve which (id, cve_id) pairs to enrich ────────────────────────
    query = select(Vulnerability.id, Vulnerability.cve_id).where(
        Vulnerability.org_id == org_id,
    )
    if skip_duplicates:
        query = query.where(Vulnerability.is_duplicate == False)  # noqa: E712
    if vuln_ids:
        query = query.where(Vulnerability.id.in_(vuln_ids))

    rows = await db.execute(query)
    vulns_to_enrich: list[tuple[uuid.UUID, str]] = [
        (row.id, row.cve_id) for row in rows.all()
    ]

    if not vulns_to_enrich:
        return result

    result.enriched = len(vulns_to_enrich)
    cve_ids = [cve_id for _, cve_id in vulns_to_enrich]

    # ── 2. Fetch KEV catalog (one cached fetch for the whole batch) ───────────
    kev_catalog: dict[str, str] = {}
    try:
        kev_catalog = await fetch_kev_catalog(redis)
    except Exception as exc:
        logger.error("KEV catalog fetch failed: %s", exc)
        result.errors.append(f"KEV fetch failed: {exc}")

    # ── 3. Batch-fetch EPSS scores ────────────────────────────────────────────
    epss_scores: dict[str, float] = {}
    try:
        epss_scores = await fetch_epss_scores(redis, cve_ids)
    except Exception as exc:
        logger.error("EPSS batch fetch failed: %s", exc)
        result.errors.append(f"EPSS fetch failed: {exc}")

    # ── 4. Fetch NVD data per unique CVE ─────────────────────────────────────
    unique_cve_ids = list(dict.fromkeys(cve_ids))
    nvd_by_cve: dict[str, dict] = {}
    for cve_id in unique_cve_ids:
        try:
            nvd_data = await fetch_nvd_data(
                redis, cve_id, api_key=settings.NVD_API_KEY
            )
            if nvd_data:
                nvd_by_cve[cve_id] = nvd_data
        except Exception as exc:
            logger.warning("NVD fetch failed for %s: %s", cve_id, exc)
            result.errors.append(f"NVD fetch failed for {cve_id}: {exc}")

    # ── 5. Apply SQL UPDATE per vulnerability ─────────────────────────────────
    for vuln_id, cve_id in vulns_to_enrich:
        updates: dict = {}

        # Always write kev_listed so stale True flags are cleared when a CVE
        # is no longer in the catalog (e.g. after a catalog update or a
        # corrected CVE ID).  Previously this block only wrote True, meaning
        # once flagged a finding could never be unflagged by re-enrichment.
        kev_in_catalog = cve_id in kev_catalog
        updates["kev_listed"] = kev_in_catalog
        if kev_in_catalog:
            date_str = kev_catalog[cve_id]
            try:
                updates["kev_added_date"] = datetime.strptime(
                    date_str, "%Y-%m-%d"
                ).replace(tzinfo=timezone.utc)
            except ValueError:
                updates["kev_added_date"] = None
            result.kev_updated += 1
        else:
            updates["kev_added_date"] = None  # clear stale date if no longer in catalog

        if cve_id in epss_scores:
            updates["epss_score"] = epss_scores[cve_id]
            result.epss_updated += 1

        nvd = nvd_by_cve.get(cve_id)
        if nvd:
            if nvd.get("cvss_score") is not None:
                updates["cvss_score"] = nvd["cvss_score"]
                result.cvss_updated += 1
            if nvd.get("published_at") is not None:
                try:
                    updates["published_at"] = datetime.fromisoformat(
                        nvd["published_at"]
                    )
                    result.published_at_updated += 1
                except ValueError:
                    pass

        if updates:
            await db.execute(
                sql_update(Vulnerability)
                .where(
                    Vulnerability.id == vuln_id,
                    Vulnerability.org_id == org_id,
                )
                .values(**updates)
                .execution_options(synchronize_session="fetch")
            )

    return result
