"""
NIST NVD (National Vulnerability Database) API client.

Fetches CVE details including CVSS scores and published date.
Caches per CVE in Redis with a 7-day TTL (NVD data rarely changes post-publication).

API: https://nvd.nist.gov/developers/vulnerabilities (v2.0)

Response shape (trimmed):
  {
    "vulnerabilities": [{
      "cve": {
        "id": "CVE-...",
        "published": "2021-03-03T00:15:00.000",
        "metrics": {
          "cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}],
          "cvssMetricV30": [...],
          "cvssMetricV2":  [...]
        }
      }
    }]
  }
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

import httpx
import redis.asyncio as aioredis

logger = logging.getLogger("vulnops.enrichment.nvd")

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_KEY_PREFIX = "enrichment:nvd:"
CACHE_TTL = 604800  # 7 days


def _extract_fields(cve_entry: dict) -> dict | None:
    """
    Extract ``cvss_score`` and ``published_at`` from one NVD vulnerabilities[] item.

    CVSS preference order: v3.1 → v3.0 → v2.
    Returns ``None`` if the entry is structurally invalid.
    """
    try:
        cve = cve_entry["cve"]
    except (KeyError, TypeError):
        return None

    # published_at — NVD uses ISO 8601 with milliseconds
    published_at: str | None = None
    raw_published = cve.get("published")
    if raw_published:
        try:
            published_at = (
                datetime.fromisoformat(raw_published.replace("Z", "+00:00"))
                .isoformat()
            )
        except ValueError:
            pass

    # CVSS base score — try metric keys in preference order
    cvss_score: float | None = None
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_list = metrics.get(key, [])
        if metric_list:
            try:
                cvss_score = float(metric_list[0]["cvssData"]["baseScore"])
            except (KeyError, TypeError, ValueError):
                pass
            break

    return {"cvss_score": cvss_score, "published_at": published_at}


async def fetch_nvd_data(
    redis: aioredis.Redis,
    cve_id: str,
    *,
    api_key: str = "",
    http_client: httpx.AsyncClient | None = None,
) -> dict | None:
    """
    Return ``{"cvss_score": float | None, "published_at": str | None}`` for a CVE.

    Data is cached per CVE in Redis for 7 days.
    Returns ``None`` if the CVE is not found or any API/network error occurs.

    Args:
        redis: Redis client used for cache read/write.
        cve_id: CVE identifier (e.g. ``"CVE-2021-26855"``).
        api_key: Optional NVD API key — increases rate limit from 5 to 50 req/30s.
        http_client: Optional pre-created httpx client (useful for testing).
    """
    cache_key = f"{CACHE_KEY_PREFIX}{cve_id}"
    cached = await redis.get(cache_key)
    if cached is not None:
        return json.loads(cached)

    headers: dict[str, str] = {}
    if api_key:
        headers["apiKey"] = api_key

    own_client = http_client is None
    client: httpx.AsyncClient = (
        httpx.AsyncClient(timeout=30) if own_client else http_client  # type: ignore[assignment]
    )
    try:
        try:
            resp = await client.get(
                NVD_URL, params={"cveId": cve_id}, headers=headers
            )
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            logger.warning("NVD API error for %s: %s", cve_id, exc)
            return None
    finally:
        if own_client:
            await client.aclose()

    data = resp.json()
    vulnerabilities = data.get("vulnerabilities", [])
    if not vulnerabilities:
        return None

    result = _extract_fields(vulnerabilities[0])
    if result is not None:
        await redis.setex(cache_key, CACHE_TTL, json.dumps(result))
    return result
