"""
FIRST EPSS (Exploit Prediction Scoring System) API client.

Fetches EPSS scores for a batch of CVE IDs, caches per CVE in Redis.
Cache TTL: 24 hours.

API reference: https://www.first.org/epss/api
Response shape:
  {"status":"OK","data":[{"cve":"CVE-2021-26855","epss":"0.97528","percentile":"0.99"},...]}
"""

from __future__ import annotations

import logging
from collections.abc import Sequence

import httpx
import redis.asyncio as aioredis

logger = logging.getLogger("vulnops.enrichment.epss")

EPSS_URL = "https://api.first.org/data/v1/epss"
CACHE_KEY_PREFIX = "enrichment:epss:"
CACHE_TTL = 86400  # 24 hours
_BATCH_SIZE = 100  # FIRST API supports up to ~100 CVEs per request


async def fetch_epss_scores(
    redis: aioredis.Redis,
    cve_ids: Sequence[str],
    *,
    http_client: httpx.AsyncClient | None = None,
) -> dict[str, float]:
    """
    Return {cve_id: epss_score} for each CVE ID that has EPSS data.

    Checks Redis cache first; only fetches from the API for cache misses.
    Results (scores only, not percentile) are cached per CVE.

    Args:
        redis: Redis client used for cache read/write.
        cve_ids: CVE IDs to look up (duplicates are silently de-duped).
        http_client: Optional pre-created httpx client (useful for testing).
    """
    if not cve_ids:
        return {}

    unique_ids: list[str] = list(dict.fromkeys(cve_ids))  # preserve order, dedupe

    # ── Check per-CVE cache ───────────────────────────────────────────────────
    results: dict[str, float] = {}
    uncached: list[str] = []
    for cve_id in unique_ids:
        cached = await redis.get(f"{CACHE_KEY_PREFIX}{cve_id}")
        if cached is not None:
            try:
                results[cve_id] = float(cached)
            except ValueError:
                uncached.append(cve_id)  # corrupted cache entry — re-fetch
        else:
            uncached.append(cve_id)

    if not uncached:
        return results

    # ── Fetch uncached CVEs from FIRST API in batches ────────────────────────
    own_client = http_client is None
    client: httpx.AsyncClient = (
        httpx.AsyncClient(timeout=30) if own_client else http_client  # type: ignore[assignment]
    )
    try:
        for i in range(0, len(uncached), _BATCH_SIZE):
            batch = uncached[i : i + _BATCH_SIZE]
            try:
                resp = await client.get(EPSS_URL, params={"cve": ",".join(batch)})
                resp.raise_for_status()
            except httpx.HTTPError as exc:
                logger.warning("EPSS API error (batch starting %s): %s", batch[0], exc)
                continue  # skip this batch; other batches may succeed

            for item in resp.json().get("data", []):
                cve_id = item.get("cve", "")
                if not cve_id:
                    continue
                try:
                    score = float(item.get("epss", 0))
                except (ValueError, TypeError):
                    continue
                results[cve_id] = score
                await redis.setex(
                    f"{CACHE_KEY_PREFIX}{cve_id}", CACHE_TTL, str(score)
                )
    finally:
        if own_client:
            await client.aclose()

    return results
