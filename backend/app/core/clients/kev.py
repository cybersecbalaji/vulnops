"""
CISA Known Exploited Vulnerabilities (KEV) catalog client.

Fetches the full CISA KEV JSON catalog and caches it in Redis.
Cache TTL: 24 hours (the catalog is updated at most daily).

On cache miss, performs a single HTTP GET to the CISA feed endpoint.
On cache hit, returns the parsed dict immediately without any HTTP call.
"""

from __future__ import annotations

import json
import logging

import httpx
import redis.asyncio as aioredis

logger = logging.getLogger("vulnops.enrichment.kev")

KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
CACHE_KEY = "enrichment:kev:catalog"
CACHE_TTL = 86400  # 24 hours


async def fetch_kev_catalog(
    redis: aioredis.Redis,
    *,
    http_client: httpx.AsyncClient | None = None,
) -> dict[str, str]:
    """
    Return {cve_id: date_added_iso_str} for all CISA KEV entries.

    ``date_added`` is the ISO-format date string from the catalog
    (e.g. ``"2021-11-03"``).  Results are cached in Redis for 24 hours.

    Args:
        redis: Redis client used for cache read/write.
        http_client: Optional pre-created httpx client (useful for testing).
                     When omitted, a new client is created and closed here.
    """
    cached = await redis.get(CACHE_KEY)
    if cached is not None:
        return json.loads(cached)

    own_client = http_client is None
    client: httpx.AsyncClient = (
        httpx.AsyncClient(timeout=30) if own_client else http_client  # type: ignore[assignment]
    )
    try:
        resp = await client.get(KEV_URL)
        resp.raise_for_status()
    finally:
        if own_client:
            await client.aclose()

    data = resp.json()
    catalog: dict[str, str] = {
        entry["cveID"]: entry["dateAdded"]
        for entry in data.get("vulnerabilities", [])
    }
    await redis.setex(CACHE_KEY, CACHE_TTL, json.dumps(catalog))
    return catalog
