"""
Tenable.io scanner connector.

Uses the Tenable.io Workbenches API:
  GET /workbenches/vulnerabilities?date_range=<days>&filter.0.filter=...

Authentication: X-ApiKeys header with accessKey + secretKey.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import AsyncIterator

import httpx

from app.core.clients.scanners.base import ScannerClient
from app.core.clients.scanners.registry import register

logger = logging.getLogger("vulnops.scanners.tenable")

BASE_URL = "https://cloud.tenable.com"

_SEVERITY_MAP = {
    4: "critical",
    3: "high",
    2: "medium",
    1: "low",
    0: "low",
}


@register
class TenableClient(ScannerClient):
    name = "tenable"
    required_config_keys = ["access_key", "secret_key"]

    def _auth_headers(self) -> dict[str, str]:
        return {
            "X-ApiKeys": (
                f"accessKey={self.config['access_key']};"
                f"secretKey={self.config['secret_key']}"
            ),
            "Accept": "application/json",
        }

    async def test_connection(self) -> bool:
        async with httpx.AsyncClient(timeout=15) as client:
            try:
                resp = await client.get(
                    f"{BASE_URL}/session", headers=self._auth_headers()
                )
                return resp.status_code == 200
            except httpx.HTTPError as exc:
                logger.warning("Tenable connection test failed: %s", exc)
                return False

    async def fetch_findings(
        self, since: datetime | None = None
    ) -> AsyncIterator[dict]:
        # Tenable date_range is in days; derive from `since` or default 30 days.
        if since is not None:
            delta = datetime.now(timezone.utc) - since
            date_range = max(1, delta.days + 1)
        else:
            date_range = 30

        params = {
            "date_range": date_range,
            "filter.0.filter": "severity",
            "filter.0.quality": "gte",
            "filter.0.value": "1",   # skip informational (0)
            "filter.search_type": "and",
        }

        async with httpx.AsyncClient(timeout=60) as client:
            try:
                resp = await client.get(
                    f"{BASE_URL}/workbenches/vulnerabilities",
                    headers=self._auth_headers(),
                    params=params,
                )
                resp.raise_for_status()
            except httpx.HTTPError as exc:
                logger.error("Tenable fetch failed: %s", exc)
                return

        data = resp.json()
        for vuln in data.get("vulnerabilities", []):
            cve_ids: list[str] = (
                vuln.get("plugin", {}).get("cve", []) or []
            )
            if not cve_ids:
                continue   # skip findings without a CVE

            severity_id = vuln.get("severity", {}).get("id", 0)
            severity = _SEVERITY_MAP.get(severity_id, "low")
            plugin = vuln.get("plugin", {})
            plugin_id = str(plugin.get("id", ""))
            plugin_name = plugin.get("name", "Unknown")
            description = plugin.get("description", "") or plugin_name
            cvss = plugin.get("cvss_base_score") or plugin.get("cvss3_base_score")
            published = plugin.get("publication_date")

            for cve_id in cve_ids:
                yield {
                    "cve_id": cve_id,
                    "title": plugin_name,
                    "description": description[:4000],
                    "severity": severity,
                    "source": "tenable",
                    "source_id": f"tenable-plugin-{plugin_id}-{cve_id}",
                    "affected_component": vuln.get("asset", {}).get("hostname"),
                    "cvss_score": float(cvss) if cvss else None,
                    "published_at": (
                        datetime.fromisoformat(published) if published else None
                    ),
                }
