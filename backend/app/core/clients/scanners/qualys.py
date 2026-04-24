"""
Qualys VMDR scanner connector.

Uses the Qualys Host Detection API (v2):
  POST /api/2.0/fo/asset/host/vm/detection/
  action=list&show_results=1&output_format=XML

Authentication: HTTP Basic (username + password).
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import AsyncIterator
from xml.etree import ElementTree

import httpx

from app.core.clients.scanners.base import ScannerClient
from app.core.clients.scanners.registry import register

logger = logging.getLogger("vulnops.scanners.qualys")

_SEVERITY_MAP = {
    "5": "critical",
    "4": "high",
    "3": "medium",
    "2": "low",
    "1": "low",
}


@register
class QualysClient(ScannerClient):
    name = "qualys"
    required_config_keys = ["username", "password", "platform_url"]
    # platform_url example: https://qualysapi.qualys.com

    def _auth(self) -> tuple[str, str]:
        return (self.config["username"], self.config["password"])

    def _base(self) -> str:
        return self.config["platform_url"].rstrip("/")

    async def test_connection(self) -> bool:
        async with httpx.AsyncClient(timeout=15) as client:
            try:
                resp = await client.post(
                    f"{self._base()}/api/2.0/fo/asset/host/vm/detection/",
                    auth=self._auth(),
                    data={"action": "list", "truncation_limit": "1"},
                    headers={"X-Requested-With": "VulnOps"},
                )
                return resp.status_code == 200
            except httpx.HTTPError as exc:
                logger.warning("Qualys connection test failed: %s", exc)
                return False

    async def fetch_findings(
        self, since: datetime | None = None
    ) -> AsyncIterator[dict]:
        params: dict[str, str] = {
            "action": "list",
            "show_results": "1",
            "output_format": "XML",
            "truncation_limit": "0",   # no pagination limit
        }
        if since is not None:
            params["vm_scan_date_after"] = since.strftime("%Y-%m-%dT%H:%M:%SZ")

        async with httpx.AsyncClient(timeout=120) as client:
            try:
                resp = await client.post(
                    f"{self._base()}/api/2.0/fo/asset/host/vm/detection/",
                    auth=self._auth(),
                    data=params,
                    headers={"X-Requested-With": "VulnOps"},
                )
                resp.raise_for_status()
            except httpx.HTTPError as exc:
                logger.error("Qualys fetch failed: %s", exc)
                return

        try:
            root = ElementTree.fromstring(resp.text)
        except ElementTree.ParseError as exc:
            logger.error("Qualys XML parse error: %s", exc)
            return

        for host in root.iter("HOST"):
            hostname = (host.findtext("DNS") or host.findtext("IP") or "").strip()
            for detection in host.iter("DETECTION"):
                cve_list_el = detection.find("CVE_LIST")
                if cve_list_el is None:
                    continue
                cve_ids = [
                    cve.findtext("ID") or ""
                    for cve in cve_list_el.findall("CVE")
                ]
                cve_ids = [c for c in cve_ids if c.startswith("CVE-")]
                if not cve_ids:
                    continue

                severity_raw = detection.findtext("SEVERITY") or "1"
                severity = _SEVERITY_MAP.get(severity_raw, "low")
                qid = detection.findtext("QID") or ""
                title = detection.findtext("RESULTS") or f"QID-{qid}"
                title = title[:255]
                cvss_raw = detection.findtext("CVSS_FINAL")

                for cve_id in cve_ids:
                    yield {
                        "cve_id": cve_id,
                        "title": title,
                        "description": title,
                        "severity": severity,
                        "source": "qualys",
                        "source_id": f"qualys-qid-{qid}-{cve_id}",
                        "affected_component": hostname or None,
                        "cvss_score": float(cvss_raw) if cvss_raw else None,
                    }
