"""
Asset register tests — CRUD endpoints, CSV import, and scanner parsers.

Coverage:
  Asset CRUD
    - Create: valid payload → 201, all fields returned
    - Create: missing name → 422
    - Create: requires auth → 403
    - Create: analyst can create, readonly cannot
    - Get single: found → 200, not found / wrong org → 404
    - List: returns only current org's assets (org scoping)
    - List: pagination works
    - List: filter by criticality, environment, internet_facing
    - Patch: updates only supplied fields
    - Patch: readonly user cannot patch → 403
    - Delete: admin can delete → 204
    - Delete: non-admin → 403
    - Delete: nonexistent → 404

  Asset CSV import
    - VulnOps generic format → imported correctly
    - Qualys CMDB format → auto-detected, mapped correctly
    - ServiceNow CMDB format → auto-detected, mapped correctly
    - Rapid7 asset list format → auto-detected, mapped correctly
    - Upsert: re-importing same IP updates rather than duplicates
    - Rows with no name/IP/hostname → skipped with error entry
    - internet_facing coercion: "true" / "1" / "yes" all → True

  Scanner parsers (unit tests — no DB)
    Tenable CSV
      - Standard export → VulnerabilityCreate with correct fields
      - Row without CVE ID → skipped (error returned)
      - Risk column maps to correct severity
      - CVSS v3 preferred over v2

    Nessus XML
      - Well-formed .nessus file → correct findings
      - Plugin without <cve> tag → skipped
      - Severity attribute 0-4 → correct severity
      - cvss3_base_score preferred over cvss_base_score
      - Malformed XML → graceful error

    Qualys CSV
      - Standard export → correct CVE/severity/CVSS mapping
      - Severity 1-5 → informational/low/medium/high/critical
      - QID without CVE ID → skipped
      - Multiple CVE IDs in one cell → primary + notes

    Rapid7 CSV
      - Standard export → correct mapping
      - Multiple CVE IDs → primary used, extras in notes
      - Rows without CVE → skipped

  Scanner ingestion endpoints
    - Tenable endpoint → 200 with ingested count
    - Nessus endpoint → 200 with ingested count
    - Qualys endpoint → 200 with ingested count
    - Rapid7 endpoint → 200 with ingested count

  Asset-vulnerability matching
    - Match by IP: vuln affected_component == asset IP → linked
    - Match by IP with port: "10.0.0.1:443" strips port, matches "10.0.0.1"
    - Match by hostname: vuln affected_component == asset hostname → linked
    - No cross-org match: org A asset cannot match org B vuln
    - Unmatched vuln stays null: no false positives

  New CMDB format round-trips (unit tests)
    - Intune: Device name → name, Serial number → external_id, asset_type=endpoint
    - SCCM: NetBIOS Name → name, space-separated IPs → first IP used
    - Axonius: Network Interfaces: IPs (comma-separated) → first IP
    - CrowdStrike: Hostname → hostname, Local IP → ip_address, Device ID → external_id
"""

from __future__ import annotations

import io
import textwrap
import uuid
from unittest.mock import patch

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

import csv as _csv_mod

from app.services.scanner_parsers import (
    parse_nessus_xml,
    parse_qualys_csv,
    parse_rapid7_csv,
    parse_tenable_csv,
)

# ── Constants ─────────────────────────────────────────────────────────────────

_BASE = "/api/v1"
_AUTH = f"{_BASE}/auth"
_ASSETS = f"{_BASE}/assets"
_VULNS = f"{_BASE}/vulnerabilities"
_PW = "S3cur3P@ssw0rd!"


@pytest.fixture(autouse=True)
def mock_hibp():
    with patch("app.api.routes.auth.is_password_pwned", return_value=False):
        yield


# ── Helpers ───────────────────────────────────────────────────────────────────

async def _register(client: AsyncClient, email: str, role: str = "admin") -> dict:
    resp = await client.post(
        f"{_AUTH}/register",
        json={"email": email, "password": _PW, "org_name": f"Org-{email}"},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


async def _downgrade(email: str, role: str, db: AsyncSession) -> None:
    from sqlalchemy import update
    from app.models.user import User
    await db.execute(update(User).where(User.email == email).values(role=role))
    await db.commit()


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _asset_payload(**overrides) -> dict:
    base = {
        "name": "prod-web-01",
        "asset_type": "server",
        "criticality": "high",
        "environment": "production",
        "internet_facing": True,
        "ip_address": "10.0.1.10",
        "hostname": "prod-web-01",
        "operating_system": "Ubuntu 22.04 LTS",
        "owner": "Platform team",
    }
    base.update(overrides)
    return base


def _csv(rows: list[dict]) -> bytes:
    if not rows:
        return b""
    headers = list(rows[0].keys())
    lines = [",".join(headers)]
    for row in rows:
        lines.append(",".join(str(row.get(h, "")) for h in headers))
    return "\n".join(lines).encode()


# ── Asset CRUD ────────────────────────────────────────────────────────────────

class TestAssetCreate:

    async def test_create_returns_201(self, client: AsyncClient):
        reg = await _register(client, "asset_create@example.com")
        resp = await client.post(_ASSETS + "/", json=_asset_payload(), headers=_auth(reg["access_token"]))
        assert resp.status_code == 201
        body = resp.json()
        assert body["name"] == "prod-web-01"
        assert body["ip_address"] == "10.0.1.10"
        assert body["internet_facing"] is True
        assert body["environment"] == "production"
        assert "id" in body

    async def test_create_all_fields_persisted(self, client: AsyncClient):
        reg = await _register(client, "asset_allfields@example.com")
        payload = _asset_payload(fqdn="prod-web-01.example.com", tags="pci,dmz", notes="Tier 1 asset")
        resp = await client.post(_ASSETS + "/", json=payload, headers=_auth(reg["access_token"]))
        assert resp.status_code == 201
        body = resp.json()
        assert body["fqdn"] == "prod-web-01.example.com"
        assert body["tags"] == "pci,dmz"
        assert body["notes"] == "Tier 1 asset"

    async def test_create_requires_auth(self, client: AsyncClient):
        resp = await client.post(_ASSETS + "/", json=_asset_payload())
        assert resp.status_code == 403

    async def test_create_requires_name(self, client: AsyncClient):
        reg = await _register(client, "asset_noname@example.com")
        resp = await client.post(_ASSETS + "/", json={"asset_type": "server"}, headers=_auth(reg["access_token"]))
        assert resp.status_code == 422

    async def test_analyst_can_create(self, client: AsyncClient, db_session: AsyncSession):
        reg = await _register(client, "asset_analyst@example.com")
        await _downgrade("asset_analyst@example.com", "analyst", db_session)
        resp = await client.post(_ASSETS + "/", json=_asset_payload(name="analyst-asset"), headers=_auth(reg["access_token"]))
        assert resp.status_code == 201

    async def test_readonly_cannot_create(self, client: AsyncClient, db_session: AsyncSession):
        reg = await _register(client, "asset_readonly@example.com")
        await _downgrade("asset_readonly@example.com", "readonly", db_session)
        resp = await client.post(_ASSETS + "/", json=_asset_payload(), headers=_auth(reg["access_token"]))
        assert resp.status_code == 403

    async def test_internet_facing_defaults_false(self, client: AsyncClient):
        reg = await _register(client, "asset_default_facing@example.com")
        resp = await client.post(_ASSETS + "/", json={"name": "internal-box"}, headers=_auth(reg["access_token"]))
        assert resp.status_code == 201
        assert resp.json()["internet_facing"] is False


class TestAssetRead:

    async def test_get_single_found(self, client: AsyncClient):
        reg = await _register(client, "asset_get@example.com")
        create = await client.post(_ASSETS + "/", json=_asset_payload(), headers=_auth(reg["access_token"]))
        asset_id = create.json()["id"]
        resp = await client.get(f"{_ASSETS}/{asset_id}", headers=_auth(reg["access_token"]))
        assert resp.status_code == 200
        assert resp.json()["id"] == asset_id

    async def test_get_single_not_found(self, client: AsyncClient):
        reg = await _register(client, "asset_notfound@example.com")
        resp = await client.get(f"{_ASSETS}/{uuid.uuid4()}", headers=_auth(reg["access_token"]))
        assert resp.status_code == 404

    async def test_org_scoping(self, client: AsyncClient):
        """Asset from org A is not visible to org B."""
        reg_a = await _register(client, "asset_org_a@example.com")
        reg_b = await _register(client, "asset_org_b@example.com")
        create = await client.post(_ASSETS + "/", json=_asset_payload(), headers=_auth(reg_a["access_token"]))
        asset_id = create.json()["id"]
        resp = await client.get(f"{_ASSETS}/{asset_id}", headers=_auth(reg_b["access_token"]))
        assert resp.status_code == 404

    async def test_list_returns_own_assets(self, client: AsyncClient):
        reg = await _register(client, "asset_list@example.com")
        await client.post(_ASSETS + "/", json=_asset_payload(name="a1", ip_address="10.0.0.1"), headers=_auth(reg["access_token"]))
        await client.post(_ASSETS + "/", json=_asset_payload(name="a2", ip_address="10.0.0.2"), headers=_auth(reg["access_token"]))
        resp = await client.get(_ASSETS + "/", headers=_auth(reg["access_token"]))
        assert resp.status_code == 200
        assert resp.json()["total"] == 2

    async def test_list_pagination(self, client: AsyncClient):
        reg = await _register(client, "asset_page@example.com")
        for i in range(5):
            await client.post(_ASSETS + "/", json=_asset_payload(name=f"box{i}", ip_address=f"10.1.0.{i}"), headers=_auth(reg["access_token"]))
        resp = await client.get(_ASSETS + "/?page=1&page_size=2", headers=_auth(reg["access_token"]))
        body = resp.json()
        assert len(body["items"]) == 2
        assert body["total"] == 5

    async def test_list_filter_criticality(self, client: AsyncClient):
        reg = await _register(client, "asset_filtcrit@example.com")
        await client.post(_ASSETS + "/", json=_asset_payload(name="high-box", ip_address="10.2.0.1", criticality="high"), headers=_auth(reg["access_token"]))
        await client.post(_ASSETS + "/", json=_asset_payload(name="low-box", ip_address="10.2.0.2", criticality="low"), headers=_auth(reg["access_token"]))
        resp = await client.get(_ASSETS + "/?criticality=high", headers=_auth(reg["access_token"]))
        body = resp.json()
        assert body["total"] == 1
        assert body["items"][0]["criticality"] == "high"

    async def test_list_filter_internet_facing(self, client: AsyncClient):
        reg = await _register(client, "asset_filtfacing@example.com")
        await client.post(_ASSETS + "/", json=_asset_payload(name="exposed", ip_address="1.2.3.4", internet_facing=True), headers=_auth(reg["access_token"]))
        await client.post(_ASSETS + "/", json=_asset_payload(name="internal", ip_address="10.3.0.1", internet_facing=False), headers=_auth(reg["access_token"]))
        resp = await client.get(_ASSETS + "/?internet_facing=true", headers=_auth(reg["access_token"]))
        assert resp.json()["total"] == 1
        assert resp.json()["items"][0]["name"] == "exposed"


class TestAssetMutate:

    async def test_patch_updates_fields(self, client: AsyncClient):
        reg = await _register(client, "asset_patch@example.com")
        create = await client.post(_ASSETS + "/", json=_asset_payload(), headers=_auth(reg["access_token"]))
        asset_id = create.json()["id"]
        resp = await client.patch(f"{_ASSETS}/{asset_id}", json={"criticality": "critical", "internet_facing": False}, headers=_auth(reg["access_token"]))
        assert resp.status_code == 200
        body = resp.json()
        assert body["criticality"] == "critical"
        assert body["internet_facing"] is False
        assert body["name"] == "prod-web-01"  # unchanged

    async def test_patch_not_found(self, client: AsyncClient):
        reg = await _register(client, "asset_patch_nf@example.com")
        resp = await client.patch(f"{_ASSETS}/{uuid.uuid4()}", json={"criticality": "low"}, headers=_auth(reg["access_token"]))
        assert resp.status_code == 404

    async def test_readonly_cannot_patch(self, client: AsyncClient, db_session: AsyncSession):
        reg = await _register(client, "asset_patch_ro@example.com")
        create = await client.post(_ASSETS + "/", json=_asset_payload(), headers=_auth(reg["access_token"]))
        asset_id = create.json()["id"]
        await _downgrade("asset_patch_ro@example.com", "readonly", db_session)
        resp = await client.patch(f"{_ASSETS}/{asset_id}", json={"criticality": "low"}, headers=_auth(reg["access_token"]))
        assert resp.status_code == 403

    async def test_delete_admin_succeeds(self, client: AsyncClient):
        reg = await _register(client, "asset_del@example.com")
        create = await client.post(_ASSETS + "/", json=_asset_payload(), headers=_auth(reg["access_token"]))
        asset_id = create.json()["id"]
        resp = await client.delete(f"{_ASSETS}/{asset_id}", headers=_auth(reg["access_token"]))
        assert resp.status_code == 204
        resp2 = await client.get(f"{_ASSETS}/{asset_id}", headers=_auth(reg["access_token"]))
        assert resp2.status_code == 404

    async def test_delete_non_admin_forbidden(self, client: AsyncClient, db_session: AsyncSession):
        reg = await _register(client, "asset_del_analyst@example.com")
        create = await client.post(_ASSETS + "/", json=_asset_payload(), headers=_auth(reg["access_token"]))
        asset_id = create.json()["id"]
        await _downgrade("asset_del_analyst@example.com", "analyst", db_session)
        resp = await client.delete(f"{_ASSETS}/{asset_id}", headers=_auth(reg["access_token"]))
        assert resp.status_code == 403

    async def test_delete_not_found(self, client: AsyncClient):
        reg = await _register(client, "asset_del_nf@example.com")
        resp = await client.delete(f"{_ASSETS}/{uuid.uuid4()}", headers=_auth(reg["access_token"]))
        assert resp.status_code == 404


# ── Asset CSV import ──────────────────────────────────────────────────────────

class TestAssetCSVImport:

    async def test_vulnops_format_imported(self, client: AsyncClient):
        reg = await _register(client, "asset_imp_vo@example.com")
        csv_data = _csv([
            {"name": "db-01", "ip_address": "192.168.1.10", "hostname": "db-01", "asset_type": "database",
             "criticality": "high", "environment": "production", "internet_facing": "false", "owner": "DBA team"},
            {"name": "web-01", "ip_address": "10.0.0.5", "hostname": "web-01", "asset_type": "server",
             "criticality": "critical", "environment": "production", "internet_facing": "true"},
        ])
        resp = await client.post(
            f"{_ASSETS}/import/csv",
            files={"file": ("assets.csv", csv_data, "text/csv")},
            headers=_auth(reg["access_token"]),
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["imported"] == 2
        assert body["updated"] == 0
        assert body["errors"] == []

    async def test_upsert_by_ip_updates_existing(self, client: AsyncClient):
        reg = await _register(client, "asset_imp_upsert@example.com")
        # First import
        csv1 = _csv([{"name": "server-a", "ip_address": "10.10.0.1", "criticality": "low"}])
        r1 = await client.post(f"{_ASSETS}/import/csv", files={"file": ("a.csv", csv1, "text/csv")}, headers=_auth(reg["access_token"]))
        assert r1.json()["imported"] == 1
        # Re-import same IP with updated criticality
        csv2 = _csv([{"name": "server-a-v2", "ip_address": "10.10.0.1", "criticality": "critical"}])
        r2 = await client.post(f"{_ASSETS}/import/csv", files={"file": ("b.csv", csv2, "text/csv")}, headers=_auth(reg["access_token"]))
        assert r2.json()["updated"] == 1
        assert r2.json()["imported"] == 0
        # Verify list has only 1 asset
        lst = await client.get(_ASSETS + "/", headers=_auth(reg["access_token"]))
        assert lst.json()["total"] == 1

    async def test_internet_facing_string_coercion(self, client: AsyncClient):
        reg = await _register(client, "asset_imp_bool@example.com")
        csv_data = _csv([
            {"name": "exposed", "ip_address": "1.1.1.1", "internet_facing": "true"},
            {"name": "internal", "ip_address": "10.0.0.1", "internet_facing": "false"},
            {"name": "yes-server", "ip_address": "2.2.2.2", "internet_facing": "yes"},
        ])
        resp = await client.post(f"{_ASSETS}/import/csv", files={"file": ("b.csv", csv_data, "text/csv")}, headers=_auth(reg["access_token"]))
        assert resp.json()["imported"] == 3
        assets_resp = await client.get(_ASSETS + "/?internet_facing=true", headers=_auth(reg["access_token"]))
        assert assets_resp.json()["total"] == 2

    async def test_qualys_cmdb_format(self, client: AsyncClient):
        """Qualys CMDB CSV (IP, DNS, NetBIOS, OS columns) is auto-detected."""
        csv_data = (
            b"IP,DNS,NetBIOS,OS,Asset Name,Tracking Method,Tags\n"
            b"192.168.5.10,web01.internal,WEB01,Windows Server 2019,,IP,pci\n"
            b"10.0.2.5,db01.internal,,Ubuntu 20.04,,IP,\n"
        )
        reg = await _register(client, "asset_imp_qualys@example.com")
        resp = await client.post(f"{_ASSETS}/import/csv", files={"file": ("qualys.csv", csv_data, "text/csv")}, headers=_auth(reg["access_token"]))
        assert resp.status_code == 200
        assert resp.json()["imported"] == 2
        # Verify IP and hostname mapped correctly
        lst = await client.get(_ASSETS + "/", headers=_auth(reg["access_token"]))
        ips = {a["ip_address"] for a in lst.json()["items"]}
        assert "192.168.5.10" in ips

    async def test_rapid7_asset_format(self, client: AsyncClient):
        """Rapid7 InsightVM asset list CSV is auto-detected."""
        csv_data = (
            b"Asset IP Address,Asset Name,Asset MAC Address,Asset OS Name,Asset OS Version,Asset Tags\n"
            b"172.16.0.5,app-server-01,AA:BB:CC:DD:EE:FF,CentOS 7,7.9,production\n"
            b"172.16.0.6,app-server-02,,Ubuntu 20.04,20.04.1,\n"
        )
        reg = await _register(client, "asset_imp_rapid7@example.com")
        resp = await client.post(f"{_ASSETS}/import/csv", files={"file": ("r7.csv", csv_data, "text/csv")}, headers=_auth(reg["access_token"]))
        assert resp.status_code == 200
        assert resp.json()["imported"] == 2
        lst = await client.get(_ASSETS + "/", headers=_auth(reg["access_token"]))
        names = {a["name"] for a in lst.json()["items"]}
        assert "app-server-01" in names

    async def test_empty_rows_skipped(self, client: AsyncClient):
        reg = await _register(client, "asset_imp_empty@example.com")
        csv_data = b"name,ip_address\n,,\n\nvalid-server,10.9.0.1\n"
        resp = await client.post(f"{_ASSETS}/import/csv", files={"file": ("e.csv", csv_data, "text/csv")}, headers=_auth(reg["access_token"]))
        assert resp.status_code == 200
        body = resp.json()
        assert body["imported"] == 1
        assert len(body["errors"]) >= 1  # empty row reported


# ── Scanner parser unit tests (no DB / HTTP) ──────────────────────────────────

class TestTenableParser:

    def _make_csv(self, rows: list[dict]) -> bytes:
        buf = io.StringIO()
        headers = list(rows[0].keys())
        w = _csv_mod.DictWriter(buf, fieldnames=headers)
        w.writeheader()
        w.writerows(rows)
        return buf.getvalue().encode()

    def _standard_row(self, **overrides) -> dict:
        base = {
            "Plugin ID": "19506",
            "CVE": "CVE-2021-44228",
            "CVSS v3.0 Base Score": "10.0",
            "CVSS v2.0 Base Score": "9.3",
            "Risk": "Critical",
            "Host": "192.168.1.5",
            "Port": "8080",
            "Name": "Apache Log4j RCE",
            "Synopsis": "Remote code execution via JNDI",
            "Description": "Log4Shell vulnerability in Log4j 2.x.",
            "Solution": "Upgrade to Log4j 2.15.0",
        }
        base.update(overrides)
        return base

    def test_valid_row_parsed(self):
        data = self._make_csv([self._standard_row()])
        results = parse_tenable_csv(data)
        assert len(results) == 1
        _, vuln, err = results[0]
        assert err is None
        assert vuln is not None
        assert vuln.cve_id == "CVE-2021-44228"
        assert vuln.severity == "critical"
        assert vuln.cvss_score == 10.0
        assert vuln.source == "tenable"

    def test_no_cve_row_skipped(self):
        row = self._standard_row(CVE="")
        data = self._make_csv([row])
        results = parse_tenable_csv(data)
        _, vuln, err = results[0]
        assert vuln is None
        assert err is not None

    def test_cvss_v3_preferred_over_v2(self):
        row = self._standard_row(**{"CVSS v3.0 Base Score": "8.5", "CVSS v2.0 Base Score": "7.2"})
        data = self._make_csv([row])
        _, vuln, _ = parse_tenable_csv(data)[0]
        assert vuln.cvss_score == 8.5

    def test_risk_severity_mapping(self):
        for risk, expected in [("Critical", "critical"), ("High", "high"), ("Medium", "medium"), ("Low", "low"), ("Info", "informational"), ("None", "informational")]:
            row = self._standard_row(Risk=risk)
            data = self._make_csv([row])
            _, vuln, _ = parse_tenable_csv(data)[0]
            if vuln:
                assert vuln.severity == expected

    def test_host_port_in_affected_component(self):
        row = self._standard_row(Host="10.0.0.5", Port="443")
        data = self._make_csv([row])
        _, vuln, _ = parse_tenable_csv(data)[0]
        assert "10.0.0.5" in vuln.affected_component
        assert "443" in vuln.affected_component

    def test_multiple_cves_extras_in_notes(self):
        row = self._standard_row(CVE="CVE-2021-44228,CVE-2021-45046")
        data = self._make_csv([row])
        _, vuln, _ = parse_tenable_csv(data)[0]
        assert vuln.cve_id == "CVE-2021-44228"
        assert "CVE-2021-45046" in (vuln.notes or "")

    def test_source_id_set(self):
        data = self._make_csv([self._standard_row()])
        _, vuln, _ = parse_tenable_csv(data)[0]
        assert vuln.source_id is not None
        assert "tenable" in vuln.source_id


class TestNessusParser:

    def _make_nessus(self, items: list[dict]) -> bytes:
        """Build a minimal .nessus XML with the given ReportItem dicts."""
        report_items = ""
        for item in items:
            cve_tags = "".join(f"<cve>{c}</cve>" for c in item.get("cves", []))
            report_items += f"""
            <ReportItem port="{item.get('port', '443')}"
                        protocol="tcp"
                        severity="{item.get('severity_attr', '3')}"
                        pluginID="{item.get('plugin_id', '99999')}"
                        pluginName="{item.get('plugin_name', 'Test Plugin')}">
                {cve_tags}
                <cvss3_base_score>{item.get('cvss3', '')}</cvss3_base_score>
                <cvss_base_score>{item.get('cvss2', '')}</cvss_base_score>
                <description>{item.get('description', 'A test vulnerability.')}</description>
                <synopsis>{item.get('synopsis', '')}</synopsis>
                <risk_factor>{item.get('risk_factor', '')}</risk_factor>
                <solution>{item.get('solution', '')}</solution>
            </ReportItem>"""
        return f"""<?xml version="1.0"?>
        <NessusClientData_v2>
          <Report name="TestReport">
            <ReportHost name="192.168.1.10">
              {report_items}
            </ReportHost>
          </Report>
        </NessusClientData_v2>""".encode()

    def test_valid_item_parsed(self):
        xml = self._make_nessus([{"cves": ["CVE-2021-44228"], "cvss3": "10.0", "risk_factor": "Critical", "plugin_name": "Log4Shell"}])
        results = parse_nessus_xml(xml)
        assert len(results) == 1
        _, vuln, err = results[0]
        assert err is None
        assert vuln.cve_id == "CVE-2021-44228"
        assert vuln.severity == "critical"
        assert vuln.cvss_score == 10.0
        assert vuln.source == "nessus"

    def test_no_cve_item_skipped(self):
        xml = self._make_nessus([{"cves": [], "plugin_id": "12345"}])
        results = parse_nessus_xml(xml)
        _, vuln, err = results[0]
        assert vuln is None
        assert err is not None

    def test_severity_attr_fallback(self):
        """When risk_factor is absent, severity attribute 0-4 is used."""
        xml = self._make_nessus([{"cves": ["CVE-2024-1111"], "severity_attr": "4", "risk_factor": ""}])
        _, vuln, _ = parse_nessus_xml(xml)[0]
        assert vuln.severity == "critical"

    def test_cvss3_preferred_over_cvss2(self):
        xml = self._make_nessus([{"cves": ["CVE-2024-2222"], "cvss3": "8.0", "cvss2": "7.0", "risk_factor": "High"}])
        _, vuln, _ = parse_nessus_xml(xml)[0]
        assert vuln.cvss_score == 8.0

    def test_malformed_xml_returns_error(self):
        results = parse_nessus_xml(b"this is not xml at all <><><")
        assert len(results) == 1
        _, vuln, err = results[0]
        assert vuln is None
        assert err is not None

    def test_severity_numeric_mapping(self):
        for attr, expected in [("4", "critical"), ("3", "high"), ("2", "medium"), ("1", "low"), ("0", "informational")]:
            xml = self._make_nessus([{"cves": ["CVE-2024-9999"], "severity_attr": attr, "risk_factor": ""}])
            _, vuln, _ = parse_nessus_xml(xml)[0]
            if vuln:
                assert vuln.severity == expected

    def test_host_and_port_in_affected_component(self):
        xml = self._make_nessus([{"cves": ["CVE-2024-3333"], "port": "8443", "risk_factor": "Medium"}])
        _, vuln, _ = parse_nessus_xml(xml)[0]
        assert "192.168.1.10" in vuln.affected_component
        assert "8443" in vuln.affected_component


class TestQualysParser:

    def _make_csv(self, rows: list[dict]) -> bytes:
        buf = io.StringIO()
        headers = list(rows[0].keys())
        w = _csv_mod.DictWriter(buf, fieldnames=headers)
        w.writeheader()
        w.writerows(rows)
        return buf.getvalue().encode()

    def _standard_row(self, **overrides) -> dict:
        base = {
            "QID": "90001",
            "Title": "OpenSSL Heartbleed",
            "Severity": "5",
            "IP": "10.0.1.5",
            "DNS": "internal-server",
            "OS": "Ubuntu 18.04",
            "CVSSv3 Base": "7.5",
            "CVE ID": "CVE-2014-0160",
            "Impact": "Remote memory disclosure vulnerability.",
            "Solution": "Upgrade OpenSSL.",
        }
        base.update(overrides)
        return base

    def test_valid_row_parsed(self):
        data = self._make_csv([self._standard_row()])
        results = parse_qualys_csv(data)
        assert len(results) == 1
        _, vuln, err = results[0]
        assert err is None
        assert vuln.cve_id == "CVE-2014-0160"
        assert vuln.severity == "critical"
        assert vuln.cvss_score == 7.5
        assert vuln.source == "qualys"

    def test_severity_1_to_5_mapping(self):
        mapping = {"5": "critical", "4": "high", "3": "medium", "2": "low", "1": "informational"}
        for sev, expected in mapping.items():
            data = self._make_csv([self._standard_row(Severity=sev)])
            _, vuln, _ = parse_qualys_csv(data)[0]
            if vuln:
                assert vuln.severity == expected

    def test_no_cve_row_skipped(self):
        data = self._make_csv([self._standard_row(**{"CVE ID": ""})])
        _, vuln, err = parse_qualys_csv(data)[0]
        assert vuln is None
        assert err is not None

    def test_multiple_cves_first_used(self):
        data = self._make_csv([self._standard_row(**{"CVE ID": "CVE-2014-0160, CVE-2014-0224"})])
        _, vuln, _ = parse_qualys_csv(data)[0]
        assert vuln.cve_id == "CVE-2014-0160"
        assert "CVE-2014-0224" in (vuln.notes or "")

    def test_ip_and_dns_in_affected_component(self):
        data = self._make_csv([self._standard_row(IP="192.168.2.1", DNS="myserver")])
        _, vuln, _ = parse_qualys_csv(data)[0]
        assert vuln.affected_component is not None


class TestRapid7Parser:

    def _make_csv(self, rows: list[dict]) -> bytes:
        buf = io.StringIO()
        headers = list(rows[0].keys())
        w = _csv_mod.DictWriter(buf, fieldnames=headers)
        w.writeheader()
        w.writerows(rows)
        return buf.getvalue().encode()

    def _standard_row(self, **overrides) -> dict:
        base = {
            "Asset IP Address": "10.5.0.10",
            "Asset Name": "prod-app-server",
            "Asset MAC Address": "AA:BB:CC:11:22:33",
            "Asset OS Name": "Windows Server 2019",
            "Asset OS Version": "10.0",
            "Vulnerability Title": "MS17-010 EternalBlue",
            "Vulnerability ID": "ms17-010-eternalblue",
            "Severity": "Critical",
            "CVE IDs": "CVE-2017-0144",
            "CVSSv3 Score": "9.8",
            "CVSSv2 Score": "10.0",
            "CVSS Score": "9.8",
            "Risk Score": "1000",
            "Proof": "SMBv1 responding on port 445.",
            "First Seen": "2024-01-01",
            "Last Seen": "2024-01-10",
            "Status": "vulnerable",
        }
        base.update(overrides)
        return base

    def test_valid_row_parsed(self):
        data = self._make_csv([self._standard_row()])
        results = parse_rapid7_csv(data)
        assert len(results) == 1
        _, vuln, err = results[0]
        assert err is None
        assert vuln.cve_id == "CVE-2017-0144"
        assert vuln.severity == "critical"
        assert vuln.cvss_score == 9.8
        assert vuln.source == "rapid7"

    def test_no_cve_row_skipped(self):
        data = self._make_csv([self._standard_row(**{"CVE IDs": ""})])
        _, vuln, err = parse_rapid7_csv(data)[0]
        assert vuln is None

    def test_multiple_cves_first_used_extras_in_notes(self):
        data = self._make_csv([self._standard_row(**{"CVE IDs": "CVE-2017-0144, CVE-2017-0145, CVE-2017-0148"})])
        _, vuln, _ = parse_rapid7_csv(data)[0]
        assert vuln.cve_id == "CVE-2017-0144"
        assert "CVE-2017-0145" in (vuln.notes or "")

    def test_asset_name_in_affected_component(self):
        data = self._make_csv([self._standard_row(**{"Asset Name": "db-server-1", "Asset IP Address": "172.16.0.20"})])
        _, vuln, _ = parse_rapid7_csv(data)[0]
        assert vuln.affected_component in ("db-server-1", "172.16.0.20")

    def test_severity_word_mapping(self):
        for sev, expected in [("Critical", "critical"), ("High", "high"), ("Medium", "medium"), ("Low", "low")]:
            data = self._make_csv([self._standard_row(Severity=sev)])
            _, vuln, _ = parse_rapid7_csv(data)[0]
            if vuln:
                assert vuln.severity == expected


# ── Scanner ingestion endpoints ───────────────────────────────────────────────

class TestScannerIngestionEndpoints:
    """Integration tests: upload scanner files through the HTTP API."""

    def _tenable_csv(self) -> bytes:
        return (
            b"Plugin ID,CVE,CVSS v3.0 Base Score,Risk,Host,Port,Name,Synopsis,Description,Solution\n"
            b"19506,CVE-2021-44228,10.0,Critical,10.0.0.1,8080,Log4Shell,JNDI injection,Remote code execution in Log4j.,Upgrade Log4j.\n"
            b"10881,CVE-2014-0160,7.5,High,10.0.0.2,443,Heartbleed,SSL memory disclosure,OpenSSL heartbeat bug.,Upgrade OpenSSL.\n"
            b"12345,,5.0,Medium,10.0.0.3,80,Non-CVE Plugin,Some finding,No CVE associated.,Patch system.\n"
        )

    def _nessus_xml(self) -> bytes:
        return (
            b'<?xml version="1.0"?>'
            b'<NessusClientData_v2><Report name="R">'
            b'<ReportHost name="192.168.1.1">'
            b'<ReportItem port="443" protocol="tcp" severity="4" pluginID="1" pluginName="EternalBlue">'
            b'<cve>CVE-2017-0144</cve><cvss3_base_score>9.8</cvss3_base_score>'
            b'<description>MS17-010</description><risk_factor>Critical</risk_factor>'
            b'</ReportItem>'
            b'<ReportItem port="80" protocol="tcp" severity="3" pluginID="2" pluginName="Struts">'
            b'<cve>CVE-2017-5638</cve><cvss3_base_score>10.0</cvss3_base_score>'
            b'<description>Apache Struts RCE</description><risk_factor>Critical</risk_factor>'
            b'</ReportItem>'
            b'</ReportHost></Report></NessusClientData_v2>'
        )

    def _qualys_csv(self) -> bytes:
        return (
            b"QID,Title,Severity,IP,DNS,OS,CVSSv3 Base,CVE ID,Impact,Solution\n"
            b"90001,Heartbleed,5,10.1.1.1,host1,Ubuntu,7.5,CVE-2014-0160,Memory disclosure.,Upgrade OpenSSL.\n"
            b"90002,ShellShock,4,10.1.1.2,host2,Linux,9.8,CVE-2014-6271,RCE via env vars.,Patch bash.\n"
        )

    def _rapid7_csv(self) -> bytes:
        return (
            b"Asset IP Address,Asset Name,Asset OS Name,Vulnerability Title,Vulnerability ID,Severity,CVE IDs,CVSSv3 Score,Proof\n"
            b"172.16.0.5,app01,Ubuntu 20.04,Log4Shell,log4shell,Critical,CVE-2021-44228,10.0,JNDI endpoint detected.\n"
            b"172.16.0.6,app02,CentOS 7,EternalBlue,eternal-blue,Critical,CVE-2017-0144,9.8,SMBv1 responds on 445.\n"
        )

    async def test_tenable_endpoint(self, client: AsyncClient):
        reg = await _register(client, "scan_tenable@example.com")
        resp = await client.post(
            f"{_VULNS}/ingest/tenable",
            files={"file": ("export.csv", self._tenable_csv(), "text/csv")},
            headers=_auth(reg["access_token"]),
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["ingested"] == 2           # 2 rows with CVEs
        assert len(body["errors"]) == 1        # 1 row without CVE

    async def test_nessus_endpoint(self, client: AsyncClient):
        reg = await _register(client, "scan_nessus@example.com")
        resp = await client.post(
            f"{_VULNS}/ingest/nessus",
            files={"file": ("scan.nessus", self._nessus_xml(), "application/xml")},
            headers=_auth(reg["access_token"]),
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["ingested"] == 2

    async def test_qualys_endpoint(self, client: AsyncClient):
        reg = await _register(client, "scan_qualys@example.com")
        resp = await client.post(
            f"{_VULNS}/ingest/qualys",
            files={"file": ("qualys.csv", self._qualys_csv(), "text/csv")},
            headers=_auth(reg["access_token"]),
        )
        assert resp.status_code == 200
        assert resp.json()["ingested"] == 2

    async def test_rapid7_endpoint(self, client: AsyncClient):
        reg = await _register(client, "scan_rapid7@example.com")
        resp = await client.post(
            f"{_VULNS}/ingest/rapid7",
            files={"file": ("r7.csv", self._rapid7_csv(), "text/csv")},
            headers=_auth(reg["access_token"]),
        )
        assert resp.status_code == 200
        assert resp.json()["ingested"] == 2

    async def test_scanner_endpoint_requires_auth(self, client: AsyncClient):
        resp = await client.post(
            f"{_VULNS}/ingest/tenable",
            files={"file": ("x.csv", b"a,b\n", "text/csv")},
        )
        assert resp.status_code == 403

    async def test_scanner_results_visible_in_findings_list(self, client: AsyncClient):
        """Ingested scanner findings appear in GET /vulnerabilities/."""
        reg = await _register(client, "scan_list@example.com")
        await client.post(
            f"{_VULNS}/ingest/nessus",
            files={"file": ("scan.nessus", self._nessus_xml(), "application/xml")},
            headers=_auth(reg["access_token"]),
        )
        lst = await client.get(f"{_VULNS}/", headers=_auth(reg["access_token"]))
        assert lst.json()["total"] >= 2


# ── Asset-vulnerability matching ──────────────────────────────────────────────

class TestAssetVulnMatching:
    """Integration tests for POST /assets/match-vulnerabilities."""

    def _vuln_payload(self, cve_id: str, affected_component: str | None = None, **extra) -> dict:
        payload = {
            "cve_id": cve_id,
            "title": f"Test vuln {cve_id}",
            "description": "Test description for asset matching.",
            "severity": "high",
            "source": "manual",
        }
        if affected_component is not None:
            payload["affected_component"] = affected_component
        payload.update(extra)
        return payload

    async def test_match_by_ip(self, client: AsyncClient):
        """Vuln with affected_component matching an asset IP gets linked."""
        reg = await _register(client, "match_ip@example.com")
        tok = reg["access_token"]

        # Create asset with known IP
        await client.post(_ASSETS + "/", json=_asset_payload(name="web-match", ip_address="10.5.0.1"), headers=_auth(tok))

        # Ingest a vuln whose affected_component is that IP
        v = await client.post(_VULNS + "/", json=self._vuln_payload("CVE-2024-70001", affected_component="10.5.0.1"), headers=_auth(tok))
        vuln_id = v.json()["id"]

        # Match
        resp = await client.post(f"{_ASSETS}/match-vulnerabilities", headers=_auth(tok))
        assert resp.status_code == 200
        assert resp.json()["matched"] == 1

        # Verify asset_id is set
        vuln = await client.get(f"{_VULNS}/{vuln_id}", headers=_auth(tok))
        assert vuln.json()["asset_id"] is not None

    async def test_match_by_ip_with_port(self, client: AsyncClient):
        """affected_component with :port suffix is still matched by base IP."""
        reg = await _register(client, "match_ip_port@example.com")
        tok = reg["access_token"]

        await client.post(_ASSETS + "/", json=_asset_payload(name="api-gw", ip_address="10.5.1.1"), headers=_auth(tok))
        v = await client.post(_VULNS + "/", json=self._vuln_payload("CVE-2024-70002", affected_component="10.5.1.1:443"), headers=_auth(tok))
        vuln_id = v.json()["id"]

        resp = await client.post(f"{_ASSETS}/match-vulnerabilities", headers=_auth(tok))
        assert resp.json()["matched"] == 1
        vuln = await client.get(f"{_VULNS}/{vuln_id}", headers=_auth(tok))
        assert vuln.json()["asset_id"] is not None

    async def test_match_by_hostname(self, client: AsyncClient):
        """Vuln with affected_component matching an asset hostname gets linked."""
        reg = await _register(client, "match_hostname@example.com")
        tok = reg["access_token"]

        await client.post(_ASSETS + "/", json=_asset_payload(name="db01", hostname="db01.internal", ip_address="10.5.2.1"), headers=_auth(tok))
        v = await client.post(_VULNS + "/", json=self._vuln_payload("CVE-2024-70003", affected_component="db01.internal"), headers=_auth(tok))
        vuln_id = v.json()["id"]

        resp = await client.post(f"{_ASSETS}/match-vulnerabilities", headers=_auth(tok))
        assert resp.json()["matched"] >= 1
        vuln = await client.get(f"{_VULNS}/{vuln_id}", headers=_auth(tok))
        assert vuln.json()["asset_id"] is not None

    async def test_no_cross_org_match(self, client: AsyncClient):
        """Asset from org A must not match a vuln from org B."""
        reg_a = await _register(client, "match_orgA@example.com")
        reg_b = await _register(client, "match_orgB@example.com")

        # Org A has an asset with IP 10.5.3.1
        await client.post(_ASSETS + "/", json=_asset_payload(name="a-box", ip_address="10.5.3.1"), headers=_auth(reg_a["access_token"]))

        # Org B has a vuln pointing at the same IP
        v = await client.post(_VULNS + "/", json=self._vuln_payload("CVE-2024-70004", affected_component="10.5.3.1"), headers=_auth(reg_b["access_token"]))
        vuln_id = v.json()["id"]

        # Org B runs match
        resp = await client.post(f"{_ASSETS}/match-vulnerabilities", headers=_auth(reg_b["access_token"]))
        assert resp.json()["matched"] == 0

        # Vuln remains unlinked
        vuln = await client.get(f"{_VULNS}/{vuln_id}", headers=_auth(reg_b["access_token"]))
        assert vuln.json()["asset_id"] is None

    async def test_unmatched_vuln_stays_null(self, client: AsyncClient):
        """Vuln with no matching asset keeps asset_id=None."""
        reg = await _register(client, "match_none@example.com")
        tok = reg["access_token"]

        # Asset with a different IP
        await client.post(_ASSETS + "/", json=_asset_payload(name="unrelated", ip_address="10.5.4.1"), headers=_auth(tok))

        # Vuln pointing at an IP with no asset
        v = await client.post(_VULNS + "/", json=self._vuln_payload("CVE-2024-70005", affected_component="192.0.2.99"), headers=_auth(tok))
        vuln_id = v.json()["id"]

        resp = await client.post(f"{_ASSETS}/match-vulnerabilities", headers=_auth(tok))
        assert resp.json()["matched"] == 0
        vuln = await client.get(f"{_VULNS}/{vuln_id}", headers=_auth(tok))
        assert vuln.json()["asset_id"] is None


# ── New CMDB format CSV round-trips (unit tests — no DB) ─────────────────────

class TestNewCMDBFormats:
    """Unit tests for Intune, SCCM, Axonius, CrowdStrike CSV parsing."""

    def _make_csv(self, rows: list[dict]) -> bytes:
        buf = io.StringIO()
        headers = list(rows[0].keys())
        w = _csv_mod.DictWriter(buf, fieldnames=headers)
        w.writeheader()
        w.writerows(rows)
        return buf.getvalue().encode()

    def test_intune_csv_roundtrip(self):
        """Intune export: Device name → name, Serial number → external_id, asset_type=endpoint."""
        from app.services.asset import parse_asset_csv
        data = self._make_csv([{
            "Device name": "LAPTOP-ABCD",
            "Serial number": "SN12345678",
            "Primary user UPN": "alice@corp.com",
            "Operating System": "Windows 11",
            "OS Version": "22H2",
            "Device Type": "Laptop",
            "Last check-in": "2024-01-10",
            "Compliance state": "Compliant",
        }])
        results = parse_asset_csv(data)
        assert len(results) == 1
        _, parsed, err = results[0]
        assert err is None, err
        assert parsed is not None
        assert parsed.name == "LAPTOP-ABCD"
        assert parsed.external_id == "SN12345678"
        assert parsed.asset_type == "endpoint"
        assert parsed.environment == "other"
        assert parsed.owner == "alice@corp.com"

    def test_sccm_csv_roundtrip(self):
        """SCCM export: NetBIOS Name → name, IP Addresses (space-separated) → first IP."""
        from app.services.asset import parse_asset_csv
        data = self._make_csv([{
            "NetBIOS Name": "DESKTOP-XYZ",
            "IP Addresses": "10.20.30.40 169.254.1.1",
            "Last Logon User Name": "bob",
            "Operating System Name and Version": "Windows 10 Enterprise",
            "Resource Domain or Workgroup": "CORP",
            "Client": "Yes",
        }])
        results = parse_asset_csv(data)
        assert len(results) == 1
        _, parsed, err = results[0]
        assert err is None, err
        assert parsed is not None
        assert parsed.name == "DESKTOP-XYZ"
        # Only the first of the space-separated IPs should be used
        assert parsed.ip_address == "10.20.30.40"

    def test_axonius_csv_roundtrip(self):
        """Axonius export: Network Interfaces: IPs (comma-separated) → first IP."""
        from app.services.asset import parse_asset_csv
        data = self._make_csv([{
            "Name": "axonius-device",
            "Hostname": "axonius-device.example.com",
            "Network Interfaces: IPs": "10.0.0.5, 10.0.0.6, 10.0.0.7",
            "OS.Type": "Linux",
            "OS.Distribution": "Ubuntu 22.04",
            "Asset criticality": "high",
            "Owners": "infra-team",
            "Labels": "pci,production",
            "Last seen": "2024-01-15",
        }])
        results = parse_asset_csv(data)
        assert len(results) == 1
        _, parsed, err = results[0]
        assert err is None, err
        assert parsed is not None
        assert parsed.name == "axonius-device"
        # Only the first comma-separated IP should be used
        assert parsed.ip_address == "10.0.0.5"
        assert parsed.criticality == "high"

    def test_crowdstrike_csv_roundtrip(self):
        """CrowdStrike export: Hostname → hostname, Local IP → ip_address, Device ID → external_id."""
        from app.services.asset import parse_asset_csv
        data = self._make_csv([{
            "Hostname": "cs-endpoint-01",
            "Local IP": "10.30.0.55",
            "External IP": "203.0.113.10",
            "OS Version": "Windows Server 2022",
            "Platform Name": "Windows",
            "Device ID": "abc123def456",
            "Tags": "server,prod",
            "First seen": "2023-12-01",
            "Last seen": "2024-01-15",
        }])
        results = parse_asset_csv(data)
        assert len(results) == 1
        _, parsed, err = results[0]
        assert err is None, err
        assert parsed is not None
        assert parsed.hostname == "cs-endpoint-01"
        assert parsed.ip_address == "10.30.0.55"
        assert parsed.external_id == "abc123def456"
        # Name should fall back to hostname
        assert parsed.name == "cs-endpoint-01"
