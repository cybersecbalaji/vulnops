"""
Phase 8 tests — Reporting dashboard + PDF export + audit log.

Test strategy:
  - Unit test: generate_dashboard_pdf returns valid non-empty bytes.
  - Dashboard endpoint: counts match ingested vulnerabilities.
  - PDF endpoint: returns application/pdf with non-empty body.
  - Audit log endpoint: admin-only, entries appear after create/delete,
    pagination and filtering work.

Note: _register() creates the org's first user as "admin" by design (see auth route).
For non-admin tests, downgrade the user role via direct DB update.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from httpx import AsyncClient
from sqlalchemy import update

from app.main import app
from app.models.user import User
from app.services.reports import DashboardStats, generate_dashboard_pdf

# ── Constants / helpers ───────────────────────────────────────────────────────

_BASE = "/api/v1"
_AUTH_URL = f"{_BASE}/auth"
_VULN_URL = f"{_BASE}/vulnerabilities"
_REPORTS_URL = f"{_BASE}/reports"


@pytest.fixture(autouse=True)
def mock_hibp_not_pwned():
    with patch("app.api.routes.auth.is_password_pwned", return_value=False):
        yield


async def _register(client: AsyncClient, email: str) -> dict:
    """Register a new org+user (role defaults to 'admin' per auth route design)."""
    resp = await client.post(
        f"{_AUTH_URL}/register",
        json={"email": email, "password": "S3cur3P@ssw0rd!", "org_name": f"Org-{email}"},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


async def _downgrade_to_analyst(email: str, db_session) -> None:
    """Downgrade a user's role to analyst via direct DB update."""
    await db_session.execute(
        update(User).where(User.email == email).values(role="analyst")
    )
    await db_session.commit()


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _vuln_payload(cve_id: str = "CVE-2024-30001", **kwargs) -> dict:
    return {
        "cve_id": cve_id,
        "title": "Test Vuln",
        "description": "A test vulnerability description.",
        "severity": "high",
        "source": "manual",
        **kwargs,
    }


# ── Unit tests: PDF generation ────────────────────────────────────────────────

class TestGenerateDashboardPdf:
    def test_returns_bytes(self):
        stats = DashboardStats(
            total=10,
            duplicate_count=2,
            kev_count=3,
            scored_count=8,
            by_severity={"critical": 2, "high": 5, "medium": 3},
            by_status={"open": 8, "triaged": 2},
            by_priority={"immediate": 2, "this_week": 3, "monitor": 5},
        )
        result = generate_dashboard_pdf(stats, org_name="Test Org")
        assert isinstance(result, bytes)
        assert len(result) > 100

    def test_pdf_starts_with_pdf_signature(self):
        stats = DashboardStats()
        result = generate_dashboard_pdf(stats)
        assert result.startswith(b"%PDF")

    def test_empty_stats_still_generates_pdf(self):
        stats = DashboardStats()
        result = generate_dashboard_pdf(stats, org_name="Empty Org")
        assert isinstance(result, bytes)
        assert len(result) > 100

    def test_all_severity_levels_in_output(self):
        """Stats with all severity levels renders without error."""
        stats = DashboardStats(
            total=5,
            by_severity={"critical": 1, "high": 1, "medium": 1, "low": 1, "informational": 1},
        )
        result = generate_dashboard_pdf(stats)
        assert result.startswith(b"%PDF")


# ── Dashboard endpoint tests ──────────────────────────────────────────────────

class TestDashboardEndpoint:
    async def test_dashboard_requires_auth(self, client: AsyncClient):
        resp = await client.get(f"{_REPORTS_URL}/dashboard")
        assert resp.status_code == 403

    async def test_dashboard_empty_org_returns_zeros(self, client: AsyncClient):
        data = await _register(client, "dash1@test.com")
        token = data["access_token"]
        resp = await client.get(f"{_REPORTS_URL}/dashboard", headers=_auth(token))
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 0
        assert body["kev_count"] == 0
        assert body["scored_count"] == 0
        assert body["by_severity"] == {}
        assert body["by_status"] == {}

    async def test_dashboard_counts_match_ingested_vulns(self, client: AsyncClient):
        data = await _register(client, "dash2@test.com")
        token = data["access_token"]

        await client.post(_VULN_URL + "/", json=_vuln_payload("CVE-2024-40001", severity="high"), headers=_auth(token))
        await client.post(_VULN_URL + "/", json=_vuln_payload("CVE-2024-40002", severity="high"), headers=_auth(token))
        await client.post(_VULN_URL + "/", json=_vuln_payload("CVE-2024-40003", severity="critical"), headers=_auth(token))

        resp = await client.get(f"{_REPORTS_URL}/dashboard", headers=_auth(token))
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 3
        assert body["by_severity"]["high"] == 2
        assert body["by_severity"]["critical"] == 1
        assert body["by_status"]["open"] == 3

    async def test_dashboard_by_priority_unscored_when_no_scoring(self, client: AsyncClient):
        data = await _register(client, "dash3@test.com")
        token = data["access_token"]
        await client.post(_VULN_URL + "/", json=_vuln_payload("CVE-2024-50001"), headers=_auth(token))

        resp = await client.get(f"{_REPORTS_URL}/dashboard", headers=_auth(token))
        assert resp.status_code == 200
        body = resp.json()
        assert body["by_priority"].get("unscored", 0) == 1

    async def test_dashboard_duplicate_count(self, client: AsyncClient):
        """Creating the same CVE twice marks the second as duplicate."""
        data = await _register(client, "dash4@test.com")
        token = data["access_token"]
        await client.post(_VULN_URL + "/", json=_vuln_payload("CVE-2024-60001"), headers=_auth(token))
        await client.post(_VULN_URL + "/", json=_vuln_payload("CVE-2024-60001"), headers=_auth(token))

        resp = await client.get(f"{_REPORTS_URL}/dashboard", headers=_auth(token))
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 1
        assert body["duplicate_count"] == 1


# ── PDF export endpoint tests ─────────────────────────────────────────────────

class TestDashboardPdfEndpoint:
    async def test_pdf_requires_auth(self, client: AsyncClient):
        resp = await client.get(f"{_REPORTS_URL}/dashboard/pdf")
        assert resp.status_code == 403

    async def test_pdf_returns_pdf_content_type(self, client: AsyncClient):
        data = await _register(client, "pdf1@test.com")
        token = data["access_token"]
        resp = await client.get(f"{_REPORTS_URL}/dashboard/pdf", headers=_auth(token))
        assert resp.status_code == 200
        assert "application/pdf" in resp.headers["content-type"]

    async def test_pdf_body_is_non_empty_pdf(self, client: AsyncClient):
        data = await _register(client, "pdf2@test.com")
        token = data["access_token"]
        resp = await client.get(f"{_REPORTS_URL}/dashboard/pdf", headers=_auth(token))
        assert resp.status_code == 200
        assert resp.content.startswith(b"%PDF")
        assert len(resp.content) > 200

    async def test_pdf_content_disposition_header(self, client: AsyncClient):
        data = await _register(client, "pdf3@test.com")
        token = data["access_token"]
        resp = await client.get(f"{_REPORTS_URL}/dashboard/pdf", headers=_auth(token))
        assert resp.status_code == 200
        assert "vulnops-dashboard.pdf" in resp.headers.get("content-disposition", "")


# ── Audit log endpoint tests ──────────────────────────────────────────────────

class TestAuditLogEndpoint:
    async def test_audit_log_requires_admin(self, client: AsyncClient, db_session):
        """Analyst role cannot access the audit log."""
        data = await _register(client, "audit1@test.com")
        token = data["access_token"]
        # Downgrade from admin to analyst
        await _downgrade_to_analyst("audit1@test.com", db_session)

        resp = await client.get(f"{_REPORTS_URL}/audit-log", headers=_auth(token))
        assert resp.status_code == 403

    async def test_audit_log_accessible_to_admin(self, client: AsyncClient):
        """Admin (default registered role) can access the audit log."""
        data = await _register(client, "audit2@test.com")
        token = data["access_token"]
        resp = await client.get(f"{_REPORTS_URL}/audit-log", headers=_auth(token))
        assert resp.status_code == 200
        body = resp.json()
        assert "items" in body
        assert "total" in body

    async def test_audit_log_entry_after_vuln_create(self, client: AsyncClient):
        data = await _register(client, "audit3@test.com")
        token = data["access_token"]

        resp = await client.post(
            _VULN_URL + "/",
            json=_vuln_payload("CVE-2024-70001"),
            headers=_auth(token),
        )
        assert resp.status_code == 201

        resp = await client.get(f"{_REPORTS_URL}/audit-log", headers=_auth(token))
        assert resp.status_code == 200
        items = resp.json()["items"]
        actions = [e["action"] for e in items]
        assert "vulnerability.created" in actions

    async def test_audit_log_entry_after_vuln_delete(self, client: AsyncClient):
        data = await _register(client, "audit4@test.com")
        token = data["access_token"]

        resp = await client.post(
            _VULN_URL + "/",
            json=_vuln_payload("CVE-2024-80001"),
            headers=_auth(token),
        )
        vuln_id = resp.json()["id"]

        resp = await client.delete(f"{_VULN_URL}/{vuln_id}", headers=_auth(token))
        assert resp.status_code == 204

        resp = await client.get(f"{_REPORTS_URL}/audit-log", headers=_auth(token))
        items = resp.json()["items"]
        actions = [e["action"] for e in items]
        assert "vulnerability.deleted" in actions

    async def test_audit_log_filter_by_action(self, client: AsyncClient):
        data = await _register(client, "audit5@test.com")
        token = data["access_token"]

        await client.post(_VULN_URL + "/", json=_vuln_payload("CVE-2024-90001"), headers=_auth(token))
        await client.post(_VULN_URL + "/", json=_vuln_payload("CVE-2024-90002"), headers=_auth(token))

        resp = await client.get(
            f"{_REPORTS_URL}/audit-log",
            params={"action": "vulnerability.created"},
            headers=_auth(token),
        )
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert all(e["action"] == "vulnerability.created" for e in items)
        assert len(items) >= 2

    async def test_audit_log_pagination(self, client: AsyncClient):
        data = await _register(client, "audit6@test.com")
        token = data["access_token"]

        for i in range(3):
            await client.post(
                _VULN_URL + "/",
                json=_vuln_payload(f"CVE-2024-910{i+1}"),
                headers=_auth(token),
            )

        resp = await client.get(
            f"{_REPORTS_URL}/audit-log",
            params={"page": 1, "page_size": 2},
            headers=_auth(token),
        )
        assert resp.status_code == 200
        body = resp.json()
        assert len(body["items"]) <= 2
        assert body["page"] == 1
        assert body["page_size"] == 2

    async def test_audit_log_scoped_to_org(self, client: AsyncClient):
        """Org A's create events are not in Org B's audit log."""
        dataA = await _register(client, "auditorgA@test.com")
        dataB = await _register(client, "auditorgB@test.com")
        tokenA = dataA["access_token"]
        tokenB = dataB["access_token"]

        # Org A creates a vuln
        resp = await client.post(_VULN_URL + "/", json=_vuln_payload("CVE-2024-99001"), headers=_auth(tokenA))
        vuln_id_A = resp.json()["id"]

        # Org B's audit log should NOT contain Org A's events
        resp = await client.get(f"{_REPORTS_URL}/audit-log", headers=_auth(tokenB))
        assert resp.status_code == 200
        items = resp.json()["items"]
        resource_ids = [e["resource_id"] for e in items]
        assert vuln_id_A not in resource_ids

    async def test_audit_log_requires_auth(self, client: AsyncClient):
        resp = await client.get(f"{_REPORTS_URL}/audit-log")
        assert resp.status_code == 403
