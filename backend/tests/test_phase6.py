"""
Phase 6 tests — Context scoring agent.

Test strategy:
  - Unit tests for rule_based_priority: MagicMock org/vuln objects (no DB).
  - Unit tests for parse_scoring_json: pure function, no mocking needed.
  - Unit tests for score_single: MagicMock org/vuln + mock LLM.
  - Endpoint integration tests: full HTTP round-trip, mock LLM via dep override.

score_vulnerabilities is tested exclusively through endpoint tests because it
loads full Vulnerability ORM objects (triggering EncryptedString decryption),
which requires an active encryption_context() that the route sets up via
get_org_encryption.
"""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import AsyncClient

from app.api.deps import get_llm_client
from app.core.llm.base import LLMResponse
from app.main import app
from app.services.scoring import (
    parse_scoring_json,
    rule_based_priority,
    score_single,
)

# ── Constants / helpers ───────────────────────────────────────────────────────

_BASE = "/api/v1"
_AUTH_URL = f"{_BASE}/auth"
_VULN_URL = f"{_BASE}/vulnerabilities"


@pytest.fixture(autouse=True)
def mock_hibp_not_pwned():
    with patch("app.api.routes.auth.is_password_pwned", return_value=False):
        yield


async def _register(client: AsyncClient, email: str) -> dict:
    resp = await client.post(
        f"{_AUTH_URL}/register",
        json={"email": email, "password": "S3cur3P@ssw0rd!", "org_name": f"Org-{email}"},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _vuln_payload(cve_id: str = "CVE-2024-10001", **kwargs) -> dict:
    return {
        "cve_id": cve_id,
        "title": "Test Vuln",
        "description": "A test vulnerability for scoring.",
        "severity": "high",
        "source": "manual",
        **kwargs,
    }


def _make_org(**kwargs) -> MagicMock:
    """Build a mock Organization with default scoring thresholds."""
    org = MagicMock()
    org.epss_immediate_threshold = kwargs.get("epss_immediate_threshold", 0.5)
    org.epss_this_week_threshold = kwargs.get("epss_this_week_threshold", 0.3)
    org.cvss_immediate_threshold = kwargs.get("cvss_immediate_threshold", 9.0)
    org.cvss_this_week_threshold = kwargs.get("cvss_this_week_threshold", 7.0)
    org.kev_sla_days = kwargs.get("kev_sla_days", 7)
    org.non_kev_critical_sla_days = kwargs.get("non_kev_critical_sla_days", 30)
    return org


def _make_vuln(**kwargs) -> MagicMock:
    """Build a mock Vulnerability for unit tests."""
    vuln = MagicMock()
    vuln.cve_id = kwargs.get("cve_id", "CVE-2024-10001")
    vuln.severity = kwargs.get("severity", "high")
    vuln.status = kwargs.get("status", "open")
    vuln.kev_listed = kwargs.get("kev_listed", False)
    vuln.epss_score = kwargs.get("epss_score", None)
    vuln.cvss_score = kwargs.get("cvss_score", None)
    vuln.enc_title = kwargs.get("enc_title", "Test Title")
    vuln.enc_description = kwargs.get("enc_description", "Test description.")
    vuln.enc_affected_component = kwargs.get("enc_affected_component", None)
    return vuln


def _mock_llm(priority: str = "this_week", rationale: str = "High severity.") -> AsyncMock:
    llm = AsyncMock()
    llm.complete = AsyncMock(
        return_value=LLMResponse(
            content=f'{{"priority": "{priority}", "rationale": "{rationale}"}}',
            model="claude-sonnet-4-6",
            provider="anthropic",
            input_tokens=50,
            output_tokens=20,
        )
    )
    return llm


def _llm_dep_override(priority: str = "this_week", rationale: str = "High severity."):
    """FastAPI dependency override that returns a pre-configured mock LLM."""
    mock = _mock_llm(priority, rationale)
    async def _dep():
        return mock
    return _dep


# ── Rule-based priority unit tests ────────────────────────────────────────────

class TestRuleBasedPriority:
    def test_kev_listed_is_immediate(self):
        org = _make_org()
        vuln = _make_vuln(kev_listed=True)
        assert rule_based_priority(vuln, org) == "immediate"

    def test_high_epss_is_immediate(self):
        org = _make_org(epss_immediate_threshold=0.5)
        vuln = _make_vuln(epss_score=0.75)
        assert rule_based_priority(vuln, org) == "immediate"

    def test_high_cvss_is_immediate(self):
        org = _make_org(cvss_immediate_threshold=9.0)
        vuln = _make_vuln(cvss_score=9.5)
        assert rule_based_priority(vuln, org) == "immediate"

    def test_medium_epss_is_this_week(self):
        org = _make_org(epss_immediate_threshold=0.5, epss_this_week_threshold=0.3)
        vuln = _make_vuln(epss_score=0.4, severity="medium")
        assert rule_based_priority(vuln, org) == "this_week"

    def test_critical_severity_is_this_week(self):
        org = _make_org()
        vuln = _make_vuln(severity="critical", epss_score=0.0, cvss_score=0.0)
        assert rule_based_priority(vuln, org) == "this_week"

    def test_high_severity_no_scores_is_this_month(self):
        org = _make_org()
        vuln = _make_vuln(severity="high", epss_score=0.0, cvss_score=0.0)
        assert rule_based_priority(vuln, org) == "this_month"

    def test_low_everything_is_monitor(self):
        org = _make_org()
        vuln = _make_vuln(severity="low", epss_score=0.01, cvss_score=2.0)
        assert rule_based_priority(vuln, org) == "monitor"

    def test_none_scores_treated_as_zero(self):
        org = _make_org()
        vuln = _make_vuln(severity="low", epss_score=None, cvss_score=None)
        assert rule_based_priority(vuln, org) == "monitor"

    def test_kev_overrides_everything(self):
        """KEV listed → immediate regardless of EPSS/CVSS values."""
        org = _make_org(epss_immediate_threshold=0.5)
        vuln = _make_vuln(kev_listed=True, epss_score=0.0, cvss_score=0.0, severity="low")
        assert rule_based_priority(vuln, org) == "immediate"

    def test_exact_threshold_boundary_epss(self):
        """Score exactly at threshold qualifies (>=)."""
        org = _make_org(epss_immediate_threshold=0.5)
        vuln = _make_vuln(epss_score=0.5, severity="low")
        assert rule_based_priority(vuln, org) == "immediate"


# ── JSON parsing unit tests ───────────────────────────────────────────────────

class TestParseScoringJson:
    def test_clean_json(self):
        text = '{"priority": "immediate", "rationale": "KEV listed."}'
        result = parse_scoring_json(text)
        assert result["priority"] == "immediate"
        assert result["rationale"] == "KEV listed."

    def test_json_with_surrounding_text(self):
        text = 'Analysis:\n{"priority": "this_week", "rationale": "High EPSS."}\nDone.'
        result = parse_scoring_json(text)
        assert result["priority"] == "this_week"

    def test_json_in_markdown_block(self):
        text = "```json\n{\"priority\": \"monitor\", \"rationale\": \"Low risk.\"}\n```"
        result = parse_scoring_json(text)
        assert result["priority"] == "monitor"

    def test_unparseable_raises_value_error(self):
        with pytest.raises(ValueError, match="Cannot parse"):
            parse_scoring_json("Sorry, I cannot score this vulnerability.")

    def test_whitespace_stripped(self):
        text = '   {"priority": "accept", "rationale": "No real risk."}   '
        result = parse_scoring_json(text)
        assert result["priority"] == "accept"

    def test_extra_fields_allowed(self):
        text = '{"priority": "this_month", "rationale": "ok", "confidence": 0.9}'
        result = parse_scoring_json(text)
        assert result["priority"] == "this_month"


# ── score_single unit tests ───────────────────────────────────────────────────

class TestScoreSingle:
    @pytest.mark.asyncio
    async def test_llm_priority_returned(self):
        org = _make_org()
        vuln = _make_vuln()
        llm = _mock_llm(priority="immediate", rationale="KEV listed.")

        output = await score_single(llm, org, vuln)

        assert output.priority == "immediate"
        assert "KEV" in output.rationale

    @pytest.mark.asyncio
    async def test_temperature_is_zero(self):
        """PRD non-negotiable: temperature=0.0 for all scoring calls."""
        org = _make_org()
        vuln = _make_vuln()
        llm = _mock_llm()

        await score_single(llm, org, vuln)

        call_kwargs = llm.complete.call_args[1]
        assert call_kwargs.get("temperature") == 0.0

    @pytest.mark.asyncio
    async def test_invalid_priority_falls_back_to_rule_based(self):
        org = _make_org()
        vuln = _make_vuln(kev_listed=True)  # rule-based → immediate
        llm = AsyncMock()
        llm.complete = AsyncMock(
            return_value=LLMResponse(
                content='{"priority": "not_valid", "rationale": "..."}',
                model="m", provider="p", input_tokens=0, output_tokens=0,
            )
        )

        output = await score_single(llm, org, vuln)
        assert output.priority == "immediate"  # falls back to rule-based

    @pytest.mark.asyncio
    async def test_unparseable_llm_response_falls_back(self):
        org = _make_org()
        vuln = _make_vuln(severity="high")  # rule-based → this_month
        llm = AsyncMock()
        llm.complete = AsyncMock(
            return_value=LLMResponse(
                content="I cannot determine the priority.",
                model="m", provider="p", input_tokens=0, output_tokens=0,
            )
        )

        output = await score_single(llm, org, vuln)
        assert output.priority == "this_month"
        assert "Rule-based" in output.rationale

    @pytest.mark.asyncio
    async def test_system_prompt_in_complete_call(self):
        """score_single must pass a system prompt to the LLM."""
        org = _make_org()
        vuln = _make_vuln()
        llm = _mock_llm()

        await score_single(llm, org, vuln)

        call_kwargs = llm.complete.call_args[1]
        assert call_kwargs.get("system") is not None
        assert len(call_kwargs["system"]) > 0


# ── Endpoint integration tests ────────────────────────────────────────────────

class TestScoringEndpoints:
    @pytest.mark.asyncio
    async def test_score_all_returns_200_with_counts(self, client):
        reg = await _register(client, "ep_score_all@example.com")
        token = reg["access_token"]

        await client.post(
            f"{_VULN_URL}/", json=_vuln_payload("CVE-2024-11001"), headers=_auth(token)
        )

        app.dependency_overrides[get_llm_client] = _llm_dep_override("this_week")
        try:
            resp = await client.post(f"{_VULN_URL}/score", headers=_auth(token))
        finally:
            app.dependency_overrides.pop(get_llm_client, None)

        assert resp.status_code == 200
        body = resp.json()
        assert body["scored"] == 1
        assert body["errors"] == []

    @pytest.mark.asyncio
    async def test_score_all_requires_auth(self, client):
        resp = await client.post(f"{_VULN_URL}/score")
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_score_single_returns_full_vuln_response(self, client):
        reg = await _register(client, "ep_score_single@example.com")
        token = reg["access_token"]

        create = await client.post(
            f"{_VULN_URL}/", json=_vuln_payload("CVE-2024-12001"), headers=_auth(token)
        )
        assert create.status_code == 201
        vuln_id = create.json()["id"]

        app.dependency_overrides[get_llm_client] = _llm_dep_override(
            "immediate", "KEV listed and high EPSS."
        )
        try:
            resp = await client.post(
                f"{_VULN_URL}/{vuln_id}/score", headers=_auth(token)
            )
        finally:
            app.dependency_overrides.pop(get_llm_client, None)

        assert resp.status_code == 200
        body = resp.json()
        assert body["triage_priority"] == "immediate"
        assert body["score_rationale"] == "KEV listed and high EPSS."
        assert body["scored_at"] is not None
        assert body["id"] == vuln_id

    @pytest.mark.asyncio
    async def test_score_single_404_for_unknown_id(self, client):
        reg = await _register(client, "ep_score_404@example.com")
        token = reg["access_token"]

        app.dependency_overrides[get_llm_client] = _llm_dep_override()
        try:
            resp = await client.post(
                f"{_VULN_URL}/{uuid.uuid4()}/score", headers=_auth(token)
            )
        finally:
            app.dependency_overrides.pop(get_llm_client, None)

        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_score_all_empty_org_returns_zero(self, client):
        reg = await _register(client, "ep_score_empty@example.com")
        token = reg["access_token"]

        app.dependency_overrides[get_llm_client] = _llm_dep_override()
        try:
            resp = await client.post(f"{_VULN_URL}/score", headers=_auth(token))
        finally:
            app.dependency_overrides.pop(get_llm_client, None)

        assert resp.status_code == 200
        assert resp.json()["scored"] == 0

    @pytest.mark.asyncio
    async def test_score_updates_triage_priority_visible_in_get(self, client):
        """Scored vulnerability returns triage_priority in GET /{id}."""
        reg = await _register(client, "ep_score_get@example.com")
        token = reg["access_token"]

        create = await client.post(
            f"{_VULN_URL}/", json=_vuln_payload("CVE-2024-13001"), headers=_auth(token)
        )
        vuln_id = create.json()["id"]

        app.dependency_overrides[get_llm_client] = _llm_dep_override("monitor", "Low risk.")
        try:
            await client.post(f"{_VULN_URL}/{vuln_id}/score", headers=_auth(token))
        finally:
            app.dependency_overrides.pop(get_llm_client, None)

        get_resp = await client.get(f"{_VULN_URL}/{vuln_id}", headers=_auth(token))
        assert get_resp.status_code == 200
        body = get_resp.json()
        assert body["triage_priority"] == "monitor"
        assert body["score_rationale"] == "Low risk."

    @pytest.mark.asyncio
    async def test_score_visible_in_list(self, client):
        """List endpoint includes triage_priority after scoring."""
        reg = await _register(client, "ep_score_list@example.com")
        token = reg["access_token"]

        await client.post(
            f"{_VULN_URL}/", json=_vuln_payload("CVE-2024-14001"), headers=_auth(token)
        )

        app.dependency_overrides[get_llm_client] = _llm_dep_override("this_week")
        try:
            await client.post(f"{_VULN_URL}/score", headers=_auth(token))
        finally:
            app.dependency_overrides.pop(get_llm_client, None)

        list_resp = await client.get(f"{_VULN_URL}/", headers=_auth(token))
        assert list_resp.status_code == 200
        items = list_resp.json()["items"]
        assert any(i["triage_priority"] == "this_week" for i in items)

    @pytest.mark.asyncio
    async def test_score_single_wrong_org_returns_404(self, client):
        """Cannot score a vulnerability from another org."""
        reg_a = await _register(client, "ep_score_orga@example.com")
        reg_b = await _register(client, "ep_score_orgb@example.com")
        token_a = reg_a["access_token"]
        token_b = reg_b["access_token"]

        create = await client.post(
            f"{_VULN_URL}/", json=_vuln_payload("CVE-2024-15001"), headers=_auth(token_a)
        )
        vuln_id = create.json()["id"]

        app.dependency_overrides[get_llm_client] = _llm_dep_override()
        try:
            resp = await client.post(
                f"{_VULN_URL}/{vuln_id}/score", headers=_auth(token_b)
            )
        finally:
            app.dependency_overrides.pop(get_llm_client, None)

        assert resp.status_code == 404
