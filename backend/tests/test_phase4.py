"""
Phase 4 tests — Enrichment pipeline (CISA KEV, FIRST EPSS, NVD) with Redis caching.

Test strategy:
  - Client unit tests: mock Redis + mock httpx (via injected http_client param).
  - Service unit tests: mock the three client functions, use real db_session.
  - Endpoint integration tests: mock client functions, verify HTTP response schema.

All external HTTP calls are intercepted — no live network requests are made.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.clients.epss import (
    CACHE_KEY_PREFIX as EPSS_PREFIX,
    CACHE_TTL as EPSS_TTL,
    fetch_epss_scores,
)
from app.core.clients.kev import (
    CACHE_KEY as KEV_CACHE_KEY,
    CACHE_TTL as KEV_TTL,
    fetch_kev_catalog,
)
from app.core.clients.nvd import (
    CACHE_KEY_PREFIX as NVD_PREFIX,
    CACHE_TTL as NVD_TTL,
    fetch_nvd_data,
)
from app.models.vulnerability import Vulnerability
from app.services.enrichment import EnrichmentResult, enrich_vulnerabilities

# ── Shared constants ──────────────────────────────────────────────────────────

_BASE = "/api/v1"
_AUTH_URL = f"{_BASE}/auth"
_VULN_URL = f"{_BASE}/vulnerabilities"


# ── Shared fixtures / helpers ─────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def mock_hibp_not_pwned():
    with patch("app.api.routes.auth.is_password_pwned", return_value=False):
        yield


def _make_redis(cached_value=None):
    """Return an AsyncMock Redis client. ``cached_value`` is returned by .get()."""
    redis = AsyncMock()
    redis.get = AsyncMock(return_value=cached_value)
    redis.setex = AsyncMock()
    return redis


def _make_http_response(json_body: dict, status_code: int = 200) -> httpx.Response:
    """Build a real httpx.Response with a JSON body (no network required)."""
    return httpx.Response(
        status_code=status_code,
        headers={"content-type": "application/json"},
        content=json.dumps(json_body).encode(),
        # httpx requires a request object to call raise_for_status()
        request=httpx.Request("GET", "http://test"),
    )


def _make_mock_http_client(response: httpx.Response) -> AsyncMock:
    """AsyncMock httpx client whose .get() returns ``response``."""
    client = AsyncMock(spec=httpx.AsyncClient)
    client.get = AsyncMock(return_value=response)
    client.aclose = AsyncMock()
    return client


async def _register(client: AsyncClient, email: str) -> dict:
    resp = await client.post(
        f"{_AUTH_URL}/register",
        json={
            "email": email,
            "password": "S3cur3P@ssw0rd!",
            "org_name": f"Org-{email}",
        },
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _vuln_payload(cve_id: str = "CVE-2024-10001") -> dict:
    return {
        "cve_id": cve_id,
        "title": "Test Vulnerability",
        "description": "A test vulnerability for enrichment.",
        "severity": "high",
        "source": "manual",
    }


# ── KEV client tests ──────────────────────────────────────────────────────────

class TestKevClient:
    """Unit tests for app.core.clients.kev."""

    @pytest.mark.asyncio
    async def test_cache_miss_fetches_and_caches(self):
        """On a cache miss, fetch from CISA and store result in Redis."""
        redis = _make_redis(cached_value=None)
        kev_body = {
            "vulnerabilities": [
                {"cveID": "CVE-2021-26855", "dateAdded": "2021-11-03"},
                {"cveID": "CVE-2021-34473", "dateAdded": "2021-11-03"},
            ]
        }
        http = _make_mock_http_client(_make_http_response(kev_body))

        result = await fetch_kev_catalog(redis, http_client=http)

        assert result == {
            "CVE-2021-26855": "2021-11-03",
            "CVE-2021-34473": "2021-11-03",
        }
        http.get.assert_awaited_once()
        redis.setex.assert_awaited_once()
        args = redis.setex.call_args
        assert args[0][0] == KEV_CACHE_KEY
        assert args[0][1] == KEV_TTL
        stored = json.loads(args[0][2])
        assert stored["CVE-2021-26855"] == "2021-11-03"

    @pytest.mark.asyncio
    async def test_cache_hit_skips_http(self):
        """On a cache hit, return cached data without making any HTTP call."""
        cached = json.dumps({"CVE-2021-26855": "2021-11-03"})
        redis = _make_redis(cached_value=cached)
        http = _make_mock_http_client(_make_http_response({}))

        result = await fetch_kev_catalog(redis, http_client=http)

        assert result == {"CVE-2021-26855": "2021-11-03"}
        http.get.assert_not_awaited()
        redis.setex.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_empty_vulnerabilities_list(self):
        """An empty catalog is stored and returned without error."""
        redis = _make_redis(cached_value=None)
        http = _make_mock_http_client(_make_http_response({"vulnerabilities": []}))

        result = await fetch_kev_catalog(redis, http_client=http)

        assert result == {}
        redis.setex.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_http_error_propagates(self):
        """HTTP errors are not swallowed — they propagate to the caller."""
        redis = _make_redis(cached_value=None)
        client = AsyncMock(spec=httpx.AsyncClient)
        client.get = AsyncMock(
            side_effect=httpx.HTTPStatusError(
                "503", request=MagicMock(), response=MagicMock(status_code=503)
            )
        )
        client.aclose = AsyncMock()

        with pytest.raises(httpx.HTTPStatusError):
            await fetch_kev_catalog(redis, http_client=client)

        redis.setex.assert_not_awaited()


# ── EPSS client tests ─────────────────────────────────────────────────────────

class TestEpssClient:
    """Unit tests for app.core.clients.epss."""

    @pytest.mark.asyncio
    async def test_cache_miss_fetches_and_caches(self):
        """Uncached CVE IDs are fetched from FIRST and stored per-CVE."""
        redis = _make_redis(cached_value=None)
        epss_body = {
            "status": "OK",
            "data": [
                {"cve": "CVE-2021-26855", "epss": "0.97528"},
                {"cve": "CVE-2021-34473", "epss": "0.12345"},
            ],
        }
        http = _make_mock_http_client(_make_http_response(epss_body))

        result = await fetch_epss_scores(
            redis, ["CVE-2021-26855", "CVE-2021-34473"], http_client=http
        )

        assert result["CVE-2021-26855"] == pytest.approx(0.97528)
        assert result["CVE-2021-34473"] == pytest.approx(0.12345)
        assert redis.setex.await_count == 2

    @pytest.mark.asyncio
    async def test_cache_hit_skips_http(self):
        """Fully-cached CVE IDs return without any HTTP call."""
        # Both CVEs are cached
        redis = AsyncMock()
        redis.get = AsyncMock(return_value="0.97528")
        redis.setex = AsyncMock()
        http = _make_mock_http_client(_make_http_response({"data": []}))

        result = await fetch_epss_scores(
            redis, ["CVE-2021-26855", "CVE-2021-34473"], http_client=http
        )

        assert result["CVE-2021-26855"] == pytest.approx(0.97528)
        assert result["CVE-2021-34473"] == pytest.approx(0.97528)
        http.get.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_empty_cve_list_returns_empty(self):
        redis = _make_redis()
        result = await fetch_epss_scores(redis, [])
        assert result == {}

    @pytest.mark.asyncio
    async def test_http_error_skips_batch_non_fatal(self):
        """HTTP errors during a batch are logged and skipped (non-fatal)."""
        redis = _make_redis(cached_value=None)
        client = AsyncMock(spec=httpx.AsyncClient)
        client.get = AsyncMock(side_effect=httpx.ConnectError("refused"))
        client.aclose = AsyncMock()

        # Should not raise; just returns empty dict
        result = await fetch_epss_scores(
            redis, ["CVE-2021-26855"], http_client=client
        )
        assert result == {}

    @pytest.mark.asyncio
    async def test_deduplicates_cve_ids(self):
        """Duplicate CVE IDs in input are de-duped before fetching."""
        redis = _make_redis(cached_value=None)
        epss_body = {
            "data": [{"cve": "CVE-2021-26855", "epss": "0.5"}]
        }
        http = _make_mock_http_client(_make_http_response(epss_body))

        result = await fetch_epss_scores(
            redis,
            ["CVE-2021-26855", "CVE-2021-26855", "CVE-2021-26855"],
            http_client=http,
        )

        # Only one HTTP call; result has the CVE once
        http.get.assert_awaited_once()
        assert len(result) == 1
        assert result["CVE-2021-26855"] == pytest.approx(0.5)


# ── NVD client tests ──────────────────────────────────────────────────────────

class TestNvdClient:
    """Unit tests for app.core.clients.nvd."""

    def _nvd_body(self, cve_id: str, base_score: float, published: str) -> dict:
        return {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": cve_id,
                        "published": published,
                        "metrics": {
                            "cvssMetricV31": [
                                {"cvssData": {"baseScore": base_score}}
                            ]
                        },
                    }
                }
            ]
        }

    @pytest.mark.asyncio
    async def test_cache_miss_fetches_and_caches(self):
        redis = _make_redis(cached_value=None)
        body = self._nvd_body("CVE-2021-26855", 9.8, "2021-03-03T00:15:00.000")
        http = _make_mock_http_client(_make_http_response(body))

        result = await fetch_nvd_data(redis, "CVE-2021-26855", http_client=http)

        assert result is not None
        assert result["cvss_score"] == pytest.approx(9.8)
        assert "2021-03-03" in result["published_at"]
        redis.setex.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_cache_hit_skips_http(self):
        cached_data = json.dumps({"cvss_score": 9.8, "published_at": "2021-03-03T00:15:00"})
        redis = _make_redis(cached_value=cached_data)
        http = _make_mock_http_client(_make_http_response({}))

        result = await fetch_nvd_data(redis, "CVE-2021-26855", http_client=http)

        assert result["cvss_score"] == pytest.approx(9.8)
        http.get.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_not_found_returns_none(self):
        redis = _make_redis(cached_value=None)
        http = _make_mock_http_client(_make_http_response({"vulnerabilities": []}))

        result = await fetch_nvd_data(redis, "CVE-2024-99999", http_client=http)

        assert result is None
        redis.setex.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_http_error_returns_none(self):
        redis = _make_redis(cached_value=None)
        client = AsyncMock(spec=httpx.AsyncClient)
        client.get = AsyncMock(
            side_effect=httpx.HTTPStatusError(
                "404", request=MagicMock(), response=MagicMock(status_code=404)
            )
        )
        client.aclose = AsyncMock()

        result = await fetch_nvd_data(redis, "CVE-2024-99999", http_client=client)

        assert result is None
        redis.setex.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_cvss_v30_fallback(self):
        """Uses CVSSv3.0 when v3.1 is absent."""
        redis = _make_redis(cached_value=None)
        body = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2020-12345",
                        "published": "2020-05-01T00:00:00.000",
                        "metrics": {
                            "cvssMetricV30": [{"cvssData": {"baseScore": 7.5}}]
                        },
                    }
                }
            ]
        }
        http = _make_mock_http_client(_make_http_response(body))

        result = await fetch_nvd_data(redis, "CVE-2020-12345", http_client=http)

        assert result["cvss_score"] == pytest.approx(7.5)

    @pytest.mark.asyncio
    async def test_cvss_v2_fallback(self):
        """Uses CVSSv2 when v3.x is absent."""
        redis = _make_redis(cached_value=None)
        body = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2010-12345",
                        "published": "2010-01-01T00:00:00.000",
                        "metrics": {
                            "cvssMetricV2": [{"cvssData": {"baseScore": 5.0}}]
                        },
                    }
                }
            ]
        }
        http = _make_mock_http_client(_make_http_response(body))

        result = await fetch_nvd_data(redis, "CVE-2010-12345", http_client=http)

        assert result["cvss_score"] == pytest.approx(5.0)

    @pytest.mark.asyncio
    async def test_api_key_passed_in_header(self):
        """NVD API key is included in the request headers."""
        redis = _make_redis(cached_value=None)
        body = self._nvd_body("CVE-2021-26855", 9.8, "2021-03-03T00:15:00.000")
        http = _make_mock_http_client(_make_http_response(body))

        await fetch_nvd_data(
            redis, "CVE-2021-26855", api_key="test-api-key", http_client=http
        )

        call_kwargs = http.get.call_args[1]
        assert call_kwargs.get("headers", {}).get("apiKey") == "test-api-key"


# ── Enrichment service tests ──────────────────────────────────────────────────

class TestEnrichmentService:
    """
    Integration tests for app.services.enrichment.enrich_vulnerabilities.

    Uses the HTTP client to create vulns (to avoid manually wiring encryption
    context), then calls the service directly with a mock Redis and patched
    external client functions.
    """

    @pytest.mark.asyncio
    async def test_no_vulns_returns_zero_result(self, client, db_session, mock_redis):
        """Enriching an org with no vulnerabilities returns zeros."""
        reg = await _register(client, "enrich_empty@example.com")
        org_id = uuid.UUID(reg["user"]["org_id"])

        with (
            patch("app.services.enrichment.fetch_kev_catalog", return_value={}),
            patch("app.services.enrichment.fetch_epss_scores", return_value={}),
            patch("app.services.enrichment.fetch_nvd_data", return_value=None),
        ):
            result = await enrich_vulnerabilities(db_session, mock_redis, org_id)

        assert result.enriched == 0
        assert result.kev_updated == 0
        assert result.epss_updated == 0
        assert result.cvss_updated == 0
        assert result.published_at_updated == 0
        assert result.errors == []

    @pytest.mark.asyncio
    async def test_kev_enrichment_updates_record(self, client, db_session, mock_redis):
        """A KEV-listed CVE sets kev_listed=True and kev_added_date."""
        reg = await _register(client, "enrich_kev@example.com")
        token = reg["access_token"]
        org_id = uuid.UUID(reg["user"]["org_id"])

        create = await client.post(
            f"{_VULN_URL}/",
            json=_vuln_payload("CVE-2021-26855"),
            headers=_auth(token),
        )
        assert create.status_code == 201
        vuln_id = uuid.UUID(create.json()["id"])

        kev_catalog = {"CVE-2021-26855": "2021-11-03"}
        with (
            patch("app.services.enrichment.fetch_kev_catalog", return_value=kev_catalog),
            patch("app.services.enrichment.fetch_epss_scores", return_value={}),
            patch("app.services.enrichment.fetch_nvd_data", return_value=None),
        ):
            result = await enrich_vulnerabilities(db_session, mock_redis, org_id)
            await db_session.commit()

        assert result.enriched == 1
        assert result.kev_updated == 1
        assert result.epss_updated == 0
        assert result.errors == []

        # Verify DB state — use plaintext column select (no encryption context needed)
        row = await db_session.execute(
            select(Vulnerability.kev_listed, Vulnerability.kev_added_date).where(
                Vulnerability.id == vuln_id
            )
        )
        db_row = row.one()
        assert db_row.kev_listed is True
        assert db_row.kev_added_date is not None

    @pytest.mark.asyncio
    async def test_epss_enrichment_updates_score(self, client, db_session, mock_redis):
        """EPSS data updates epss_score on the vulnerability."""
        reg = await _register(client, "enrich_epss@example.com")
        token = reg["access_token"]
        org_id = uuid.UUID(reg["user"]["org_id"])

        create = await client.post(
            f"{_VULN_URL}/",
            json=_vuln_payload("CVE-2021-34473"),
            headers=_auth(token),
        )
        assert create.status_code == 201
        vuln_id = uuid.UUID(create.json()["id"])

        with (
            patch("app.services.enrichment.fetch_kev_catalog", return_value={}),
            patch(
                "app.services.enrichment.fetch_epss_scores",
                return_value={"CVE-2021-34473": 0.9753},
            ),
            patch("app.services.enrichment.fetch_nvd_data", return_value=None),
        ):
            result = await enrich_vulnerabilities(db_session, mock_redis, org_id)
            await db_session.commit()

        assert result.epss_updated == 1

        row = await db_session.execute(
            select(Vulnerability.epss_score).where(Vulnerability.id == vuln_id)
        )
        assert row.scalar_one() == pytest.approx(0.9753)

    @pytest.mark.asyncio
    async def test_nvd_enrichment_updates_cvss_and_published(
        self, client, db_session, mock_redis
    ):
        """NVD data updates cvss_score and published_at."""
        reg = await _register(client, "enrich_nvd@example.com")
        token = reg["access_token"]
        org_id = uuid.UUID(reg["user"]["org_id"])

        create = await client.post(
            f"{_VULN_URL}/",
            json=_vuln_payload("CVE-2021-44228"),
            headers=_auth(token),
        )
        assert create.status_code == 201
        vuln_id = uuid.UUID(create.json()["id"])

        nvd_data = {"cvss_score": 10.0, "published_at": "2021-12-10T00:00:00+00:00"}
        with (
            patch("app.services.enrichment.fetch_kev_catalog", return_value={}),
            patch("app.services.enrichment.fetch_epss_scores", return_value={}),
            patch(
                "app.services.enrichment.fetch_nvd_data",
                return_value=nvd_data,
            ),
        ):
            result = await enrich_vulnerabilities(db_session, mock_redis, org_id)
            await db_session.commit()

        assert result.cvss_updated == 1
        assert result.published_at_updated == 1

        row = await db_session.execute(
            select(Vulnerability.cvss_score, Vulnerability.published_at).where(
                Vulnerability.id == vuln_id
            )
        )
        db_row = row.one()
        assert db_row.cvss_score == pytest.approx(10.0)
        assert db_row.published_at is not None

    @pytest.mark.asyncio
    async def test_all_three_sources_together(self, client, db_session, mock_redis):
        """All three enrichment sources can update a single vulnerability."""
        reg = await _register(client, "enrich_all3@example.com")
        token = reg["access_token"]
        org_id = uuid.UUID(reg["user"]["org_id"])

        create = await client.post(
            f"{_VULN_URL}/",
            json=_vuln_payload("CVE-2021-26855"),
            headers=_auth(token),
        )
        assert create.status_code == 201

        with (
            patch(
                "app.services.enrichment.fetch_kev_catalog",
                return_value={"CVE-2021-26855": "2021-11-03"},
            ),
            patch(
                "app.services.enrichment.fetch_epss_scores",
                return_value={"CVE-2021-26855": 0.97528},
            ),
            patch(
                "app.services.enrichment.fetch_nvd_data",
                return_value={"cvss_score": 9.8, "published_at": "2021-03-03T00:15:00+00:00"},
            ),
        ):
            result = await enrich_vulnerabilities(db_session, mock_redis, org_id)

        assert result.enriched == 1
        assert result.kev_updated == 1
        assert result.epss_updated == 1
        assert result.cvss_updated == 1
        assert result.published_at_updated == 1

    @pytest.mark.asyncio
    async def test_specific_vuln_ids_filter(self, client, db_session, mock_redis):
        """Passing vuln_ids only enriches the specified vulns."""
        reg = await _register(client, "enrich_filter@example.com")
        token = reg["access_token"]
        org_id = uuid.UUID(reg["user"]["org_id"])

        c1 = await client.post(
            f"{_VULN_URL}/", json=_vuln_payload("CVE-2024-20001"), headers=_auth(token)
        )
        c2 = await client.post(
            f"{_VULN_URL}/", json=_vuln_payload("CVE-2024-20002"), headers=_auth(token)
        )
        assert c1.status_code == 201
        assert c2.status_code == 201
        vuln_id_1 = uuid.UUID(c1.json()["id"])

        kev = {"CVE-2024-20001": "2024-01-01", "CVE-2024-20002": "2024-01-02"}
        with (
            patch("app.services.enrichment.fetch_kev_catalog", return_value=kev),
            patch("app.services.enrichment.fetch_epss_scores", return_value={}),
            patch("app.services.enrichment.fetch_nvd_data", return_value=None),
        ):
            result = await enrich_vulnerabilities(
                db_session, mock_redis, org_id, vuln_ids=[vuln_id_1]
            )

        assert result.enriched == 1  # only 1 of 2 vulns enriched
        assert result.kev_updated == 1

    @pytest.mark.asyncio
    async def test_kev_fetch_failure_is_non_fatal(self, client, db_session, mock_redis):
        """A KEV fetch failure is recorded in errors but does not abort EPSS/NVD."""
        reg = await _register(client, "enrich_kevfail@example.com")
        token = reg["access_token"]
        org_id = uuid.UUID(reg["user"]["org_id"])

        await client.post(
            f"{_VULN_URL}/",
            json=_vuln_payload("CVE-2021-26855"),
            headers=_auth(token),
        )

        with (
            patch(
                "app.services.enrichment.fetch_kev_catalog",
                side_effect=RuntimeError("CISA unreachable"),
            ),
            patch(
                "app.services.enrichment.fetch_epss_scores",
                return_value={"CVE-2021-26855": 0.97528},
            ),
            patch("app.services.enrichment.fetch_nvd_data", return_value=None),
        ):
            result = await enrich_vulnerabilities(db_session, mock_redis, org_id)

        assert result.enriched == 1
        assert result.kev_updated == 0
        assert result.epss_updated == 1
        assert len(result.errors) == 1
        assert "KEV fetch failed" in result.errors[0]


    @pytest.mark.asyncio
    async def test_kev_flag_cleared_on_re_enrichment(self, client, db_session, mock_redis):
        """
        A vulnerability previously marked kev_listed=True must be reset to
        False when a subsequent enrichment runs against a catalog that does
        NOT contain that CVE.

        Regression test for the stale-flag bug where `enrichment.py` only
        ever wrote kev_listed=True, so once flagged a finding stayed flagged
        regardless of the catalog content.
        """
        reg = await _register(client, "enrich_kev_clear@example.com")
        token = reg["access_token"]
        org_id = uuid.UUID(reg["user"]["org_id"])

        create = await client.post(
            f"{_VULN_URL}/",
            json=_vuln_payload("CVE-2021-26855"),
            headers=_auth(token),
        )
        assert create.status_code == 201
        vuln_id = uuid.UUID(create.json()["id"])

        # Round 1: enrich with catalog that CONTAINS the CVE → kev_listed=True.
        kev_catalog_with = {"CVE-2021-26855": "2021-11-03"}
        with (
            patch("app.services.enrichment.fetch_kev_catalog", return_value=kev_catalog_with),
            patch("app.services.enrichment.fetch_epss_scores", return_value={}),
            patch("app.services.enrichment.fetch_nvd_data", return_value=None),
        ):
            result1 = await enrich_vulnerabilities(db_session, mock_redis, org_id)
            await db_session.commit()

        assert result1.kev_updated == 1
        row1 = (await db_session.execute(
            select(Vulnerability.kev_listed, Vulnerability.kev_added_date).where(
                Vulnerability.id == vuln_id
            )
        )).one()
        assert row1.kev_listed is True
        assert row1.kev_added_date is not None

        # Round 2: enrich with EMPTY catalog → kev_listed must become False.
        with (
            patch("app.services.enrichment.fetch_kev_catalog", return_value={}),
            patch("app.services.enrichment.fetch_epss_scores", return_value={}),
            patch("app.services.enrichment.fetch_nvd_data", return_value=None),
        ):
            result2 = await enrich_vulnerabilities(db_session, mock_redis, org_id)
            await db_session.commit()

        assert result2.kev_updated == 0  # counter only increments on True transitions
        row2 = (await db_session.execute(
            select(Vulnerability.kev_listed, Vulnerability.kev_added_date).where(
                Vulnerability.id == vuln_id
            )
        )).one()
        assert row2.kev_listed is False
        assert row2.kev_added_date is None


# ── Enrichment endpoint tests ─────────────────────────────────────────────────

class TestEnrichmentEndpoints:
    """HTTP integration tests for POST /vulnerabilities/enrich and /{id}/enrich."""

    @pytest.mark.asyncio
    async def test_enrich_all_returns_200_with_schema(self, client):
        """POST /enrich returns 200 with the EnrichmentResultSchema."""
        reg = await _register(client, "ep_enrich_all@example.com")
        token = reg["access_token"]

        with (
            patch("app.services.enrichment.fetch_kev_catalog", return_value={}),
            patch("app.services.enrichment.fetch_epss_scores", return_value={}),
            patch("app.services.enrichment.fetch_nvd_data", return_value=None),
        ):
            resp = await client.post(
                f"{_VULN_URL}/enrich", headers=_auth(token)
            )

        assert resp.status_code == 200
        body = resp.json()
        for key in ("enriched", "kev_updated", "epss_updated", "cvss_updated", "published_at_updated", "errors"):
            assert key in body, f"missing key: {key}"

    @pytest.mark.asyncio
    async def test_enrich_all_counts_are_correct(self, client):
        """POST /enrich updates counts reflect what the service returns."""
        reg = await _register(client, "ep_enrich_counts@example.com")
        token = reg["access_token"]

        # Create two vulns
        for cve in ("CVE-2024-30001", "CVE-2024-30002"):
            r = await client.post(
                f"{_VULN_URL}/", json=_vuln_payload(cve), headers=_auth(token)
            )
            assert r.status_code == 201

        kev = {"CVE-2024-30001": "2024-01-15"}
        epss = {"CVE-2024-30001": 0.5, "CVE-2024-30002": 0.3}
        nvd = {"cvss_score": 7.5, "published_at": "2024-01-01T00:00:00+00:00"}

        with (
            patch("app.services.enrichment.fetch_kev_catalog", return_value=kev),
            patch("app.services.enrichment.fetch_epss_scores", return_value=epss),
            patch("app.services.enrichment.fetch_nvd_data", return_value=nvd),
        ):
            resp = await client.post(
                f"{_VULN_URL}/enrich", headers=_auth(token)
            )

        assert resp.status_code == 200
        body = resp.json()
        assert body["enriched"] == 2
        assert body["kev_updated"] == 1
        assert body["epss_updated"] == 2
        assert body["cvss_updated"] == 2
        assert body["published_at_updated"] == 2

    @pytest.mark.asyncio
    async def test_enrich_all_requires_auth(self, client):
        """POST /enrich returns 403 without a Bearer token."""
        resp = await client.post(f"{_VULN_URL}/enrich")
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_enrich_single_returns_200(self, client):
        """POST /{id}/enrich returns 200 for an existing vulnerability."""
        reg = await _register(client, "ep_single_ok@example.com")
        token = reg["access_token"]

        create = await client.post(
            f"{_VULN_URL}/",
            json=_vuln_payload("CVE-2024-40001"),
            headers=_auth(token),
        )
        assert create.status_code == 201
        vuln_id = create.json()["id"]

        with (
            patch("app.services.enrichment.fetch_kev_catalog", return_value={}),
            patch("app.services.enrichment.fetch_epss_scores", return_value={}),
            patch("app.services.enrichment.fetch_nvd_data", return_value=None),
        ):
            resp = await client.post(
                f"{_VULN_URL}/{vuln_id}/enrich", headers=_auth(token)
            )

        assert resp.status_code == 200
        body = resp.json()
        assert body["enriched"] == 1

    @pytest.mark.asyncio
    async def test_enrich_single_returns_404_for_unknown(self, client):
        """POST /{id}/enrich returns 404 when the vuln does not exist."""
        reg = await _register(client, "ep_single_404@example.com")
        token = reg["access_token"]
        fake_id = str(uuid.uuid4())

        with (
            patch("app.services.enrichment.fetch_kev_catalog", return_value={}),
            patch("app.services.enrichment.fetch_epss_scores", return_value={}),
            patch("app.services.enrichment.fetch_nvd_data", return_value=None),
        ):
            resp = await client.post(
                f"{_VULN_URL}/{fake_id}/enrich", headers=_auth(token)
            )

        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_enrich_single_requires_auth(self, client):
        """POST /{id}/enrich returns 403 without a Bearer token."""
        fake_id = str(uuid.uuid4())
        resp = await client.post(f"{_VULN_URL}/{fake_id}/enrich")
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_enrich_single_wrong_org_returns_404(self, client):
        """A vulnerability from another org is not visible — returns 404."""
        reg_a = await _register(client, "ep_orga_enrich@example.com")
        reg_b = await _register(client, "ep_orgb_enrich@example.com")
        token_a = reg_a["access_token"]
        token_b = reg_b["access_token"]

        # Create vuln as org A
        create = await client.post(
            f"{_VULN_URL}/",
            json=_vuln_payload("CVE-2024-50001"),
            headers=_auth(token_a),
        )
        assert create.status_code == 201
        vuln_id = create.json()["id"]

        # Try to enrich as org B
        with (
            patch("app.services.enrichment.fetch_kev_catalog", return_value={}),
            patch("app.services.enrichment.fetch_epss_scores", return_value={}),
            patch("app.services.enrichment.fetch_nvd_data", return_value=None),
        ):
            resp = await client.post(
                f"{_VULN_URL}/{vuln_id}/enrich", headers=_auth(token_b)
            )

        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_enrich_all_errors_in_response(self, client):
        """Non-fatal errors from client fetches appear in the errors list."""
        reg = await _register(client, "ep_errors@example.com")
        token = reg["access_token"]

        await client.post(
            f"{_VULN_URL}/", json=_vuln_payload("CVE-2024-60001"), headers=_auth(token)
        )

        with (
            patch(
                "app.services.enrichment.fetch_kev_catalog",
                side_effect=RuntimeError("timeout"),
            ),
            patch("app.services.enrichment.fetch_epss_scores", return_value={}),
            patch("app.services.enrichment.fetch_nvd_data", return_value=None),
        ):
            resp = await client.post(f"{_VULN_URL}/enrich", headers=_auth(token))

        assert resp.status_code == 200
        body = resp.json()
        assert len(body["errors"]) >= 1
        assert any("KEV" in e for e in body["errors"])
