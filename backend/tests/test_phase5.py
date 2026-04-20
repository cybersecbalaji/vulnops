"""
Phase 5 tests — LLM abstraction layer + org settings API.

Test strategy:
  - LLM client unit tests: injected httpx mock (http_client param).
  - Factory unit tests: verify correct class is returned per provider.
  - Org settings endpoint tests: HTTP via AsyncClient, mock LLM where needed.

No live LLM or network calls are made.
"""

from __future__ import annotations

import json
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from httpx import AsyncClient

from app.core.llm.anthropic_client import AnthropicLLMClient
from app.core.llm.base import LLMMessage, LLMResponse
from app.core.llm.factory import create_llm_client
from app.core.llm.gemini_client import GeminiLLMClient
from app.core.llm.ollama_client import OllamaLLMClient
from app.core.llm.openai_client import OpenAILLMClient

# ── Shared constants / helpers ────────────────────────────────────────────────

_BASE = "/api/v1"
_AUTH_URL = f"{_BASE}/auth"
_ORG_URL = f"{_BASE}/org"


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


def _http_resp(body: dict, status_code: int = 200) -> httpx.Response:
    return httpx.Response(
        status_code=status_code,
        headers={"content-type": "application/json"},
        content=json.dumps(body).encode(),
        request=httpx.Request("POST", "http://test"),
    )


def _mock_http(response: httpx.Response) -> AsyncMock:
    client = AsyncMock(spec=httpx.AsyncClient)
    client.post = AsyncMock(return_value=response)
    client.get = AsyncMock(return_value=response)
    client.aclose = AsyncMock()
    return client


# ── Anthropic client ──────────────────────────────────────────────────────────

class TestAnthropicClient:
    @pytest.mark.asyncio
    async def test_sends_correct_request_format(self):
        body = {
            "content": [{"type": "text", "text": "Paris"}],
            "model": "claude-sonnet-4-6",
            "usage": {"input_tokens": 10, "output_tokens": 5},
        }
        http = _mock_http(_http_resp(body))
        client = AnthropicLLMClient(api_key="test-key", model="claude-sonnet-4-6", http_client=http)

        result = await client.complete(
            [LLMMessage(role="user", content="Capital of France?")],
            system="You are a geography expert.",
            max_tokens=50,
            temperature=0.0,
        )

        assert result.content == "Paris"
        assert result.provider == "anthropic"
        assert result.input_tokens == 10
        assert result.output_tokens == 5

        call_kwargs = http.post.call_args
        payload = call_kwargs[1]["json"]
        assert payload["model"] == "claude-sonnet-4-6"
        assert payload["temperature"] == 0.0
        assert payload["system"] == "You are a geography expert."
        headers = call_kwargs[1]["headers"]
        assert headers["x-api-key"] == "test-key"
        assert "anthropic-version" in headers

    @pytest.mark.asyncio
    async def test_no_system_omits_system_key(self):
        body = {
            "content": [{"type": "text", "text": "hi"}],
            "model": "claude-sonnet-4-6",
            "usage": {},
        }
        http = _mock_http(_http_resp(body))
        client = AnthropicLLMClient(api_key="k", http_client=http)
        await client.complete([LLMMessage(role="user", content="hi")])

        payload = http.post.call_args[1]["json"]
        assert "system" not in payload

    @pytest.mark.asyncio
    async def test_http_error_propagates(self):
        http = AsyncMock(spec=httpx.AsyncClient)
        http.post = AsyncMock(
            side_effect=httpx.HTTPStatusError(
                "401", request=MagicMock(), response=MagicMock(status_code=401)
            )
        )
        http.aclose = AsyncMock()
        client = AnthropicLLMClient(api_key="bad-key", http_client=http)

        with pytest.raises(httpx.HTTPStatusError):
            await client.complete([LLMMessage(role="user", content="hi")])


# ── OpenAI client ─────────────────────────────────────────────────────────────

class TestOpenAIClient:
    @pytest.mark.asyncio
    async def test_sends_correct_request_format(self):
        body = {
            "choices": [{"message": {"content": "Paris"}}],
            "model": "gpt-4o",
            "usage": {"prompt_tokens": 8, "completion_tokens": 3},
        }
        http = _mock_http(_http_resp(body))
        client = OpenAILLMClient(api_key="openai-key", model="gpt-4o", http_client=http)

        result = await client.complete(
            [LLMMessage(role="user", content="Capital of France?")],
            system="Be concise.",
            temperature=0.0,
        )

        assert result.content == "Paris"
        assert result.provider == "openai"
        assert result.input_tokens == 8
        assert result.output_tokens == 3

        payload = http.post.call_args[1]["json"]
        assert payload["messages"][0]["role"] == "system"
        assert payload["messages"][0]["content"] == "Be concise."
        assert payload["messages"][1]["role"] == "user"
        headers = http.post.call_args[1]["headers"]
        assert headers["Authorization"] == "Bearer openai-key"

    @pytest.mark.asyncio
    async def test_custom_base_url(self):
        body = {
            "choices": [{"message": {"content": "ok"}}],
            "model": "local-model",
            "usage": {},
        }
        http = _mock_http(_http_resp(body))
        client = OpenAILLMClient(
            api_key="k",
            model="local-model",
            base_url="http://localhost:8080/v1",
            http_client=http,
        )
        await client.complete([LLMMessage(role="user", content="hi")])

        call_url = http.post.call_args[0][0]
        assert "localhost:8080" in call_url


# ── Gemini client ─────────────────────────────────────────────────────────────

class TestGeminiClient:
    @pytest.mark.asyncio
    async def test_sends_correct_request_format(self):
        body = {
            "candidates": [
                {"content": {"parts": [{"text": "Paris"}]}}
            ],
            "usageMetadata": {"promptTokenCount": 5, "candidatesTokenCount": 2},
        }
        http = _mock_http(_http_resp(body))
        client = GeminiLLMClient(api_key="gemini-key", model="gemini-1.5-pro", http_client=http)

        result = await client.complete(
            [LLMMessage(role="user", content="Capital of France?")],
            system="Be concise.",
        )

        assert result.content == "Paris"
        assert result.provider == "gemini"
        assert result.input_tokens == 5
        assert result.output_tokens == 2

        payload = http.post.call_args[1]["json"]
        # System injected as user/model primer pair
        assert payload["contents"][0]["role"] == "user"
        assert payload["contents"][1]["role"] == "model"
        # API key in query params
        params = http.post.call_args[1]["params"]
        assert params["key"] == "gemini-key"

    @pytest.mark.asyncio
    async def test_assistant_role_mapped_to_model(self):
        body = {
            "candidates": [{"content": {"parts": [{"text": "ok"}]}}],
            "usageMetadata": {},
        }
        http = _mock_http(_http_resp(body))
        client = GeminiLLMClient(api_key="k", http_client=http)
        await client.complete([
            LLMMessage(role="user", content="hello"),
            LLMMessage(role="assistant", content="hi"),
            LLMMessage(role="user", content="bye"),
        ])

        payload = http.post.call_args[1]["json"]
        roles = [c["role"] for c in payload["contents"]]
        assert "assistant" not in roles
        assert "model" in roles


# ── Ollama client ─────────────────────────────────────────────────────────────

class TestOllamaClient:
    @pytest.mark.asyncio
    async def test_sends_correct_request_format(self):
        body = {
            "message": {"role": "assistant", "content": "Paris"},
            "model": "llama3",
            "prompt_eval_count": 7,
            "eval_count": 2,
        }
        http = _mock_http(_http_resp(body))
        client = OllamaLLMClient(model="llama3", base_url="http://localhost:11434", http_client=http)

        result = await client.complete(
            [LLMMessage(role="user", content="Capital of France?")],
            system="Be concise.",
        )

        assert result.content == "Paris"
        assert result.provider == "ollama"
        assert result.input_tokens == 7
        assert result.output_tokens == 2

        payload = http.post.call_args[1]["json"]
        assert payload["stream"] is False
        assert payload["messages"][0]["role"] == "system"
        assert payload["model"] == "llama3"


# ── Factory ───────────────────────────────────────────────────────────────────

class TestLLMFactory:
    def test_creates_anthropic_client(self):
        c = create_llm_client("anthropic", "claude-sonnet-4-6", api_key="k")
        assert isinstance(c, AnthropicLLMClient)
        assert c.provider == "anthropic"

    def test_creates_openai_client(self):
        c = create_llm_client("openai", "gpt-4o", api_key="k")
        assert isinstance(c, OpenAILLMClient)
        assert c.provider == "openai"

    def test_creates_gemini_client(self):
        c = create_llm_client("gemini", "gemini-1.5-pro", api_key="k")
        assert isinstance(c, GeminiLLMClient)
        assert c.provider == "gemini"

    def test_creates_ollama_client(self):
        c = create_llm_client("ollama", "llama3")
        assert isinstance(c, OllamaLLMClient)
        assert c.provider == "ollama"

    def test_unknown_provider_raises(self):
        with pytest.raises(ValueError, match="Unknown LLM provider"):
            create_llm_client("grok", "some-model")

    def test_default_model_used_when_none(self):
        c = create_llm_client("anthropic", None, api_key="k")
        assert isinstance(c, AnthropicLLMClient)

    def test_openai_custom_base_url(self):
        c = create_llm_client("openai", "gpt-4o", api_key="k", base_url="http://proxy/v1")
        assert isinstance(c, OpenAILLMClient)
        assert "proxy" in c._base_url

    def test_ollama_default_base_url(self):
        c = create_llm_client("ollama", "llama3")
        assert isinstance(c, OllamaLLMClient)
        assert "11434" in c._base_url


# ── Org settings endpoints ────────────────────────────────────────────────────

class TestOrgSettingsGet:
    @pytest.mark.asyncio
    async def test_get_returns_defaults(self, client):
        """Freshly registered org returns sensible defaults with no API keys set."""
        reg = await _register(client, "settings_get@example.com")
        token = reg["access_token"]

        resp = await client.get(f"{_ORG_URL}/settings", headers=_auth(token))

        assert resp.status_code == 200
        body = resp.json()
        assert body["ai_provider"] == "anthropic"
        assert body["has_ai_api_key"] is False
        assert body["has_jira_api_key"] is False
        # Thresholds should be present
        assert "epss_immediate_threshold" in body
        assert "cvss_immediate_threshold" in body
        assert body["kev_sla_days"] == 7

    @pytest.mark.asyncio
    async def test_get_requires_auth(self, client):
        resp = await client.get(f"{_ORG_URL}/settings")
        assert resp.status_code == 403


class TestOrgSettingsPatch:
    @pytest.mark.asyncio
    async def test_patch_updates_llm_provider(self, client):
        reg = await _register(client, "settings_patch_prov@example.com")
        token = reg["access_token"]

        resp = await client.patch(
            f"{_ORG_URL}/settings",
            json={"ai_provider": "openai", "ai_model": "gpt-4o"},
            headers=_auth(token),
        )

        assert resp.status_code == 200
        body = resp.json()
        assert body["ai_provider"] == "openai"
        assert body["ai_model"] == "gpt-4o"

    @pytest.mark.asyncio
    async def test_patch_with_api_key_sets_has_flag(self, client):
        """Sending an API key sets has_ai_api_key=True; the key itself is never returned."""
        reg = await _register(client, "settings_patch_key@example.com")
        token = reg["access_token"]

        resp = await client.patch(
            f"{_ORG_URL}/settings",
            json={"ai_api_key": "sk-secret-key"},
            headers=_auth(token),
        )

        assert resp.status_code == 200
        body = resp.json()
        assert body["has_ai_api_key"] is True
        assert "ai_api_key" not in body
        assert "encrypted" not in str(body)

    @pytest.mark.asyncio
    async def test_patch_clears_api_key_with_null(self, client):
        reg = await _register(client, "settings_clear_key@example.com")
        token = reg["access_token"]

        # Set key
        await client.patch(
            f"{_ORG_URL}/settings",
            json={"ai_api_key": "sk-secret"},
            headers=_auth(token),
        )
        # Clear key
        resp = await client.patch(
            f"{_ORG_URL}/settings",
            json={"ai_api_key": None},
            headers=_auth(token),
        )

        assert resp.status_code == 200
        assert resp.json()["has_ai_api_key"] is False

    @pytest.mark.asyncio
    async def test_patch_updates_thresholds(self, client):
        reg = await _register(client, "settings_thresh@example.com")
        token = reg["access_token"]

        resp = await client.patch(
            f"{_ORG_URL}/settings",
            json={
                "epss_immediate_threshold": 0.8,
                "cvss_immediate_threshold": 9.5,
                "kev_sla_days": 3,
            },
            headers=_auth(token),
        )

        assert resp.status_code == 200
        body = resp.json()
        assert body["epss_immediate_threshold"] == pytest.approx(0.8)
        assert body["cvss_immediate_threshold"] == pytest.approx(9.5)
        assert body["kev_sla_days"] == 3

    @pytest.mark.asyncio
    async def test_patch_requires_admin(self, client, db_session):
        """Analyst role gets 403."""
        from sqlalchemy import update
        from app.models.user import User as UserModel

        reg = await _register(client, "settings_analyst@example.com")
        token = reg["access_token"]

        # Downgrade to analyst
        await db_session.execute(
            update(UserModel)
            .where(UserModel.email == "settings_analyst@example.com")
            .values(role="analyst")
        )
        await db_session.commit()

        resp = await client.patch(
            f"{_ORG_URL}/settings",
            json={"ai_provider": "openai"},
            headers=_auth(token),
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_patch_invalid_provider_returns_422(self, client):
        reg = await _register(client, "settings_badprov@example.com")
        token = reg["access_token"]

        resp = await client.patch(
            f"{_ORG_URL}/settings",
            json={"ai_provider": "grok"},
            headers=_auth(token),
        )
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_patch_threshold_out_of_range_returns_422(self, client):
        reg = await _register(client, "settings_badrange@example.com")
        token = reg["access_token"]

        resp = await client.patch(
            f"{_ORG_URL}/settings",
            json={"epss_immediate_threshold": 1.5},  # max is 1.0
            headers=_auth(token),
        )
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_patch_jira_settings(self, client):
        reg = await _register(client, "settings_jira@example.com")
        token = reg["access_token"]

        resp = await client.patch(
            f"{_ORG_URL}/settings",
            json={
                "jira_base_url": "https://mycompany.atlassian.net",
                "jira_project_key": "VULN",
                "jira_api_key": "jira-token-xyz",
            },
            headers=_auth(token),
        )

        assert resp.status_code == 200
        body = resp.json()
        assert body["jira_base_url"] == "https://mycompany.atlassian.net"
        assert body["jira_project_key"] == "VULN"
        assert body["has_jira_api_key"] is True


class TestOrgSettingsLLMTest:
    @pytest.mark.asyncio
    async def test_test_llm_success(self, client):
        """POST /org/settings/test-llm returns success when LLM responds."""
        reg = await _register(client, "llm_test_ok@example.com")
        token = reg["access_token"]

        mock_response = LLMResponse(
            content="OK",
            model="claude-sonnet-4-6",
            provider="anthropic",
            input_tokens=5,
            output_tokens=1,
        )

        with patch("app.api.routes.org_settings.create_llm_client") as mock_factory:
            mock_llm = AsyncMock()
            mock_llm.complete = AsyncMock(return_value=mock_response)
            mock_factory.return_value = mock_llm

            # Pass a key in the body so the endpoint's guard (which hard-fails
            # when no key is available for a key-requiring provider) is
            # satisfied and the factory is actually invoked.
            resp = await client.post(
                f"{_ORG_URL}/settings/test-llm",
                headers=_auth(token),
                json={"ai_api_key": "sk-test-ok-key"},
            )

        assert resp.status_code == 200
        body = resp.json()
        assert body["success"] is True
        assert body["provider"] == "anthropic"
        assert "OK" in body["message"]

    @pytest.mark.asyncio
    async def test_test_llm_failure_returns_200_with_success_false(self, client):
        """LLM connection errors are caught and returned as success=False (not 500)."""
        reg = await _register(client, "llm_test_fail@example.com")
        token = reg["access_token"]

        with patch("app.api.routes.org_settings.create_llm_client") as mock_factory:
            mock_llm = AsyncMock()
            mock_llm.complete = AsyncMock(
                side_effect=httpx.ConnectError("connection refused")
            )
            mock_factory.return_value = mock_llm

            resp = await client.post(
                f"{_ORG_URL}/settings/test-llm",
                headers=_auth(token),
                json={"ai_api_key": "sk-test-will-fail"},
            )

        assert resp.status_code == 200
        body = resp.json()
        assert body["success"] is False
        assert "failed" in body["message"].lower()

    @pytest.mark.asyncio
    async def test_test_llm_returns_failure_when_no_key_available(self, client):
        """
        When the provider requires a key and neither a stored nor supplied key
        exists, the endpoint must return success=False with a clear message
        instead of calling the LLM with an empty credential.
        """
        reg = await _register(client, "llm_test_nokey@example.com")
        token = reg["access_token"]

        with patch("app.api.routes.org_settings.create_llm_client") as mock_factory:
            resp = await client.post(
                f"{_ORG_URL}/settings/test-llm", headers=_auth(token)
            )
            # Guard must short-circuit before the factory is invoked.
            mock_factory.assert_not_called()

        assert resp.status_code == 200
        body = resp.json()
        assert body["success"] is False
        assert "no api key" in body["message"].lower()

    @pytest.mark.asyncio
    async def test_test_llm_requires_admin(self, client, db_session):
        from sqlalchemy import update
        from app.models.user import User as UserModel

        reg = await _register(client, "llm_test_anl@example.com")
        token = reg["access_token"]

        await db_session.execute(
            update(UserModel)
            .where(UserModel.email == "llm_test_anl@example.com")
            .values(role="analyst")
        )
        await db_session.commit()

        resp = await client.post(
            f"{_ORG_URL}/settings/test-llm", headers=_auth(token)
        )
        assert resp.status_code == 403
