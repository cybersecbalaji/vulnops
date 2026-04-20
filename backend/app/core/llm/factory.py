"""
LLM client factory.

Creates the correct LLMClient subclass based on the provider string stored in
OrgSettings.  All Phase 6+ code must obtain LLM clients exclusively through
this factory (PRD non-negotiable: all LLM calls via LLMClient abstraction).
"""

from __future__ import annotations

import httpx

from app.core.llm.anthropic_client import AnthropicLLMClient
from app.core.llm.base import DEFAULT_MODELS, VALID_PROVIDERS, LLMClient
from app.core.llm.gemini_client import GeminiLLMClient
from app.core.llm.ollama_client import OllamaLLMClient
from app.core.llm.openai_client import OpenAILLMClient


def create_llm_client(
    provider: str,
    model: str | None = None,
    api_key: str | None = None,
    base_url: str | None = None,
    *,
    http_client: httpx.AsyncClient | None = None,
) -> LLMClient:
    """
    Instantiate and return the appropriate LLMClient for ``provider``.

    Args:
        provider: One of ``"anthropic"``, ``"openai"``, ``"gemini"``, ``"ollama"``.
        model: Model identifier.  Defaults to the provider's recommended model
               (see ``DEFAULT_MODELS``) when ``None`` or empty.
        api_key: Provider API key (not required for Ollama).
        base_url: Custom endpoint base URL.  Used for Ollama and OpenAI-compatible
                  proxies; ignored by Anthropic and Gemini.
        http_client: Optional pre-created httpx client for testing.

    Raises:
        ValueError: When ``provider`` is not in ``VALID_PROVIDERS``.
    """
    if provider not in VALID_PROVIDERS:
        raise ValueError(
            f"Unknown LLM provider {provider!r}. "
            f"Must be one of: {', '.join(sorted(VALID_PROVIDERS))}"
        )

    effective_model = model or DEFAULT_MODELS[provider]
    key = api_key or ""

    if provider == "anthropic":
        return AnthropicLLMClient(
            api_key=key, model=effective_model, http_client=http_client
        )
    if provider == "openai":
        kwargs: dict = {"api_key": key, "model": effective_model, "http_client": http_client}
        if base_url:
            kwargs["base_url"] = base_url
        return OpenAILLMClient(**kwargs)
    if provider == "gemini":
        return GeminiLLMClient(
            api_key=key, model=effective_model, http_client=http_client
        )
    # ollama
    return OllamaLLMClient(
        model=effective_model,
        base_url=base_url or "http://localhost:11434",
        http_client=http_client,
    )
