"""
OpenAI (GPT) LLM client.

Also works for any OpenAI-compatible endpoint (Azure OpenAI, local vLLM, etc.)
by setting a custom ``base_url``.

API reference: https://platform.openai.com/docs/api-reference/chat
"""

from __future__ import annotations

import logging

import httpx

from app.core.llm.base import LLMClient, LLMMessage, LLMResponse

logger = logging.getLogger("vulnops.llm.openai")

_DEFAULT_BASE_URL = "https://api.openai.com/v1"


class OpenAILLMClient(LLMClient):
    provider = "openai"

    def __init__(
        self,
        api_key: str,
        model: str = "gpt-4o",
        base_url: str = _DEFAULT_BASE_URL,
        *,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self._api_key = api_key
        self._model = model
        self._base_url = base_url.rstrip("/")
        self._http_client = http_client

    async def complete(
        self,
        messages: list[LLMMessage],
        *,
        system: str | None = None,
        max_tokens: int = 1024,
        temperature: float = 0.0,
    ) -> LLMResponse:
        api_messages: list[dict] = []
        if system:
            api_messages.append({"role": "system", "content": system})
        api_messages.extend({"role": m.role, "content": m.content} for m in messages)

        payload = {
            "model": self._model,
            "messages": api_messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }

        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "content-type": "application/json",
        }

        own_client = self._http_client is None
        client: httpx.AsyncClient = (
            httpx.AsyncClient(timeout=60) if own_client else self._http_client  # type: ignore[assignment]
        )
        try:
            resp = await client.post(
                f"{self._base_url}/chat/completions",
                json=payload,
                headers=headers,
            )
            resp.raise_for_status()
        finally:
            if own_client:
                await client.aclose()

        data = resp.json()
        text = data["choices"][0]["message"]["content"]
        usage = data.get("usage", {})

        return LLMResponse(
            content=text,
            model=data.get("model", self._model),
            provider=self.provider,
            input_tokens=usage.get("prompt_tokens", 0),
            output_tokens=usage.get("completion_tokens", 0),
        )
