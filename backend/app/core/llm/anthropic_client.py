"""
Anthropic (Claude) LLM client.

API reference: https://docs.anthropic.com/en/api/messages
"""

from __future__ import annotations

import logging

import httpx

from app.core.llm.base import LLMClient, LLMMessage, LLMResponse

logger = logging.getLogger("vulnops.llm.anthropic")

_API_URL = "https://api.anthropic.com/v1/messages"
_ANTHROPIC_VERSION = "2023-06-01"


class AnthropicLLMClient(LLMClient):
    provider = "anthropic"

    def __init__(
        self,
        api_key: str,
        model: str = "claude-sonnet-4-6",
        *,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self._api_key = api_key
        self._model = model
        self._http_client = http_client

    async def complete(
        self,
        messages: list[LLMMessage],
        *,
        system: str | None = None,
        max_tokens: int = 1024,
        temperature: float = 0.0,
    ) -> LLMResponse:
        payload: dict = {
            "model": self._model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": [{"role": m.role, "content": m.content} for m in messages],
        }
        if system:
            payload["system"] = system

        headers = {
            "x-api-key": self._api_key,
            "anthropic-version": _ANTHROPIC_VERSION,
            "content-type": "application/json",
        }

        own_client = self._http_client is None
        client: httpx.AsyncClient = (
            httpx.AsyncClient(timeout=60) if own_client else self._http_client  # type: ignore[assignment]
        )
        try:
            resp = await client.post(_API_URL, json=payload, headers=headers)
            resp.raise_for_status()
        finally:
            if own_client:
                await client.aclose()

        data = resp.json()
        content_blocks = data.get("content", [])
        text = content_blocks[0]["text"] if content_blocks else ""
        usage = data.get("usage", {})

        return LLMResponse(
            content=text,
            model=data.get("model", self._model),
            provider=self.provider,
            input_tokens=usage.get("input_tokens", 0),
            output_tokens=usage.get("output_tokens", 0),
        )
