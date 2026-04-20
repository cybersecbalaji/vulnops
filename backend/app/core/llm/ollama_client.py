"""
Ollama local LLM client.

Connects to a locally-running Ollama server (default: http://localhost:11434).
Ollama's /api/chat endpoint is OpenAI-chat-compatible so this is a thin adapter.

API reference: https://github.com/ollama/ollama/blob/main/docs/api.md#chat
"""

from __future__ import annotations

import logging

import httpx

from app.core.llm.base import LLMClient, LLMMessage, LLMResponse

logger = logging.getLogger("vulnops.llm.ollama")

_DEFAULT_BASE_URL = "http://localhost:11434"


class OllamaLLMClient(LLMClient):
    provider = "ollama"

    def __init__(
        self,
        model: str = "llama3",
        base_url: str = _DEFAULT_BASE_URL,
        *,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
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
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
            },
        }

        own_client = self._http_client is None
        client: httpx.AsyncClient = (
            httpx.AsyncClient(timeout=120) if own_client else self._http_client  # type: ignore[assignment]
        )
        try:
            resp = await client.post(
                f"{self._base_url}/api/chat", json=payload
            )
            resp.raise_for_status()
        finally:
            if own_client:
                await client.aclose()

        data = resp.json()
        text = data["message"]["content"]

        return LLMResponse(
            content=text,
            model=data.get("model", self._model),
            provider=self.provider,
            input_tokens=data.get("prompt_eval_count", 0),
            output_tokens=data.get("eval_count", 0),
        )
