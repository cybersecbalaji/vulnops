"""
Google Gemini LLM client.

Uses the Gemini REST API (generativelanguage.googleapis.com).
Gemini does not have a dedicated "system" role; system prompts are injected as
a leading user/model exchange pair so the model treats them as instructions.

API reference: https://ai.google.dev/api/generate-content
"""

from __future__ import annotations

import logging

import httpx

from app.core.llm.base import LLMClient, LLMMessage, LLMResponse

logger = logging.getLogger("vulnops.llm.gemini")

_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/models"


class GeminiLLMClient(LLMClient):
    provider = "gemini"

    def __init__(
        self,
        api_key: str,
        model: str = "gemini-1.5-pro",
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
        contents: list[dict] = []

        # Gemini has no system role — inject as a user/model primer pair
        if system:
            contents.append({"role": "user", "parts": [{"text": system}]})
            contents.append({"role": "model", "parts": [{"text": "Understood."}]})

        for m in messages:
            # Gemini uses "model" instead of "assistant"
            role = "model" if m.role == "assistant" else "user"
            contents.append({"role": role, "parts": [{"text": m.content}]})

        payload = {
            "contents": contents,
            "generationConfig": {
                "temperature": temperature,
                "maxOutputTokens": max_tokens,
            },
        }

        url = f"{_BASE_URL}/{self._model}:generateContent"

        own_client = self._http_client is None
        client: httpx.AsyncClient = (
            httpx.AsyncClient(timeout=60) if own_client else self._http_client  # type: ignore[assignment]
        )
        try:
            resp = await client.post(url, json=payload, params={"key": self._api_key})
            resp.raise_for_status()
        finally:
            if own_client:
                await client.aclose()

        data = resp.json()
        text = data["candidates"][0]["content"]["parts"][0]["text"]
        usage = data.get("usageMetadata", {})

        return LLMResponse(
            content=text,
            model=self._model,
            provider=self.provider,
            input_tokens=usage.get("promptTokenCount", 0),
            output_tokens=usage.get("candidatesTokenCount", 0),
        )
