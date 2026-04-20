"""
LLM abstraction base — provider-agnostic interface for all LLM calls.

PRD non-negotiable: ALL LLM calls must go through LLMClient.complete().
Temperature MUST be 0.0 for every scoring call (Phase 6+).

Supported providers (enforced by factory):
    anthropic | openai | gemini | ollama
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

VALID_PROVIDERS: frozenset[str] = frozenset({"anthropic", "openai", "gemini", "ollama"})
DEFAULT_MODELS: dict[str, str] = {
    "anthropic": "claude-sonnet-4-6",
    "openai": "gpt-4o",
    "gemini": "gemini-1.5-pro",
    "ollama": "llama3",
}


@dataclass
class LLMMessage:
    """A single turn in a conversation."""
    role: str     # "user" | "assistant"
    content: str


@dataclass
class LLMResponse:
    """Normalised response returned by every LLMClient implementation."""
    content: str
    model: str
    provider: str
    input_tokens: int
    output_tokens: int


class LLMClient(ABC):
    """
    Abstract base for all LLM provider clients.

    Subclasses must set the ``provider`` class attribute and implement
    ``complete()``.  The ``http_client`` constructor parameter is provided for
    dependency injection in tests (avoids global httpx patching).
    """

    provider: str  # set by each concrete subclass

    @abstractmethod
    async def complete(
        self,
        messages: list[LLMMessage],
        *,
        system: str | None = None,
        max_tokens: int = 1024,
        temperature: float = 0.0,
    ) -> LLMResponse:
        """
        Send ``messages`` to the LLM and return a normalised response.

        Args:
            messages: Conversation turns (role + content).
            system: Optional system prompt.
            max_tokens: Maximum tokens to generate.
            temperature: Sampling temperature.  Must be 0.0 for scoring calls.
        """
        ...
