"""
Abstract base for scanner API connectors.

Each connector must:
- Declare its `name` (matches the `provider` column in scanner_connections).
- Declare `required_config_keys` so the UI can render the right form fields.
- Implement `test_connection()` — returns True if credentials are valid.
- Implement `fetch_findings()` — async generator yielding VulnerabilityCreate-
  compatible dicts, optionally only findings changed since `since`.

Connectors are registered in registry.py and instantiated by
`get_scanner_client(provider, config)`.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime
from typing import AsyncIterator


class ScannerClient(ABC):
    name: str
    required_config_keys: list[str]

    def __init__(self, config: dict[str, str]) -> None:
        self.config = config

    @abstractmethod
    async def test_connection(self) -> bool:
        """Return True if the configured credentials are valid."""

    @abstractmethod
    async def fetch_findings(
        self, since: datetime | None = None
    ) -> AsyncIterator[dict]:
        """
        Yield vulnerability dicts compatible with VulnerabilityCreate.

        Required keys per dict:
            cve_id, title, description, severity, source, source_id
        Optional keys (same as VulnerabilityCreate):
            affected_component, cvss_score, epss_score, published_at, notes
        """
