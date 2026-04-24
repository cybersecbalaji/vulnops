"""
Scanner client registry.

Import each provider module (which registers itself) and expose
`get_scanner_client(provider, config)` as the single factory.
"""

from __future__ import annotations

from app.core.clients.scanners.base import ScannerClient

SCANNER_CLIENTS: dict[str, type[ScannerClient]] = {}


def register(cls: type[ScannerClient]) -> type[ScannerClient]:
    """Class decorator that registers a ScannerClient subclass by its `name`."""
    SCANNER_CLIENTS[cls.name] = cls
    return cls


def get_scanner_client(provider: str, config: dict[str, str]) -> ScannerClient:
    """Instantiate and return the scanner client for `provider`."""
    if provider not in SCANNER_CLIENTS:
        raise ValueError(
            f"Unknown scanner provider '{provider}'. "
            f"Available: {sorted(SCANNER_CLIENTS)}"
        )
    return SCANNER_CLIENTS[provider](config)


def list_providers() -> list[dict]:
    """Return provider metadata for the UI (name + required config keys)."""
    return [
        {"provider": name, "required_config_keys": cls.required_config_keys}
        for name, cls in sorted(SCANNER_CLIENTS.items())
    ]


# ── Auto-import all providers so they self-register ───────────────────────────
from app.core.clients.scanners import tenable, qualys  # noqa: E402, F401
