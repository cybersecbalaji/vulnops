"""
Input sanitization pipeline — mandatory for all ingested finding data
and any user-supplied free-text that reaches LLM prompts.

Pipeline order (per PRD §Data Sanitization on Ingestion):
  1. CVE ID strict validation
  2. HTML / control-char strip + Unicode NFC normalization
  3. URL scheme allowlist check
  4. Free-text length cap + prompt-injection pattern rejection
  5. CSV injection prefix quoting
  6. Size limit enforcement
"""

from __future__ import annotations

import html
import re
import unicodedata
from urllib.parse import urlparse

# ── Constants ─────────────────────────────────────────────────────────────────

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

# Bidirectional override characters (Unicode RLO / LRO / etc.)
BIDI_CHARS = re.compile(
    r"[\u200e\u200f\u202a-\u202e\u2066-\u2069\u200b-\u200d\ufeff]"
)

# HTML / XML tags
HTML_TAG_PATTERN = re.compile(r"<[^>]+>")

# Control characters (except \t \n \r which may be in notes)
CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

# URL schemes that are never acceptable in finding fields
BLOCKED_URL_SCHEMES = {"javascript", "data", "file", "vbscript"}

# Prompt injection patterns (case-insensitive)
INJECTION_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"ignore\s+(previous|prior|above)\s+instructions",
        r"system\s*:",
        r"<\s*/?system\s*>",
        r"assistant\s*:",
        r"forget\s+(everything|all)",
        r"new\s+role\s*:",
        r"you\s+are\s+now",
        r"\[INST\]",
        r"\[\/INST\]",
        r"<\|im_start\|>",
        r"<\|im_end\|>",
    ]
]

# CSV injection trigger characters
CSV_INJECTION_CHARS = ("=", "+", "-", "@", "\t", "\r")

FREE_TEXT_MAX_LEN = 2_000
FIELD_MAX_LEN = 10_000
CSV_MAX_BYTES = 50 * 1024 * 1024   # 50 MB
JSON_MAX_BYTES = 20 * 1024 * 1024  # 20 MB


# ── Helpers ───────────────────────────────────────────────────────────────────

def _strip_html(value: str) -> str:
    return HTML_TAG_PATTERN.sub("", value)


def _strip_control_chars(value: str) -> str:
    value = CONTROL_CHARS.sub("", value)
    value = BIDI_CHARS.sub("", value)
    return value


def _normalize_unicode(value: str) -> str:
    return unicodedata.normalize("NFC", value)


def _check_injection(value: str) -> None:
    for pattern in INJECTION_PATTERNS:
        if pattern.search(value):
            raise ValueError(
                f"Potential prompt injection detected. "
                f"Input contains a disallowed pattern: '{pattern.pattern}'"
            )


# ── Public API ────────────────────────────────────────────────────────────────

def validate_cve_id(cve_id: str) -> str:
    """Strict CVE ID validation. Raises ValueError on mismatch."""
    cve_id = cve_id.strip().upper()
    if not CVE_PATTERN.match(cve_id):
        raise ValueError(
            f"Invalid CVE ID format: '{cve_id}'. Expected: CVE-YYYY-NNNNN+"
        )
    return cve_id


def sanitize_text_field(value: str, max_len: int = FREE_TEXT_MAX_LEN) -> str:
    """
    General text field sanitization:
    - Strip HTML tags
    - Remove control chars and bidi overrides
    - Normalize to UTF-8 NFC
    - Enforce length limit
    """
    value = _strip_html(value)
    value = _strip_control_chars(value)
    value = _normalize_unicode(value)
    return value[:max_len]


def sanitize_url_field(url: str) -> str:
    """
    Validate a URL field against the scheme allowlist.
    Raises ValueError for blocked schemes.
    """
    url = url.strip()
    try:
        parsed = urlparse(url)
    except Exception as exc:
        raise ValueError(f"Malformed URL: {exc}") from exc

    scheme = (parsed.scheme or "").lower()
    if scheme in BLOCKED_URL_SCHEMES:
        raise ValueError(
            f"URL scheme '{scheme}' is not permitted. "
            f"Allowed schemes: http, https"
        )
    return url


def sanitize_for_prompt(value: str) -> str:
    """
    Prepare a field value for insertion into an LLM prompt.
    - Runs injection-pattern check (raises ValueError on detection)
    - HTML-escapes the result
    - Truncates to FREE_TEXT_MAX_LEN
    """
    _check_injection(value)
    escaped = html.escape(value[:FREE_TEXT_MAX_LEN])
    return escaped


def prevent_csv_injection(value: str) -> str:
    """
    Prefix CSV-injectable values with a single quote so spreadsheet
    applications do not execute formulas.
    """
    if value and value[0] in CSV_INJECTION_CHARS:
        return "'" + value
    return value


def check_upload_size(data: bytes, max_bytes: int, label: str) -> None:
    """Raise ValueError if upload exceeds the allowed size."""
    if len(data) > max_bytes:
        raise ValueError(
            f"{label} upload exceeds the {max_bytes // (1024 * 1024)} MB limit "
            f"(received {len(data) // (1024 * 1024)} MB)."
        )
