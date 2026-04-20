"""
Pydantic schemas for org settings (LLM provider config + scoring thresholds).

Security note: encrypted API keys are NEVER included in response schemas.
Callers learn whether a key is set via the ``has_ai_api_key`` / ``has_jira_api_key``
boolean fields instead.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.llm.base import VALID_PROVIDERS


# ── Response ──────────────────────────────────────────────────────────────────

class OrgSettingsResponse(BaseModel):
    """
    Combined view of OrgSettings + Organization threshold fields.
    Returned by GET and PATCH /org/settings.
    """
    model_config = ConfigDict(from_attributes=True)

    # LLM configuration
    ai_provider: str
    ai_model: str
    has_ai_api_key: bool          # True when an encrypted key is stored
    ollama_base_url: str | None

    # Jira integration
    jira_base_url: str | None
    jira_project_key: str | None
    has_jira_api_key: bool        # True when an encrypted key is stored

    # Org scoring thresholds (from organizations table)
    epss_immediate_threshold: float
    epss_this_week_threshold: float
    cvss_immediate_threshold: float
    cvss_this_week_threshold: float
    kev_sla_days: int
    non_kev_critical_sla_days: int


# ── Update ────────────────────────────────────────────────────────────────────

class OrgSettingsUpdate(BaseModel):
    """
    Partial update body for PATCH /org/settings.

    Plain-text ``ai_api_key`` and ``jira_api_key`` are accepted here and
    encrypted with the org DEK before persisting — they are never stored or
    returned in plaintext.
    """

    # LLM configuration
    ai_provider: str | None = None
    ai_model: str | None = None
    ai_api_key: str | None = None         # plain text — encrypted before storage
    ollama_base_url: str | None = None

    # Jira
    jira_base_url: str | None = None
    jira_project_key: str | None = None
    jira_api_key: str | None = None       # plain text — encrypted before storage

    # Scoring thresholds
    epss_immediate_threshold: float | None = Field(default=None, ge=0.0, le=1.0)
    epss_this_week_threshold: float | None = Field(default=None, ge=0.0, le=1.0)
    cvss_immediate_threshold: float | None = Field(default=None, ge=0.0, le=10.0)
    cvss_this_week_threshold: float | None = Field(default=None, ge=0.0, le=10.0)
    kev_sla_days: int | None = Field(default=None, ge=1)
    non_kev_critical_sla_days: int | None = Field(default=None, ge=1)

    @field_validator("ai_provider")
    @classmethod
    def validate_ai_provider(cls, v: str | None) -> str | None:
        if v is None:
            return None
        if v not in VALID_PROVIDERS:
            raise ValueError(
                f"ai_provider must be one of: {', '.join(sorted(VALID_PROVIDERS))}"
            )
        return v


# ── LLM test request / response ───────────────────────────────────────────────

class LLMTestRequest(BaseModel):
    """Optional body for POST /org/settings/test-llm.
    If ai_api_key is provided it overrides the stored key for this test only."""
    ai_api_key: str | None = None


class LLMTestResponse(BaseModel):
    """Result of POST /org/settings/test-llm."""
    success: bool
    provider: str
    model: str
    message: str
