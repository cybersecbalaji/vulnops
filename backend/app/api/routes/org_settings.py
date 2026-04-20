"""
Org settings routes — LLM provider configuration and scoring thresholds.

Endpoints:
  GET   /org/settings           — current org's settings (no API keys returned)
  PATCH /org/settings           — update settings (admin only)
  POST  /org/settings/test-llm  — verify LLM connection (admin only)

All endpoints require authentication.  PATCH and test-llm require admin role
(checked inline for reliability — see Phase 3 notes in project memory).

The ``get_org_encryption`` dependency is required here because PATCH encrypts
API keys with the org DEK, and GET must build the ``has_*`` booleans without
decrypting.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_org_encryption
from app.core.encryption import FieldEncryption
from app.core.llm import LLMMessage, create_llm_client
from app.db.session import get_db
from app.models.organization import Organization, OrgSettings
from app.models.user import User
from app.schemas.org_settings import LLMTestRequest, LLMTestResponse, OrgSettingsResponse, OrgSettingsUpdate

router = APIRouter()


# ── Helpers ───────────────────────────────────────────────────────────────────

async def _get_org_and_settings(
    db: AsyncSession, org_id
) -> tuple[Organization, OrgSettings]:
    """Return (org, org_settings) for the given org_id.  Both are guaranteed non-None."""
    org_result = await db.execute(
        select(Organization).where(Organization.id == org_id)
    )
    org = org_result.scalar_one()

    settings_result = await db.execute(
        select(OrgSettings).where(OrgSettings.org_id == org_id)
    )
    settings = settings_result.scalar_one()
    return org, settings


def _build_response(org: Organization, settings: OrgSettings) -> OrgSettingsResponse:
    return OrgSettingsResponse(
        ai_provider=settings.ai_provider,
        ai_model=settings.ai_model,
        has_ai_api_key=bool(settings.encrypted_ai_api_key),
        ollama_base_url=settings.ollama_base_url,
        jira_base_url=settings.jira_base_url,
        jira_project_key=settings.jira_project_key,
        has_jira_api_key=bool(settings.encrypted_jira_api_key),
        epss_immediate_threshold=org.epss_immediate_threshold,
        epss_this_week_threshold=org.epss_this_week_threshold,
        cvss_immediate_threshold=org.cvss_immediate_threshold,
        cvss_this_week_threshold=org.cvss_this_week_threshold,
        kev_sla_days=org.kev_sla_days,
        non_kev_critical_sla_days=org.non_kev_critical_sla_days,
    )


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get("/settings", response_model=OrgSettingsResponse)
async def get_org_settings(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> OrgSettingsResponse:
    """
    Return the current org's LLM configuration and scoring thresholds.

    API keys are never returned — use the ``has_*`` boolean fields to check
    whether a key is configured.
    """
    org, settings = await _get_org_and_settings(db, current_user.org_id)
    return _build_response(org, settings)


@router.patch("/settings", response_model=OrgSettingsResponse)
async def update_org_settings(
    data: OrgSettingsUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    field_enc: FieldEncryption = Depends(get_org_encryption),
) -> OrgSettingsResponse:
    """
    Update the org's LLM configuration and/or scoring thresholds.  Admin only.

    Plain-text ``ai_api_key`` / ``jira_api_key`` in the request body are
    encrypted with the org DEK before storing.  They are never persisted or
    returned in plaintext.
    """
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This action requires the admin role.",
        )

    org, settings = await _get_org_and_settings(db, current_user.org_id)
    updates = data.model_dump(exclude_unset=True)

    _ORG_THRESHOLD_FIELDS = {
        "epss_immediate_threshold",
        "epss_this_week_threshold",
        "cvss_immediate_threshold",
        "cvss_this_week_threshold",
        "kev_sla_days",
        "non_kev_critical_sla_days",
    }

    for field, value in updates.items():
        if field == "ai_api_key":
            settings.encrypted_ai_api_key = field_enc.encrypt(value) if value else None
        elif field == "jira_api_key":
            settings.encrypted_jira_api_key = field_enc.encrypt(value) if value else None
        elif field in _ORG_THRESHOLD_FIELDS:
            setattr(org, field, value)
        else:
            setattr(settings, field, value)

    await db.flush()
    await db.commit()
    return _build_response(org, settings)


@router.post("/settings/test-llm", response_model=LLMTestResponse)
async def test_llm_connection(
    body: LLMTestRequest = LLMTestRequest(),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    field_enc: FieldEncryption = Depends(get_org_encryption),
) -> LLMTestResponse:
    """
    Send a test prompt to the configured LLM provider and return the result.
    Admin only.  Useful for validating that API keys and model names are correct.

    If ``body.ai_api_key`` is provided it is used for this test only (not saved).
    This lets users test a key before saving it.
    """
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This action requires the admin role.",
        )

    _, settings = await _get_org_and_settings(db, current_user.org_id)

    # Use the key from the request body if provided, otherwise decrypt the stored key.
    # Track which source was used so the response makes the behavior transparent.
    if body.ai_api_key:
        api_key: str | None = body.ai_api_key
        key_source = "provided"
    elif settings.encrypted_ai_api_key:
        api_key = field_enc.decrypt(settings.encrypted_ai_api_key)
        key_source = "stored"
    else:
        api_key = None
        key_source = "none"

    # Hard-fail if provider requires an API key but none is available. Without
    # this guard we'd call the provider with an empty Authorization header and
    # rely on the provider's own 401 to surface the problem — fragile, and if
    # the provider ever responds with a non-auth error, the failure mode is
    # confusing. Ollama is the only provider that does not need a key.
    if settings.ai_provider != "ollama" and not (api_key or "").strip():
        return LLMTestResponse(
            success=False,
            provider=settings.ai_provider,
            model=settings.ai_model,
            message=(
                f"No API key available for provider {settings.ai_provider!r}. "
                "Paste a key above or save one to your org settings first."
            ),
        )

    llm = create_llm_client(
        settings.ai_provider,
        settings.ai_model,
        api_key=api_key,
        base_url=settings.ollama_base_url,
    )

    try:
        response = await llm.complete(
            [LLMMessage(role="user", content="Reply with exactly: OK")],
            max_tokens=10,
            temperature=0.0,
        )
        # Include key source so users understand which credential was validated.
        suffix = {
            "provided": " (using the key you just typed)",
            "stored": " (using the key previously saved to your org)",
            "none": "",
        }[key_source]
        return LLMTestResponse(
            success=True,
            provider=settings.ai_provider,
            model=settings.ai_model,
            message=f"Connection successful{suffix}. Response: {response.content[:100]}",
        )
    except Exception as exc:
        return LLMTestResponse(
            success=False,
            provider=settings.ai_provider,
            model=settings.ai_model,
            message=f"Connection failed: {exc}",
        )
