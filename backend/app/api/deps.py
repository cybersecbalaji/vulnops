"""
FastAPI dependency injection.

- get_db: yields an async SQLAlchemy session
- get_redis: returns the shared Redis client
- get_current_user: validates Bearer JWT, returns User ORM object
- require_role: factory that raises 403 if the user lacks the required role
- get_org_encryption: async generator — decrypts the org DEK, installs it in
  the request-scoped ContextVar, yields the FieldEncryption instance, and
  resets the ContextVar on teardown.  Any DB operation that reads or writes
  an EncryptedString column must Depend on this.
"""

from __future__ import annotations

import uuid as uuid_lib
from typing import AsyncGenerator, Callable

import redis.asyncio as aioredis
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.encryption import FieldEncryption, MasterKeyEncryption, encryption_context
from app.core.security import verify_access_token
from app.db.session import get_db, get_redis
from app.models.organization import Organization
from app.models.user import User

# Bearer token extractor — returns 403 (not 401) when header is missing,
# which is correct behaviour for APIs (per RFC 6750 §3.1).
bearer_scheme = HTTPBearer(auto_error=True)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    """
    Validate the JWT access token and return the authenticated User.
    Raises HTTP 401 on any token problem.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired access token.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = verify_access_token(credentials.credentials)
    except JWTError:
        raise credentials_exception

    user_id: str = payload.get("sub", "")
    if not user_id:
        raise credentials_exception

    try:
        user_uuid = uuid_lib.UUID(user_id)
    except ValueError:
        raise credentials_exception

    result = await db.execute(select(User).where(User.id == user_uuid))
    user = result.scalar_one_or_none()

    if user is None or not user.is_active:
        raise credentials_exception

    return user


def require_role(*allowed_roles: str) -> Callable:
    """
    Dependency factory: raises HTTP 403 if the current user's role is not in
    allowed_roles.

    Usage:
        @router.post("/admin-only")
        async def admin_endpoint(user: User = Depends(require_role("admin"))):
            ...
    """
    async def role_enforcer(
        current_user: User = Depends(get_current_user),
    ) -> User:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"This action requires one of the following roles: {', '.join(allowed_roles)}.",
            )
        return current_user

    return role_enforcer


async def get_org_encryption(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> AsyncGenerator[FieldEncryption, None]:
    """
    Async generator dependency that:
    1. Resolves the current org's DEK from the master key.
    2. Installs the FieldEncryption instance in the request-scoped ContextVar
       so that EncryptedString TypeDecorator hooks can encrypt / decrypt
       transparently for the duration of this request.
    3. Resets the ContextVar on teardown (after the response is sent).

    Routes that read or write any enc_* column MUST Depend on this.
    The encryption_context() context manager ensures concurrent requests
    never share encryption state (ContextVar is task-local in asyncio).
    """
    result = await db.execute(
        select(Organization).where(Organization.id == current_user.org_id)
    )
    org = result.scalar_one_or_none()
    if org is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Organization not found for current user.",
        )

    master = MasterKeyEncryption(settings.MASTER_ENCRYPTION_KEY)
    dek = master.decrypt_dek(org.encrypted_dek)
    field_enc = FieldEncryption(dek)

    with encryption_context(field_enc):
        yield field_enc


async def get_llm_client(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    field_enc: FieldEncryption = Depends(get_org_encryption),
):
    """
    Dependency that resolves the org's configured LLMClient.

    Reads OrgSettings, decrypts the stored API key with the org DEK, and
    returns the appropriate LLMClient subclass.  All Phase 6+ routes that call
    an LLM must Depend on this — direct LLM instantiation is forbidden by PRD.
    """
    from app.core.llm import create_llm_client
    from app.models.organization import OrgSettings

    result = await db.execute(
        select(OrgSettings).where(OrgSettings.org_id == current_user.org_id)
    )
    org_settings = result.scalar_one_or_none()

    if org_settings is None:
        from app.core.llm.base import DEFAULT_MODELS
        return create_llm_client("anthropic", DEFAULT_MODELS["anthropic"])

    api_key: str | None = None
    if org_settings.encrypted_ai_api_key:
        api_key = field_enc.decrypt(org_settings.encrypted_ai_api_key)

    return create_llm_client(
        org_settings.ai_provider,
        org_settings.ai_model,
        api_key=api_key,
        base_url=org_settings.ollama_base_url,
    )
