"""
Scanner connection endpoints.

Manage API credentials and sync state for scanner integrations
(Tenable, Qualys, etc.).

Endpoints:
  GET    /scanner-connections/              — list org's connections
  POST   /scanner-connections/             — create (admin only)
  GET    /scanner-connections/providers    — list available providers + config keys
  GET    /scanner-connections/{id}         — get single
  PATCH  /scanner-connections/{id}         — update (admin only)
  DELETE /scanner-connections/{id}         — delete (admin only)
  POST   /scanner-connections/{id}/test    — test credentials
  POST   /scanner-connections/{id}/sync    — trigger one-shot sync
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_org_encryption, require_role
from app.core.encryption import FieldEncryption
from app.db.session import get_db
from app.models.user import User
from app.schemas.scanner_connection import (
    ScannerConnectionCreate,
    ScannerConnectionResponse,
    ScannerConnectionUpdate,
    SyncResult,
)
from app.services.scanner_connection import (
    create_connection,
    delete_connection,
    get_connection,
    list_connections,
    run_sync,
    update_connection,
)

router = APIRouter()


def _404(connection_id: uuid.UUID) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Scanner connection {connection_id} not found.",
    )


@router.get("/providers")
async def list_providers(
    _: User = Depends(get_current_user),
) -> list[dict]:
    """Return available scanner providers and their required config keys."""
    from app.core.clients.scanners.registry import list_providers as _list
    return _list()


@router.get("/", response_model=list[ScannerConnectionResponse])
async def list_scanner_connections(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    _: FieldEncryption = Depends(get_org_encryption),
) -> list[ScannerConnectionResponse]:
    connections = await list_connections(db, current_user.org_id)
    return [ScannerConnectionResponse.model_validate(c) for c in connections]


@router.post("/", response_model=ScannerConnectionResponse, status_code=201)
async def create_scanner_connection(
    data: ScannerConnectionCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
    _: FieldEncryption = Depends(get_org_encryption),
) -> ScannerConnectionResponse:
    conn = await create_connection(db, current_user.org_id, data)
    return ScannerConnectionResponse.model_validate(conn)


@router.get("/{connection_id}", response_model=ScannerConnectionResponse)
async def get_scanner_connection(
    connection_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    _: FieldEncryption = Depends(get_org_encryption),
) -> ScannerConnectionResponse:
    conn = await get_connection(db, current_user.org_id, connection_id)
    if conn is None:
        raise _404(connection_id)
    return ScannerConnectionResponse.model_validate(conn)


@router.patch("/{connection_id}", response_model=ScannerConnectionResponse)
async def update_scanner_connection(
    connection_id: uuid.UUID,
    data: ScannerConnectionUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
    _: FieldEncryption = Depends(get_org_encryption),
) -> ScannerConnectionResponse:
    conn = await get_connection(db, current_user.org_id, connection_id)
    if conn is None:
        raise _404(connection_id)
    conn = await update_connection(db, conn, data)
    return ScannerConnectionResponse.model_validate(conn)


@router.delete("/{connection_id}", status_code=204, response_model=None)
async def delete_scanner_connection(
    connection_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
    _: FieldEncryption = Depends(get_org_encryption),
) -> None:
    conn = await get_connection(db, current_user.org_id, connection_id)
    if conn is None:
        raise _404(connection_id)
    await delete_connection(db, conn)


@router.post("/{connection_id}/test")
async def test_scanner_connection(
    connection_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    _: FieldEncryption = Depends(get_org_encryption),
) -> dict:
    import json
    from app.core.clients.scanners.registry import get_scanner_client

    conn = await get_connection(db, current_user.org_id, connection_id)
    if conn is None:
        raise _404(connection_id)

    config = json.loads(conn.enc_config)
    client = get_scanner_client(conn.provider, config)
    ok = await client.test_connection()
    return {"status": "ok" if ok else "error", "connected": ok}


@router.post("/{connection_id}/sync", response_model=SyncResult)
async def sync_scanner_connection(
    connection_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("admin", "analyst")),
    _: FieldEncryption = Depends(get_org_encryption),
) -> SyncResult:
    conn = await get_connection(db, current_user.org_id, connection_id)
    if conn is None:
        raise _404(connection_id)

    return await run_sync(db, current_user.org_id, conn, since=conn.last_sync_at)
