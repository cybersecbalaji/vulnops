"""
Service layer for scanner connections — CRUD + sync logic.

All functions take (db, org_id, ...) and scope every query to org_id.
Credentials are stored encrypted via EncryptedString; callers must have an
active encryption_context() before calling any read/write function.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone

from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.scanner_connection import ScannerConnection
from app.schemas.scanner_connection import (
    ScannerConnectionCreate,
    ScannerConnectionUpdate,
    SyncResult,
)
from app.schemas.vulnerability import VulnerabilityCreate
from app.services.vulnerability import IngestionError, IngestionResult, ingest_batch

logger = logging.getLogger("vulnops.scanner_connection")


async def create_connection(
    db: AsyncSession,
    org_id: uuid.UUID,
    data: ScannerConnectionCreate,
) -> ScannerConnection:
    conn = ScannerConnection(
        org_id=org_id,
        name=data.name,
        provider=data.provider,
        enc_config=json.dumps(data.config),
    )
    db.add(conn)
    await db.commit()
    await db.refresh(conn)
    return conn


async def list_connections(
    db: AsyncSession,
    org_id: uuid.UUID,
) -> list[ScannerConnection]:
    result = await db.execute(
        select(ScannerConnection)
        .where(ScannerConnection.org_id == org_id)
        .order_by(ScannerConnection.created_at)
    )
    return list(result.scalars().all())


async def get_connection(
    db: AsyncSession,
    org_id: uuid.UUID,
    connection_id: uuid.UUID,
) -> ScannerConnection | None:
    result = await db.execute(
        select(ScannerConnection).where(
            ScannerConnection.org_id == org_id,
            ScannerConnection.id == connection_id,
        )
    )
    return result.scalar_one_or_none()


async def update_connection(
    db: AsyncSession,
    conn: ScannerConnection,
    data: ScannerConnectionUpdate,
) -> ScannerConnection:
    if data.name is not None:
        conn.name = data.name
    if data.enabled is not None:
        conn.enabled = data.enabled
    if data.config is not None:
        conn.enc_config = json.dumps(data.config)
    await db.commit()
    await db.refresh(conn)
    return conn


async def delete_connection(db: AsyncSession, conn: ScannerConnection) -> None:
    await db.delete(conn)
    await db.commit()


async def run_sync(
    db: AsyncSession,
    org_id: uuid.UUID,
    conn: ScannerConnection,
    since: datetime | None = None,
) -> SyncResult:
    """
    Pull findings from the scanner and ingest them into vulnerabilities.

    Updates last_sync_at / last_sync_status / last_sync_error on the connection.
    """
    from app.core.clients.scanners.registry import get_scanner_client

    config = json.loads(conn.enc_config)
    client = get_scanner_client(conn.provider, config)

    conn.last_sync_status = "running"
    conn.last_sync_at = datetime.now(timezone.utc)
    await db.commit()

    parsed_rows: list[tuple[int, VulnerabilityCreate | None, str | None]] = []
    fetch_errors = 0
    row_num = 1

    try:
        async for finding in client.fetch_findings(since=since):
            try:
                vuln = VulnerabilityCreate(**finding)
                parsed_rows.append((row_num, vuln, None))
            except (ValidationError, Exception) as exc:
                parsed_rows.append((row_num, None, str(exc)))
                fetch_errors += 1
            row_num += 1
    except Exception as exc:
        logger.error("Scanner fetch error for %s: %s", conn.id, exc)
        conn.last_sync_status = "error"
        conn.last_sync_error = str(exc)
        await db.commit()
        return SyncResult(
            connection_id=conn.id,
            status="error",
            ingested=0,
            errors=1,
            message=str(exc),
        )

    ingest_result: IngestionResult = await ingest_batch(db, org_id, parsed_rows)

    conn.last_sync_status = "ok"
    conn.last_sync_at = datetime.now(timezone.utc)
    conn.last_sync_count = ingest_result.ingested
    conn.last_sync_error = None
    await db.commit()

    total_errors = fetch_errors + len(ingest_result.errors)
    return SyncResult(
        connection_id=conn.id,
        status="ok",
        ingested=ingest_result.ingested,
        errors=total_errors,
        message=(
            f"Ingested {ingest_result.ingested} findings, "
            f"{ingest_result.duplicates} duplicates, "
            f"{total_errors} errors."
        ),
    )
