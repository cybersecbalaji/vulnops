"""
Asset register endpoints.

All routes require an authenticated user; mutations require analyst or admin.
DELETE requires admin.

Endpoints:
  POST   /assets/             — create single asset
  POST   /assets/import/csv   — bulk import (VulnOps / Qualys / ServiceNow / Rapid7)
  GET    /assets/             — list (paginated, filterable)
  GET    /assets/{id}         — get single
  PATCH  /assets/{id}         — partial update
  DELETE /assets/{id}         — delete (admin only)
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, status
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_org_encryption, require_role
from app.db.session import get_db
from app.models.user import User
from app.schemas.asset import (
    AssetCreate,
    AssetImportResultSchema,
    AssetListResponse,
    AssetResponse,
    AssetUpdate,
    AssetImportErrorSchema,
)
from app.services.asset import (
    AssetImportResult,
    create_asset,
    delete_asset,
    get_asset,
    import_assets_csv,
    list_assets,
    match_vulnerabilities_to_assets,
    parse_asset_csv,
    update_asset,
)

router = APIRouter()


def _to_import_schema(result: AssetImportResult) -> AssetImportResultSchema:
    return AssetImportResultSchema(
        imported=result.imported,
        updated=result.updated,
        skipped=result.skipped,
        errors=result.errors,
        assets=[AssetResponse.model_validate(a) for a in result.assets],
    )


# ── Create ────────────────────────────────────────────────────────────────────

@router.post("/", response_model=AssetResponse, status_code=status.HTTP_201_CREATED)
async def create_asset_endpoint(
    data: AssetCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("admin", "analyst")),
) -> AssetResponse:
    """Create a single asset."""
    asset = await create_asset(db, current_user.org_id, data)
    await db.commit()
    return AssetResponse.model_validate(asset)


# ── Bulk import ───────────────────────────────────────────────────────────────

@router.post("/import/csv", response_model=AssetImportResultSchema)
async def import_assets_csv_endpoint(
    file: UploadFile,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("admin", "analyst")),
) -> AssetImportResultSchema:
    """
    Bulk-import assets from a CSV file.

    Supported formats (auto-detected):
    - **VulnOps generic** — columns match AssetCreate field names
    - **Qualys CMDB** — IP, DNS, NetBIOS, OS, Tracking Method columns
    - **ServiceNow CMDB** — sys_class_name, u_ip_address, u_name, u_environment
    - **Rapid7 InsightVM** — Asset IP Address, Asset Name, Asset OS Name columns
    - **Microsoft Intune** — Device name, Serial number, Primary user UPN columns
    - **Microsoft SCCM** — NetBIOS Name, IP Addresses, Resource Domain or Workgroup
    - **Axonius** — Name, Hostname, Network Interfaces: IPs, OS.Type columns
    - **CrowdStrike Falcon** — Hostname, Local IP, Device ID, Platform Name columns

    Assets are upserted: existing records matched by IP or hostname are updated
    rather than duplicated.  Maximum file size: 10 MB.
    """
    try:
        raw = await file.read()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Could not read uploaded file: {exc}",
        )

    try:
        parsed_rows = parse_asset_csv(raw)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    result = await import_assets_csv(db, current_user.org_id, parsed_rows)
    await db.commit()
    return _to_import_schema(result)


# ── Read ──────────────────────────────────────────────────────────────────────

@router.get("/", response_model=AssetListResponse)
async def list_assets_endpoint(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    criticality: str | None = Query(default=None),
    environment: str | None = Query(default=None),
    internet_facing: bool | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AssetListResponse:
    """List assets for the current org with optional filters."""
    skip = (page - 1) * page_size
    assets, total = await list_assets(
        db,
        current_user.org_id,
        skip=skip,
        limit=page_size,
        criticality=criticality,
        environment=environment,
        internet_facing=internet_facing,
    )
    return AssetListResponse(
        items=[AssetResponse.model_validate(a) for a in assets],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/{asset_id}", response_model=AssetResponse)
async def get_asset_endpoint(
    asset_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AssetResponse:
    """Get a single asset. Returns 404 if not found."""
    asset = await get_asset(db, current_user.org_id, asset_id)
    if asset is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found.")
    return AssetResponse.model_validate(asset)


# ── Update ────────────────────────────────────────────────────────────────────

@router.patch("/{asset_id}", response_model=AssetResponse)
async def patch_asset_endpoint(
    asset_id: uuid.UUID,
    data: AssetUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("admin", "analyst")),
) -> AssetResponse:
    """Partially update an asset."""
    asset = await update_asset(db, current_user.org_id, asset_id, data)
    if asset is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found.")
    await db.commit()
    return AssetResponse.model_validate(asset)


# ── Vulnerability matching ────────────────────────────────────────────────────

class MatchResult(BaseModel):
    matched: int


@router.post("/match-vulnerabilities", response_model=MatchResult)
async def match_vulns_to_assets(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("admin", "analyst")),
    _enc=Depends(get_org_encryption),
) -> MatchResult:
    """
    Auto-match unlinked vulnerabilities to assets by IP / hostname.

    Scans all vulnerabilities whose `affected_component` field contains an IP
    address or hostname matching a registered asset.  Sets `asset_id` on each
    matched vulnerability.  Safe to call multiple times — only unmatched vulns
    are processed.

    Returns the count of newly linked vulnerabilities.
    """
    matched = await match_vulnerabilities_to_assets(db, current_user.org_id)
    await db.commit()
    return MatchResult(matched=matched)


# ── Delete ────────────────────────────────────────────────────────────────────

@router.delete("/{asset_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_asset_endpoint(
    asset_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
) -> Response:
    """Delete an asset. Admin role required."""
    deleted = await delete_asset(db, current_user.org_id, asset_id)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found.")
    await db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
