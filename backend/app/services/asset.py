"""
Asset service — CRUD and CSV/JSON bulk import for the asset register.

All public functions take (db, org_id, ...) and filter every query by org_id.
No encryption context required — all asset columns are plaintext.

CSV import supports:
  - Generic VulnOps format (column names match AssetCreate fields)
  - Qualys CMDB export (IP, DNS, OS, Tracking Method columns)
  - ServiceNow CMDB basic export (u_ip_address, u_name, u_environment)
  - Rapid7 InsightVM asset list (Asset IP Address, Asset Name, Asset OS Name)
  - Microsoft Intune / Endpoint Manager (Device name, Serial number, Primary user UPN)
  - Microsoft SCCM (NetBIOS Name, IP Addresses, Resource Domain or Workgroup)
  - Axonius (Name, Hostname, Network Interfaces: IPs, OS.Type)
  - CrowdStrike Falcon (Hostname, Local IP, Device ID, Platform Name)

The importer normalises whichever format it detects, then upserts by
(org_id, ip_address) or (org_id, hostname) to avoid duplicates across runs.
"""

from __future__ import annotations

import csv
import io
import uuid
from dataclasses import dataclass, field
from typing import Any

from pydantic import ValidationError
from sqlalchemy import func, select, update as sql_update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.asset import Asset
from app.schemas.asset import AssetCreate, AssetImportErrorSchema, AssetUpdate

# ── CSV size limit (10 MB) ────────────────────────────────────────────────────
ASSET_CSV_MAX_BYTES = 10 * 1024 * 1024


# ── Import result type ────────────────────────────────────────────────────────

@dataclass
class AssetImportResult:
    imported: int = 0
    updated: int = 0
    skipped: int = 0
    errors: list[AssetImportErrorSchema] = field(default_factory=list)
    assets: list[Asset] = field(default_factory=list)


# ── Column-name normalisation maps ────────────────────────────────────────────

# Generic VulnOps CSV column names (used when no scanner format detected)
_VULNOPS_MAP: dict[str, str] = {
    "name": "name",
    "asset_type": "asset_type",
    "type": "asset_type",
    "criticality": "criticality",
    "environment": "environment",
    "env": "environment",
    "internet_facing": "internet_facing",
    "internet facing": "internet_facing",
    "ip_address": "ip_address",
    "ip": "ip_address",
    "hostname": "hostname",
    "host": "hostname",
    "fqdn": "fqdn",
    "operating_system": "operating_system",
    "os": "operating_system",
    "owner": "owner",
    "team": "owner",
    "tags": "tags",
    "notes": "notes",
    "external_id": "external_id",
}

# Qualys CMDB export column mapping
_QUALYS_MAP: dict[str, str] = {
    "ip": "ip_address",
    "dns": "hostname",
    "netbios": "hostname",          # fallback if dns empty
    "os": "operating_system",
    "asset name": "name",
    "tracking method": "asset_type",
    "tags": "tags",
}
_QUALYS_SENTINEL = {"ip", "dns", "netbios"}

# ServiceNow CMDB basic export
_SERVICENOW_MAP: dict[str, str] = {
    "ip address": "ip_address",
    "u_ip_address": "ip_address",
    "name": "name",
    "u_name": "name",
    "environment": "environment",
    "u_environment": "environment",
    "os": "operating_system",
    "operating system": "operating_system",
    "class": "asset_type",
    "sys_class_name": "asset_type",
    "owned by": "owner",
    "u_owner": "owner",
    "short description": "notes",
}
_SERVICENOW_SENTINEL = {"sys_class_name", "u_ip_address", "u_name"}

# Rapid7 InsightVM asset list export
_RAPID7_MAP: dict[str, str] = {
    "asset ip address": "ip_address",
    "asset name": "name",
    "asset mac address": "external_id",
    "asset os name": "operating_system",
    "asset tags": "tags",
}
_RAPID7_SENTINEL = {"asset ip address", "asset name", "asset os name"}

# Microsoft Intune / Endpoint Manager device export
_INTUNE_MAP: dict[str, str] = {
    "device name": "name",
    "serial number": "external_id",
    "primary user upn": "owner",
    "operating system": "operating_system",
    "os version": "operating_system",   # fallback if no OS column
    "last check-in": "notes",
    "compliance state": "notes",
    "manufacturer": "notes",
    "model": "notes",
    # "device type" intentionally omitted — Intune types ("Laptop", "Desktop", "Mobile")
    # don't map to our ASSET_TYPE_VALUES; all Intune devices default to "endpoint"
}
_INTUNE_SENTINEL = {"device name", "serial number", "primary user upn"}

# Microsoft SCCM (Configuration Manager) export
_SCCM_MAP: dict[str, str] = {
    "netbios name": "name",
    "ip addresses": "ip_address",
    "last logon user name": "owner",
    "operating system name and version": "operating_system",
    "client": "notes",
    "resource domain or workgroup": "notes",
}
_SCCM_SENTINEL = {"netbios name", "resource domain or workgroup"}

# Axonius CSV export
_AXONIUS_MAP: dict[str, str] = {
    "name": "name",
    "hostname": "hostname",
    "network interfaces: ips": "ip_address",
    "os.type": "operating_system",
    "os.distribution": "operating_system",
    "labels": "tags",
    "asset criticality": "criticality",
    "owners": "owner",
    "last seen": "notes",
}
_AXONIUS_SENTINEL = {"network interfaces: ips", "os.type"}

# CrowdStrike Falcon host management export
_CROWDSTRIKE_MAP: dict[str, str] = {
    "hostname": "hostname",
    "local ip": "ip_address",
    "external ip": "fqdn",    # store external IP as fqdn for visibility
    "os version": "operating_system",
    "platform name": "asset_type",
    "tags": "tags",
    "first seen": "notes",
    "last seen": "notes",
    "device id": "external_id",
}
_CROWDSTRIKE_SENTINEL = {"hostname", "device id", "platform name"}


def _detect_format(headers: set[str]) -> str:
    """Detect which CMDB/scanner format the CSV uses."""
    if _RAPID7_SENTINEL.issubset(headers):
        return "rapid7"
    if _QUALYS_SENTINEL.issubset(headers):
        return "qualys"
    if _SERVICENOW_SENTINEL.issubset(headers):
        return "servicenow"
    if _INTUNE_SENTINEL.issubset(headers):
        return "intune"
    if _SCCM_SENTINEL.issubset(headers):
        return "sccm"
    if _AXONIUS_SENTINEL.issubset(headers):
        return "axonius"
    if _CROWDSTRIKE_SENTINEL.issubset(headers):
        return "crowdstrike"
    return "vulnops"


def _normalise_row(raw: dict[str, Any], fmt: str) -> dict[str, Any]:
    """Map raw CSV column names to AssetCreate field names."""
    col_map = {
        "qualys": _QUALYS_MAP,
        "servicenow": _SERVICENOW_MAP,
        "rapid7": _RAPID7_MAP,
        "intune": _INTUNE_MAP,
        "sccm": _SCCM_MAP,
        "axonius": _AXONIUS_MAP,
        "crowdstrike": _CROWDSTRIKE_MAP,
    }.get(fmt, _VULNOPS_MAP)

    normalised: dict[str, Any] = {}
    for raw_key, value in raw.items():
        key = raw_key.strip().lower()
        mapped = col_map.get(key)
        if mapped and value not in (None, ""):
            # Don't overwrite a non-empty value with a fallback
            if mapped not in normalised or not normalised[mapped]:
                normalised[mapped] = value.strip() if isinstance(value, str) else value

    # Qualys: if no explicit name column, build from IP + DNS
    if fmt == "qualys" and "name" not in normalised:
        ip = normalised.get("ip_address", "")
        hn = normalised.get("hostname", "")
        normalised["name"] = hn or ip or "Unknown"

    # Rapid7: ensure name fallback
    if fmt == "rapid7" and not normalised.get("name"):
        normalised["name"] = normalised.get("ip_address") or "Unknown"

    # ServiceNow: ensure name
    if fmt == "servicenow" and not normalised.get("name"):
        normalised["name"] = normalised.get("ip_address") or "Unknown"

    # Intune: endpoints have no IP; set asset_type and environment defaults
    if fmt == "intune":
        normalised.setdefault("asset_type", "endpoint")
        normalised.setdefault("environment", "other")
        if not normalised.get("name"):
            normalised["name"] = normalised.get("external_id") or "Unknown"

    # SCCM: IP Addresses may be space-separated — take the first non-empty value
    if fmt == "sccm":
        ip_raw = normalised.get("ip_address", "")
        if ip_raw and " " in ip_raw:
            first_ip = next((p.strip() for p in ip_raw.split() if p.strip()), ip_raw)
            normalised["ip_address"] = first_ip
        if not normalised.get("name"):
            normalised["name"] = normalised.get("ip_address") or "Unknown"

    # Axonius: Network Interfaces: IPs may be comma-separated — take first
    if fmt == "axonius":
        ip_raw = normalised.get("ip_address", "")
        if ip_raw and "," in ip_raw:
            first_ip = next((p.strip() for p in ip_raw.split(",") if p.strip()), ip_raw)
            normalised["ip_address"] = first_ip
        if not normalised.get("name"):
            normalised["name"] = normalised.get("hostname") or normalised.get("ip_address") or "Unknown"

    # CrowdStrike: ensure name fallback from hostname
    if fmt == "crowdstrike":
        if not normalised.get("name"):
            normalised["name"] = normalised.get("hostname") or normalised.get("ip_address") or "Unknown"

    return normalised


def parse_asset_csv(data: bytes) -> list[tuple[int, AssetCreate | None, str | None]]:
    """
    Parse an asset CSV (any supported format) into AssetCreate objects.

    Returns list of (row_number, parsed | None, error | None).
    """
    if len(data) > ASSET_CSV_MAX_BYTES:
        return [(1, None, f"File too large (max {ASSET_CSV_MAX_BYTES // 1024 // 1024} MB)")]

    text = data.decode("utf-8-sig", errors="replace")
    reader = csv.DictReader(io.StringIO(text))

    if reader.fieldnames is None:
        return [(1, None, "CSV file is empty or has no header row")]

    headers = {h.strip().lower() for h in reader.fieldnames if h}
    fmt = _detect_format(headers)

    results: list[tuple[int, AssetCreate | None, str | None]] = []
    for row_idx, raw_row in enumerate(reader, start=2):
        cleaned_row = {
            k.strip().lower(): (v.strip() if isinstance(v, str) else v)
            for k, v in raw_row.items()
            if k is not None
        }
        normalised = _normalise_row(cleaned_row, fmt)

        if not normalised.get("name") and not normalised.get("ip_address") and not normalised.get("hostname"):
            results.append((row_idx, None, "Row has no name, IP, or hostname — skipped"))
            continue

        try:
            parsed = AssetCreate(**normalised)
            results.append((row_idx, parsed, None))
        except (ValidationError, ValueError) as exc:
            results.append((row_idx, None, str(exc)))

    return results


# ── Core service functions ────────────────────────────────────────────────────

async def create_asset(
    db: AsyncSession,
    org_id: uuid.UUID,
    data: AssetCreate,
) -> Asset:
    """Create a single asset and flush (caller must commit)."""
    asset = Asset(
        org_id=org_id,
        name=data.name,
        asset_type=data.asset_type,
        criticality=data.criticality,
        environment=data.environment,
        internet_facing=data.internet_facing,
        ip_address=data.ip_address,
        hostname=data.hostname,
        fqdn=data.fqdn,
        operating_system=data.operating_system,
        owner=data.owner,
        tags=data.tags,
        notes=data.notes,
        external_id=data.external_id,
    )
    db.add(asset)
    await db.flush()
    return asset


async def get_asset(
    db: AsyncSession,
    org_id: uuid.UUID,
    asset_id: uuid.UUID,
) -> Asset | None:
    """Return an Asset scoped to org_id, or None."""
    result = await db.execute(
        select(Asset).where(Asset.id == asset_id, Asset.org_id == org_id)
    )
    return result.scalar_one_or_none()


async def list_assets(
    db: AsyncSession,
    org_id: uuid.UUID,
    *,
    skip: int = 0,
    limit: int = 50,
    criticality: str | None = None,
    environment: str | None = None,
    internet_facing: bool | None = None,
) -> tuple[list[Asset], int]:
    """Return (items, total_count) with optional filters."""
    filters = [Asset.org_id == org_id]
    if criticality:
        filters.append(Asset.criticality == criticality)
    if environment:
        filters.append(Asset.environment == environment)
    if internet_facing is not None:
        filters.append(Asset.internet_facing == internet_facing)

    count = (await db.execute(
        select(func.count()).select_from(Asset).where(*filters)
    )).scalar_one()

    rows = (await db.execute(
        select(Asset).where(*filters).order_by(Asset.name.asc()).offset(skip).limit(limit)
    )).scalars().all()

    return list(rows), count


async def update_asset(
    db: AsyncSession,
    org_id: uuid.UUID,
    asset_id: uuid.UUID,
    data: AssetUpdate,
) -> Asset | None:
    """Partially update an asset.  Returns None if not found."""
    asset = await get_asset(db, org_id, asset_id)
    if asset is None:
        return None

    for field_name, value in data.model_dump(exclude_unset=True).items():
        setattr(asset, field_name, value)

    await db.flush()
    return asset


async def delete_asset(
    db: AsyncSession,
    org_id: uuid.UUID,
    asset_id: uuid.UUID,
) -> bool:
    """Delete an asset.  Returns True if deleted."""
    asset = await get_asset(db, org_id, asset_id)
    if asset is None:
        return False
    await db.delete(asset)
    await db.flush()
    return True


async def import_assets_csv(
    db: AsyncSession,
    org_id: uuid.UUID,
    parsed_rows: list[tuple[int, AssetCreate | None, str | None]],
) -> AssetImportResult:
    """
    Upsert a batch of assets.  Dedup strategy:
      1. Match by (org_id, ip_address) if ip_address is present.
      2. Otherwise match by (org_id, hostname).
      3. Otherwise match by (org_id, external_id).
      4. No match → create new asset.

    Existing assets are updated in-place (fields overwritten with new values).
    """
    result = AssetImportResult()

    # Collect parse errors
    valid_rows: list[tuple[int, AssetCreate]] = []
    for row_num, parsed, error in parsed_rows:
        if error:
            result.errors.append(AssetImportErrorSchema(row=row_num, name=None, error=error))
        else:
            valid_rows.append((row_num, parsed))  # type: ignore[arg-type]

    if not valid_rows:
        return result

    # Pre-fetch existing assets keyed by ip/hostname/external_id for dedup
    existing_ip: dict[str, Asset] = {}
    existing_hostname: dict[str, Asset] = {}
    existing_extid: dict[str, Asset] = {}

    all_assets = (await db.execute(
        select(Asset).where(Asset.org_id == org_id)
    )).scalars().all()

    for a in all_assets:
        if a.ip_address:
            existing_ip[a.ip_address] = a
        if a.hostname:
            existing_hostname[a.hostname.lower()] = a
        if a.external_id:
            existing_extid[a.external_id] = a

    for row_num, data in valid_rows:
        existing: Asset | None = None

        if data.ip_address and data.ip_address in existing_ip:
            existing = existing_ip[data.ip_address]
        elif data.hostname and data.hostname.lower() in existing_hostname:
            existing = existing_hostname[data.hostname.lower()]
        elif data.external_id and data.external_id in existing_extid:
            existing = existing_extid[data.external_id]

        if existing:
            # Update existing record
            for f, v in data.model_dump(exclude_unset=False).items():
                if v is not None:
                    setattr(existing, f, v)
            await db.flush()
            result.updated += 1
            result.assets.append(existing)
        else:
            # Create new
            asset = await create_asset(db, org_id, data)
            # Register in dedup maps for within-batch dedup
            if data.ip_address:
                existing_ip[data.ip_address] = asset
            if data.hostname:
                existing_hostname[data.hostname.lower()] = asset
            if data.external_id:
                existing_extid[data.external_id] = asset
            result.imported += 1
            result.assets.append(asset)

    return result


async def match_vulnerabilities_to_assets(
    db: AsyncSession,
    org_id: uuid.UUID,
    vuln_ids: list[uuid.UUID] | None = None,
) -> int:
    """
    Match vulnerabilities to assets by comparing affected_component against
    known asset IP addresses and hostnames.

    For each vulnerability whose affected_component contains an IP or hostname
    that matches a registered asset, sets vuln.asset_id to that asset's ID.

    Args:
        db: Async database session.
        org_id: Scope all queries to this org.
        vuln_ids: If given, only process these specific vulnerability IDs.
                  When None, processes all unmatched vulns for the org.

    Returns:
        Number of vulnerabilities that were linked to an asset.
    """
    from app.models.vulnerability import Vulnerability

    # Load all assets for the org (indexed by ip and hostname)
    assets_result = await db.execute(
        select(Asset.id, Asset.ip_address, Asset.hostname, Asset.fqdn)
        .where(Asset.org_id == org_id)
    )
    asset_rows = assets_result.all()

    # Build lookup: ip/hostname → asset_id
    ip_to_asset: dict[str, uuid.UUID] = {}
    host_to_asset: dict[str, uuid.UUID] = {}
    for row in asset_rows:
        if row.ip_address:
            ip_to_asset[row.ip_address.strip()] = row.id
        if row.hostname:
            host_to_asset[row.hostname.strip().lower()] = row.id
        if row.fqdn:
            host_to_asset[row.fqdn.strip().lower()] = row.id

    if not ip_to_asset and not host_to_asset:
        return 0

    # Load vulnerabilities to match
    vuln_query = select(
        Vulnerability.id, Vulnerability.enc_affected_component
    ).where(
        Vulnerability.org_id == org_id,
        Vulnerability.asset_id.is_(None),   # only unmatched
    )
    if vuln_ids:
        vuln_query = vuln_query.where(Vulnerability.id.in_(vuln_ids))

    vuln_rows = (await db.execute(vuln_query)).all()

    matched = 0
    for vuln_id, affected_component in vuln_rows:
        if not affected_component:
            continue

        # affected_component may be "10.0.0.5:443" or "hostname:port"
        # Strip port suffix for matching
        base = affected_component.split(":")[0].strip()
        if not base:
            continue

        asset_id: uuid.UUID | None = (
            ip_to_asset.get(base)
            or host_to_asset.get(base.lower())
        )

        if asset_id:
            await db.execute(
                sql_update(Vulnerability)
                .where(Vulnerability.id == vuln_id, Vulnerability.org_id == org_id)
                .values(asset_id=asset_id)
            )
            matched += 1

    return matched
