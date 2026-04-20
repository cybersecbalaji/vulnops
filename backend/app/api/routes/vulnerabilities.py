"""
Vulnerability ingestion and management endpoints.

All routes require an authenticated user.  The get_org_encryption dependency
installs the encryption context for the request, so EncryptedString columns
are transparently encrypted on write and decrypted on read.

Endpoints:
  POST   /vulnerabilities/              — create a single vulnerability (manual)
  POST   /vulnerabilities/ingest/csv   — bulk ingest from CSV upload
  POST   /vulnerabilities/ingest/json  — bulk ingest from JSON upload
  GET    /vulnerabilities/              — list (paginated, filterable)
  GET    /vulnerabilities/{id}          — get single
  PATCH  /vulnerabilities/{id}          — partial update
  DELETE /vulnerabilities/{id}          — delete (admin only)
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, status
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession

import redis.asyncio as aioredis

from app.api.deps import get_current_user, get_llm_client, get_org_encryption, require_role
from app.core.encryption import FieldEncryption
from app.db.session import get_db, get_redis
from app.models.user import User
from app.schemas.vulnerability import (
    EnrichmentResultSchema,
    IngestionErrorSchema,
    IngestionResultSchema,
    ScoringResultSchema,
    VulnerabilityCreate,
    VulnerabilityListResponse,
    VulnerabilityResponse,
    VulnerabilityUpdate,
)
from app.core.llm.base import LLMClient
from app.services.enrichment import (
    EnrichmentResult,
    enrich_vulnerabilities,
    vulnerability_exists,
)
from app.services.scoring import BulkScoringResult, score_vulnerabilities
from app.services.audit_log import log_event
from app.services.vulnerability import (
    IngestionError,
    IngestionResult,
    delete_vulnerability,
    get_vulnerability,
    ingest_batch,
    list_vulnerabilities,
    parse_csv_bytes,
    parse_json_bytes,
    update_vulnerability,
)
from app.services.scanner_parsers import (
    parse_nessus_xml,
    parse_qualys_csv,
    parse_rapid7_csv,
    parse_tenable_csv,
)

router = APIRouter()


# ── Helpers ───────────────────────────────────────────────────────────────────

def _to_scoring_schema(result: BulkScoringResult) -> ScoringResultSchema:
    return ScoringResultSchema(scored=result.scored, errors=result.errors)


def _to_enrichment_schema(result: EnrichmentResult) -> EnrichmentResultSchema:
    return EnrichmentResultSchema(
        enriched=result.enriched,
        kev_updated=result.kev_updated,
        epss_updated=result.epss_updated,
        cvss_updated=result.cvss_updated,
        published_at_updated=result.published_at_updated,
        errors=result.errors,
    )


def _to_schema(result: IngestionResult) -> IngestionResultSchema:
    return IngestionResultSchema(
        ingested=result.ingested,
        duplicates=result.duplicates,
        errors=[
            IngestionErrorSchema(row=e.row, cve_id=e.cve_id, error=e.error)
            for e in result.errors
        ],
        vulnerabilities=[VulnerabilityResponse.model_validate(v) for v in result.vulnerabilities],
    )


# ── Ingestion endpoints ───────────────────────────────────────────────────────

@router.post(
    "/",
    response_model=VulnerabilityResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_vulnerability(
    data: VulnerabilityCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    _enc: FieldEncryption = Depends(get_org_encryption),
) -> VulnerabilityResponse:
    """
    Create a single vulnerability via manual entry.

    The request body must pass schema validation (CVE ID format, severity enum,
    text sanitization).  Deduplication is applied — if the same CVE already
    exists for this org, is_duplicate is set to True on the new record.
    """
    parsed_rows = [(1, data, None)]
    result = await ingest_batch(db, current_user.org_id, parsed_rows)

    if result.errors:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=result.errors[0].error,
        )

    vuln = result.vulnerabilities[0]
    await log_event(
        db,
        org_id=current_user.org_id,
        user_id=current_user.id,
        action="vulnerability.created",
        resource_type="vulnerability",
        resource_id=str(vuln.id),
        details={"cve_id": vuln.cve_id, "source": "manual"},
    )
    await db.commit()
    return VulnerabilityResponse.model_validate(vuln)


@router.post(
    "/ingest/csv",
    response_model=IngestionResultSchema,
    status_code=status.HTTP_200_OK,
)
async def ingest_csv(
    file: UploadFile,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    _enc: FieldEncryption = Depends(get_org_encryption),
) -> IngestionResultSchema:
    """
    Bulk-ingest vulnerabilities from a CSV file.

    The CSV must have a header row.  Required columns: cve_id, title,
    description, severity.  Optional: affected_component, notes,
    remediation_advice, cvss_score, epss_score, source_id.

    Maximum file size: 50 MB.  All text fields pass through the sanitization
    pipeline.  Rows that fail validation are included in the errors list;
    valid rows are ingested even when some rows error.
    """
    try:
        raw = await file.read()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Could not read uploaded file: {exc}",
        )

    try:
        parsed_rows = parse_csv_bytes(raw, source="csv")
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    result = await ingest_batch(db, current_user.org_id, parsed_rows)
    await db.commit()
    return _to_schema(result)


@router.post(
    "/ingest/json",
    response_model=IngestionResultSchema,
    status_code=status.HTTP_200_OK,
)
async def ingest_json(
    file: UploadFile,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    _enc: FieldEncryption = Depends(get_org_encryption),
) -> IngestionResultSchema:
    """
    Bulk-ingest vulnerabilities from a JSON file.

    The JSON body must be an array of vulnerability objects with the same
    fields as the manual-create endpoint.  Maximum file size: 20 MB.
    """
    try:
        raw = await file.read()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Could not read uploaded file: {exc}",
        )

    try:
        parsed_rows = parse_json_bytes(raw, source="json")
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    result = await ingest_batch(db, current_user.org_id, parsed_rows)
    await db.commit()
    return _to_schema(result)


# ── Scanner ingestion endpoints ───────────────────────────────────────────────

async def _ingest_scanner(
    file: UploadFile,
    parser,
    db: AsyncSession,
    org_id,
) -> IngestionResultSchema:
    """Shared helper: read upload, parse, ingest, return schema."""
    try:
        raw = await file.read()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Could not read uploaded file: {exc}",
        )
    try:
        parsed_rows = parser(raw)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    result = await ingest_batch(db, org_id, parsed_rows)
    await db.commit()
    return _to_schema(result)


@router.post(
    "/ingest/tenable",
    response_model=IngestionResultSchema,
    status_code=status.HTTP_200_OK,
)
async def ingest_tenable(
    file: UploadFile,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    _enc: FieldEncryption = Depends(get_org_encryption),
) -> IngestionResultSchema:
    """
    Ingest vulnerabilities from a Tenable.io / Tenable.sc CSV export.

    The CSV must be the standard Tenable vulnerability export.  Rows without
    a CVE ID (non-CVE plugins) are skipped and reported in the errors list.
    """
    return await _ingest_scanner(file, parse_tenable_csv, db, current_user.org_id)


@router.post(
    "/ingest/nessus",
    response_model=IngestionResultSchema,
    status_code=status.HTTP_200_OK,
)
async def ingest_nessus(
    file: UploadFile,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    _enc: FieldEncryption = Depends(get_org_encryption),
) -> IngestionResultSchema:
    """
    Ingest vulnerabilities from a Nessus .nessus XML file.

    Accepts the .nessus XML format exported by Nessus Professional or
    Tenable.sc.  Each ReportItem with a CVE ID becomes one finding.
    """
    return await _ingest_scanner(file, parse_nessus_xml, db, current_user.org_id)


@router.post(
    "/ingest/qualys",
    response_model=IngestionResultSchema,
    status_code=status.HTTP_200_OK,
)
async def ingest_qualys(
    file: UploadFile,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    _enc: FieldEncryption = Depends(get_org_encryption),
) -> IngestionResultSchema:
    """
    Ingest vulnerabilities from a Qualys VMDR CSV export.

    Accepts the standard Qualys vulnerability export CSV.  Findings without
    a CVE ID (QIDs with no associated CVE) are skipped.
    """
    return await _ingest_scanner(file, parse_qualys_csv, db, current_user.org_id)


@router.post(
    "/ingest/rapid7",
    response_model=IngestionResultSchema,
    status_code=status.HTTP_200_OK,
)
async def ingest_rapid7(
    file: UploadFile,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    _enc: FieldEncryption = Depends(get_org_encryption),
) -> IngestionResultSchema:
    """
    Ingest vulnerabilities from a Rapid7 InsightVM / Nexpose CSV export.

    Accepts the standard vulnerability export from InsightVM or Nexpose.
    Rows without a CVE ID are skipped.
    """
    return await _ingest_scanner(file, parse_rapid7_csv, db, current_user.org_id)


# ── Read endpoints ────────────────────────────────────────────────────────────

@router.get("/", response_model=VulnerabilityListResponse)
async def list_vulns(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    severity: str | None = Query(default=None),
    status: str | None = Query(default=None, alias="status"),
    include_duplicates: bool = Query(default=False),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    _enc: FieldEncryption = Depends(get_org_encryption),
) -> VulnerabilityListResponse:
    """
    List vulnerabilities for the current org.

    Supports pagination (page / page_size) and filtering by severity and
    status.  By default, rows marked as duplicates are hidden; pass
    include_duplicates=true to include them.
    """
    skip = (page - 1) * page_size
    vulns, total = await list_vulnerabilities(
        db,
        current_user.org_id,
        skip=skip,
        limit=page_size,
        severity=severity,
        status=status,
        include_duplicates=include_duplicates,
    )
    return VulnerabilityListResponse(
        items=[VulnerabilityResponse.model_validate(v) for v in vulns],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/{vuln_id}", response_model=VulnerabilityResponse)
async def get_vuln(
    vuln_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    _enc: FieldEncryption = Depends(get_org_encryption),
) -> VulnerabilityResponse:
    """Retrieve a single vulnerability.  Returns 404 if not found or wrong org."""
    vuln = await get_vulnerability(db, current_user.org_id, vuln_id)
    if vuln is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vulnerability not found.")
    return VulnerabilityResponse.model_validate(vuln)


# ── Mutation endpoints ────────────────────────────────────────────────────────

@router.patch("/{vuln_id}", response_model=VulnerabilityResponse)
async def patch_vuln(
    vuln_id: uuid.UUID,
    data: VulnerabilityUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    _enc: FieldEncryption = Depends(get_org_encryption),
) -> VulnerabilityResponse:
    """Partially update a vulnerability.  Only supplied fields are changed."""
    vuln = await update_vulnerability(db, current_user.org_id, vuln_id, data)
    if vuln is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vulnerability not found.")
    await db.commit()
    return VulnerabilityResponse.model_validate(vuln)


# ── Scoring endpoints ─────────────────────────────────────────────────────────

@router.post(
    "/score",
    response_model=ScoringResultSchema,
    status_code=status.HTTP_200_OK,
)
async def score_all_vulns(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    _enc: FieldEncryption = Depends(get_org_encryption),
    llm: LLMClient = Depends(get_llm_client),
) -> ScoringResultSchema:
    """
    Score all non-duplicate org vulnerabilities with the configured LLM.

    Each vulnerability receives a ``triage_priority`` ("immediate" | "this_week" |
    "this_month" | "monitor" | "accept") and an encrypted LLM rationale.
    Scoring uses temperature=0.0 for deterministic results.

    The encryption context is required to read encrypted vulnerability text
    for the LLM prompt and to re-encrypt the rationale before storage.
    """
    result = await score_vulnerabilities(db, llm, current_user.org_id)
    await db.commit()
    return _to_scoring_schema(result)


@router.post(
    "/{vuln_id}/score",
    response_model=VulnerabilityResponse,
    status_code=status.HTTP_200_OK,
)
async def score_single_vuln(
    vuln_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    _enc: FieldEncryption = Depends(get_org_encryption),
    llm: LLMClient = Depends(get_llm_client),
) -> VulnerabilityResponse:
    """
    Score a single vulnerability and return the updated record.

    Returns 404 if the vulnerability is not found or belongs to a different org.
    """
    if not await vulnerability_exists(db, current_user.org_id, vuln_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Vulnerability not found.",
        )
    result = await score_vulnerabilities(
        db, llm, current_user.org_id, vuln_ids=[vuln_id]
    )
    await db.commit()

    if result.errors:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=result.errors[0],
        )

    vuln = await get_vulnerability(db, current_user.org_id, vuln_id)
    return VulnerabilityResponse.model_validate(vuln)


# ── Enrichment endpoints ──────────────────────────────────────────────────────

@router.post(
    "/enrich",
    response_model=EnrichmentResultSchema,
    status_code=status.HTTP_200_OK,
)
async def enrich_all_vulns(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    redis: aioredis.Redis = Depends(get_redis),
) -> EnrichmentResultSchema:
    """
    Enrich all non-duplicate vulnerabilities for the current org.

    Fetches the CISA KEV catalog, EPSS scores, and NVD CVE details for every
    canonical (non-duplicate) vulnerability and updates the database.  Results
    are cached in Redis so repeated calls within the cache window are cheap.

    Returns counts of updated fields and any non-fatal errors encountered.
    No encryption context is required — only plaintext columns are touched.
    """
    result = await enrich_vulnerabilities(db, redis, current_user.org_id)
    await db.commit()
    return _to_enrichment_schema(result)


@router.post(
    "/{vuln_id}/enrich",
    response_model=EnrichmentResultSchema,
    status_code=status.HTTP_200_OK,
)
async def enrich_single_vuln(
    vuln_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    redis: aioredis.Redis = Depends(get_redis),
) -> EnrichmentResultSchema:
    """
    Enrich a single vulnerability with KEV, EPSS, and NVD data.

    Returns 404 if the vulnerability does not exist or belongs to a different org.
    """
    if not await vulnerability_exists(db, current_user.org_id, vuln_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Vulnerability not found.",
        )
    result = await enrich_vulnerabilities(
        db, redis, current_user.org_id, vuln_ids=[vuln_id], skip_duplicates=False
    )
    await db.commit()
    return _to_enrichment_schema(result)


@router.delete("/{vuln_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_vuln(
    vuln_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    _enc: FieldEncryption = Depends(get_org_encryption),
) -> Response:
    """Delete a vulnerability.  Admin role required."""
    # Inline role check — more reliable than Depends(require_role()) when a
    # generator dependency (_enc) is also in scope.
    if current_user.role not in ("admin",):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This action requires one of the following roles: admin.",
        )
    deleted = await delete_vulnerability(db, current_user.org_id, vuln_id)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vulnerability not found.")
    await log_event(
        db,
        org_id=current_user.org_id,
        user_id=current_user.id,
        action="vulnerability.deleted",
        resource_type="vulnerability",
        resource_id=str(vuln_id),
    )
    await db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
