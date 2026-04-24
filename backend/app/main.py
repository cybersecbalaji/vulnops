"""
VulnOps Triage Console — FastAPI application entry point.

Security controls applied at this layer:
- CORS: restricted to configured origins, credentials allowed (for cookies)
- Security headers middleware (HSTS, CSP, X-Frame-Options, etc.)
- Global exception handlers (never leak stack traces to clients)
- Docs disabled in production
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.api.routes import assets, auth, org_settings, remediation, reports, scanner_connections, users, vulnerabilities
from app.core.config import settings
from app.db.session import AsyncSessionLocal, engine, get_db, redis_client
import app.models  # noqa: F401 — ensures all ORM models register with Base.metadata


# ── Lifespan ──────────────────────────────────────────────────────────────────

async def _scheduled_sync_all() -> None:
    """APScheduler job: sync every enabled scanner connection across all orgs."""
    import logging
    import json
    from sqlalchemy import select
    from app.core.encryption import FieldEncryption, MasterKeyEncryption, encryption_context
    from app.db.session import AsyncSessionLocal
    from app.models.organization import Organization
    from app.models.scanner_connection import ScannerConnection
    from app.services.scanner_connection import run_sync

    log = logging.getLogger("vulnops.scheduler")

    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(ScannerConnection).where(ScannerConnection.enabled == True)  # noqa: E712
        )
        connections = result.scalars().all()

    master = MasterKeyEncryption(settings.MASTER_ENCRYPTION_KEY)

    for conn in connections:
        async with AsyncSessionLocal() as db:
            try:
                org_result = await db.execute(
                    select(Organization).where(Organization.id == conn.org_id)
                )
                org = org_result.scalar_one_or_none()
                if org is None:
                    continue
                dek = master.decrypt_dek(org.encrypted_dek)
                field_enc = FieldEncryption(dek)
                with encryption_context(field_enc):
                    # Re-fetch conn inside the new session
                    fresh = await db.get(ScannerConnection, conn.id)
                    if fresh is None:
                        continue
                    await run_sync(db, conn.org_id, fresh, since=fresh.last_sync_at)
                    log.info("Scheduled sync complete for connection %s", conn.id)
            except Exception as exc:
                log.error("Scheduled sync failed for connection %s: %s", conn.id, exc)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    # Startup: verify Redis is reachable
    await redis_client.ping()

    scheduler = None
    if settings.SCHEDULER_ENABLED:
        try:
            from apscheduler.schedulers.asyncio import AsyncIOScheduler
            scheduler = AsyncIOScheduler()
            scheduler.add_job(
                _scheduled_sync_all,
                "interval",
                hours=settings.SCHEDULER_SYNC_INTERVAL_HOURS,
                id="scanner_sync_all",
                replace_existing=True,
            )
            scheduler.start()
        except ImportError:
            import logging
            logging.getLogger("vulnops").warning(
                "apscheduler not installed — SCHEDULER_ENABLED=true has no effect"
            )

    yield

    if scheduler is not None:
        scheduler.shutdown(wait=False)

    # Shutdown: close connections
    await engine.dispose()
    await redis_client.aclose()


# ── Application factory ───────────────────────────────────────────────────────

def create_app() -> FastAPI:
    app = FastAPI(
        title="VulnOps Triage Console API",
        version="1.0.0",
        description="Vulnerability operations triage platform — Phase 1: Auth",
        # Disable interactive docs in production to reduce attack surface
        docs_url="/api/docs" if settings.DEBUG else None,
        redoc_url="/api/redoc" if settings.DEBUG else None,
        openapi_url="/api/openapi.json" if settings.DEBUG else None,
        lifespan=lifespan,
    )

    _add_security_headers(app)
    _add_cors(app)
    _add_exception_handlers(app)
    _add_routes(app)

    return app


# ── Security headers middleware ───────────────────────────────────────────────

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Adds security headers to every response per PRD §Encryption in Transit.
    HSTS with 1-year max-age is enforced as required.
    """

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        # PRD mandatory: HSTS 1-year max-age
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains; preload"
        )
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), interest-cohort=()"
        )
        # Content Security Policy — tightened for an API (no HTML served here)
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; frame-ancestors 'none'"
        )
        # Remove server fingerprinting (suppress "server" header if present)
        if "server" in response.headers:
            del response.headers["server"]
        return response


def _add_security_headers(app: FastAPI) -> None:
    app.add_middleware(SecurityHeadersMiddleware)


def _add_cors(app: FastAPI) -> None:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,   # Required for HttpOnly refresh-token cookie
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
        expose_headers=["X-Request-ID"],
    )


# ── Exception handlers ────────────────────────────────────────────────────────

def _add_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        # Return structured validation errors without stack traces
        errors = []
        for error in exc.errors():
            field = " → ".join(str(loc) for loc in error.get("loc", []))
            errors.append({"field": field, "message": error["msg"]})
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={"detail": errors},
        )

    @app.exception_handler(Exception)
    async def generic_error_handler(request: Request, exc: Exception) -> JSONResponse:
        # Never leak internal details to clients
        import logging
        logging.getLogger("vulnops").exception("Unhandled exception", exc_info=exc)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": "An internal server error occurred."},
        )


# ── Routes ────────────────────────────────────────────────────────────────────

def _add_routes(app: FastAPI) -> None:
    app.include_router(
        auth.router,
        prefix=f"{settings.API_V1_STR}/auth",
        tags=["Authentication"],
    )
    app.include_router(
        assets.router,
        prefix=f"{settings.API_V1_STR}/assets",
        tags=["Assets"],
    )
    app.include_router(
        users.router,
        prefix=f"{settings.API_V1_STR}/users",
        tags=["User Management"],
    )
    app.include_router(
        vulnerabilities.router,
        prefix=f"{settings.API_V1_STR}/vulnerabilities",
        tags=["Vulnerabilities"],
    )
    app.include_router(
        org_settings.router,
        prefix=f"{settings.API_V1_STR}/org",
        tags=["Org Settings"],
    )
    app.include_router(
        remediation.router,
        prefix=f"{settings.API_V1_STR}/remediation",
        tags=["Remediation"],
    )
    app.include_router(
        reports.router,
        prefix=f"{settings.API_V1_STR}/reports",
        tags=["Reports"],
    )
    app.include_router(
        scanner_connections.router,
        prefix=f"{settings.API_V1_STR}/scanner-connections",
        tags=["Scanner Connections"],
    )

    @app.get("/health", tags=["Health"])
    async def health_check() -> dict:
        return {"status": "ok", "service": "vulnops-api"}

    @app.get("/ready", tags=["Health"])
    async def readiness_check() -> dict:
        """Readiness probe: verifies DB and Redis are reachable."""
        checks: dict[str, str] = {}
        ok = True

        try:
            async for db in get_db():
                from sqlalchemy import text
                await db.execute(text("SELECT 1"))
            checks["db"] = "ok"
        except Exception as exc:
            checks["db"] = f"error: {exc}"
            ok = False

        try:
            await redis_client.ping()
            checks["redis"] = "ok"
        except Exception as exc:
            checks["redis"] = f"error: {exc}"
            ok = False

        from fastapi.responses import JSONResponse
        return JSONResponse(
            status_code=200 if ok else 503,
            content={"status": "ready" if ok else "not ready", "checks": checks},
        )


# ── Module-level app instance ─────────────────────────────────────────────────

app = create_app()
