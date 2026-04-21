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

from app.api.routes import assets, auth, org_settings, remediation, reports, users, vulnerabilities
from app.core.config import settings
from app.db.session import engine, redis_client
import app.models  # noqa: F401 — ensures all ORM models register with Base.metadata


# ── Lifespan ──────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    # Startup: verify Redis is reachable
    await redis_client.ping()
    yield
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
        # Prevent trailing-slash 308 redirects from leaking internal URLs through the proxy
        redirect_slashes=False,
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

    @app.get("/health", tags=["Health"])
    async def health_check() -> dict:
        return {"status": "ok", "service": "vulnops-api"}


# ── Module-level app instance ─────────────────────────────────────────────────

app = create_app()
