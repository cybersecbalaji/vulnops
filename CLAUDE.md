# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

### Backend (from `backend/`)

```bash
# Run all tests (237 total, no live DB/Redis needed — uses SQLite in-memory + mocked Redis)
pytest

# Run a single test file
pytest tests/test_phase6.py -v

# Run a single test class or test
pytest tests/test_phase8.py::TestAuditLogEndpoint -v
pytest tests/test_phase3.py::TestIngestion::test_csv_upload -v

# Run with coverage
pytest --cov=app --cov-report=term-missing

# Start dev server (requires Postgres + Redis running)
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# Database migrations
alembic upgrade head
alembic downgrade -1
alembic revision --autogenerate -m "description"
```

### Full Stack (Docker)

```bash
# Start infrastructure only
docker compose up -d db redis

# Start everything
docker compose up -d

# API docs: http://localhost:8000/api/docs (DEBUG mode only)
# Frontend: http://localhost:3000
```

### Frontend (from `frontend/`)

```bash
npm run dev
npm run lint
npm run type-check
```

## Architecture Overview

**VulnOps Triage Console** is a multi-tenant vulnerability triage platform: FastAPI backend → PostgreSQL + Redis → Next.js 14 frontend.

```
Next.js 14 (TypeScript · Tailwind · shadcn/ui)  :3000
        ↕ REST API (/api/v1/*)
FastAPI (Python 3.12 · SQLAlchemy 2.0 async)    :8000
        ↕                    ↕
  PostgreSQL 16          Redis 7
  (primary store)        (caching · rate limiting)
```

### Backend Layer Structure

```
app/
  main.py              # App factory: security headers, CORS, exception handlers, routers
  core/
    config.py          # Pydantic Settings (env vars)
    encryption.py      # EncryptedString TypeDecorator + ContextVar encryption context
    security.py        # RS256 JWT (15-min access / 30-day refresh) + bcrypt
    sanitization.py    # Input sanitization pipeline
    clients/           # HTTP clients: CISA KEV, FIRST EPSS, NVD, Jira
    llm/               # LLM abstraction: base.py + factory.py + 4 provider implementations
  db/
    session.py         # Async SQLAlchemy engine + session factory + Redis client
  models/              # SQLAlchemy ORM (Organization, User, Vulnerability, AuditLog, RefreshToken)
  schemas/             # Pydantic request/response schemas per domain
  api/
    deps.py            # FastAPI dependency injection (auth, roles, DB session, encryption ctx)
    routes/            # Endpoint handlers: auth, users, vulnerabilities, org_settings, remediation, reports
  services/            # Business logic (all DB access goes through services, not directly from routes)
    vulnerability.py   # Ingestion (CSV/JSON/manual), deduplication
    enrichment.py      # KEV/EPSS/NVD enrichment with Redis caching
    scoring.py         # Rule-based + LLM triage priority assignment
    remediation.py     # Ticket drafting (Markdown/Jira), bulk triage advice
    reports.py         # Dashboard stats + PDF export
    audit_log.py       # Append-only event logging
tests/
  conftest.py          # Fixtures: SQLite in-memory engine, AsyncClient, mocked Redis
  test_auth.py         # Phase 1 (29 tests)
  test_phase2.py–8.py  # Phases 2–8 (29 tests each)
```

### Critical Design Constraints

**1. Multi-tenancy: every DB query must be scoped to `org_id`.**
Services filter all queries by `org_id`. Never write a service query without this constraint.

**2. Field encryption via `EncryptedString` TypeDecorator.**
Columns prefixed `enc_` (e.g., `enc_title`, `enc_description`) use the custom SQLAlchemy TypeDecorator in `core/encryption.py`. Reading/writing these columns requires an active `encryption_context()` — injected via the `get_org_encryption` FastAPI dependency. Without it, a `RuntimeError` is raised. The ContextVar is async-task-local to prevent cross-request leakage.

**3. All LLM calls must go through the factory.**
Use `create_llm_client(provider, model, api_key)` from `core/llm/factory.py`. Never instantiate provider clients directly. Scoring calls enforce `temperature=0.0` for determinism.

**4. Docs disabled in production.**
`/api/docs` (Swagger UI) is only served when `settings.DEBUG=True`.

### Authentication Model

- **Access token**: RS256 JWT, 15-min TTL, in-memory only (never stored in DB)
- **Refresh token**: 30-day TTL, stored as SHA-256 hash in DB, rotated on every use
- **Roles**: `admin`, `analyst`, `readonly` — enforced via `require_role()` dependency factory in `deps.py`

### Test Fixtures

`tests/conftest.py` provides:
- `test_engine`: session-scoped SQLite in-memory DB (runs all migrations)
- `db_session`: per-test async session
- `mock_redis`: `AsyncMock` — no real Redis needed
- `client`: `AsyncClient` wired to the FastAPI app with SQLite + mocked Redis

Tests are fully isolated — no live Postgres or Redis required.

### Data Flow: Vulnerability Lifecycle

1. **Ingest** (`POST /vulnerabilities/upload`) → parse CSV/JSON → sanitize → deduplicate → store
2. **Enrich** (`POST /vulnerabilities/{id}/enrich`) → query KEV/EPSS/NVD APIs → cache in Redis → update record
3. **Score** (`POST /vulnerabilities/{id}/score`) → LLM triage agent → assigns priority (critical/high/medium/low) + rationale
4. **Remediate** (`POST /remediation/draft`) → LLM drafts ticket (Markdown or Jira format)
5. **Report** (`GET /reports/dashboard`) → aggregated stats; (`GET /reports/export/pdf`) → PDF

---

## Testing Policy

**Every new feature or modification to existing features MUST include corresponding test cases.**

- Tests must be written as part of the same change — a feature is not done until its tests exist and pass.
- Run the full suite after any backend change: `pytest tests/ -q` (from `backend/`).
- Acceptable result: all tests pass with ≤1 failure (known pre-existing auth flake in `test_auth.py::TestTokenRefresh::test_refresh_returns_new_access_token`).
- For new service functions, add tests to the relevant `test_*.py` file (or create a new one following the `test_phase*.py` / `test_assets.py` naming convention).
- For new API routes, add endpoint tests covering: happy path, 404/400 error cases, role/auth enforcement, org-scoping (no cross-tenant data leakage).
- For new CSV parsers or format handlers, add round-trip tests using `csv.DictWriter` helpers (never join values with raw commas — values may contain commas).
- Frontend TypeScript changes must pass `npm run type-check` with zero errors.
