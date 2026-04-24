# VulnOps Triage Console

An open-source vulnerability triage platform for security operations teams. Ingest CVEs from scanner APIs or file uploads; enrich with KEV, EPSS, and NVD data; score with an LLM-powered triage agent; draft remediation tickets; export PDF reports — all with per-org field encryption, multi-tenancy, and a full audit log.

> **Experimental side project** — Apache 2.0. Free forever, no hosted edition, no lock-in.

```
https://github.com/cybersecbalaji/vulnops
```

---

## Table of Contents

- [Architecture](#architecture)
- [Features](#features)
- [Quick Setup (5 minutes)](#quick-setup-5-minutes)
- [Environment Variables](#environment-variables)
- [Running with Docker](#running-with-docker)
- [Running Locally (Without Docker)](#running-locally-without-docker)
- [Scanner API Connectors](#scanner-api-connectors)
- [Scheduled Sync](#scheduled-sync)
- [Database Migrations](#database-migrations)
- [Deploying Online](#deploying-online)
- [Running Tests](#running-tests)
- [API Reference](#api-reference)
- [LLM Provider Configuration](#llm-provider-configuration)
- [Security Model](#security-model)
- [Project Structure](#project-structure)

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                   Next.js 14 Frontend                │
│         (TypeScript · Tailwind · shadcn/ui)          │
│                   localhost:3000                     │
└──────────────────────────┬──────────────────────────┘
                           │ REST API (/api/v1/*)
┌──────────────────────────▼──────────────────────────┐
│                  FastAPI Backend                      │
│             (Python 3.12 · SQLAlchemy 2.0)           │
│                   localhost:8000                     │
└──────┬────────────────────────────────┬─────────────┘
       │                                │
┌──────▼──────┐                ┌────────▼────────┐
│ PostgreSQL  │                │   Redis 7        │
│     16      │                │  (cache + rate   │
│  (primary   │                │   limiting)      │
│   store)    │                └─────────────────-┘
└─────────────┘
```

**Stack:** Next.js 14 · FastAPI · PostgreSQL 16 · Redis 7 · Fernet encryption · APScheduler · fpdf2 · Recharts

---

## Features

| Area | Feature |
|------|---------|
| **Auth** | RS256 JWT (15-min access tokens) · refresh token rotation · multi-org · RBAC (admin / analyst / readonly) |
| **Encryption** | Per-org Fernet DEK · `EncryptedString` TypeDecorator · ContextVar isolation per request |
| **Ingestion** | CSV, JSON, manual entry · deduplication · scanner API connectors (pull, no CSV export needed) |
| **Scanner connectors** | Tenable.io · Qualys VMDR · Rapid7 InsightVM (beta) · Nessus Pro (beta) · Microsoft Defender (beta) |
| **Scheduled sync** | APScheduler — auto-sync all enabled connectors every N hours (`SCHEDULER_ENABLED=true`) |
| **Enrichment** | CISA KEV · FIRST EPSS · NVD · Redis caching |
| **AI triage** | LLM scoring agent (OpenAI, Anthropic, Gemini, Ollama) · `temperature=0.0` · written rationale |
| **Assets** | Asset register · link findings to assets · internet-facing flag boosts priority |
| **Remediation** | Markdown + Jira ticket drafts · bulk triage advisor |
| **Reporting** | Dashboard stats · PDF export · board-ready summaries |
| **Audit log** | Append-only, org-scoped, admin-read-only |
| **Security headers** | HSTS · CSP · X-Frame-Options · X-Content-Type-Options on every response |

---

## Quick Setup (5 minutes)

Requires Docker Desktop and Python 3.11+.

```bash
# 1. Clone
git clone https://github.com/cybersecbalaji/vulnops && cd vulnops

# 2. Generate secrets and write .env automatically
python scripts/setup.py

# For CI or one-click installers — skip all prompts:
python scripts/setup.py --non-interactive

# 3. Start the full stack
docker compose up -d

# 4. Apply database migrations (first run only)
docker compose exec backend alembic upgrade head
```

- **Frontend** → http://localhost:3000
- **API docs** → http://localhost:8000/api/docs *(DEBUG mode only)*

Register your first user at `http://localhost:3000` — the first user in a new org becomes admin automatically.

---

## Environment Variables

`scripts/setup.py` generates most values automatically. The root `.env.example` documents everything.

### Core (required)

| Variable | Description | Example |
|----------|-------------|---------|
| `MASTER_ENCRYPTION_KEY` | Fernet key — encrypts all per-org DEKs | `python scripts/setup.py` |
| `JWT_PRIVATE_KEY` | RSA 4096 private key (PEM, `\n`-escaped) | `python scripts/setup.py` |
| `JWT_PUBLIC_KEY` | RSA 4096 public key (PEM, `\n`-escaped) | `python scripts/setup.py` |
| `DATABASE_URL` | PostgreSQL connection string (`asyncpg://` scheme) | `postgresql+asyncpg://user:pass@host/db` |
| `REDIS_URL` | Redis connection string | `redis://localhost:6379/0` |
| `CORS_ORIGINS` | JSON array of allowed origins | `["https://app.yourdomain.com"]` |
| `APP_ENV` | `development` or `production` | `production` |
| `DEBUG` | Enable Swagger UI + verbose errors | `false` |

### Optional

| Variable | Description | Default |
|----------|-------------|---------|
| `NVD_API_KEY` | NVD API key (higher rate limit) | — |
| `BACKEND_URL` | Backend URL used by the Next.js server-side proxy | `http://backend:8000` |
| `SCHEDULER_ENABLED` | Enable background scanner sync via APScheduler | `false` |
| `SCHEDULER_SYNC_INTERVAL_HOURS` | How often to sync all enabled connectors | `6` |
| `MAX_LOGIN_ATTEMPTS` | Failed logins before lockout | `10` |
| `LOCKOUT_MINUTES` | Lockout window after too many failures | `15` |

> **Critical:** Back up `MASTER_ENCRYPTION_KEY` securely — losing it means losing access to all encrypted fields in the database.

---

## Running with Docker

```bash
git clone https://github.com/cybersecbalaji/vulnops && cd vulnops

# Generate secrets
python scripts/setup.py

# Start infra first, run migrations, then bring up the full stack
docker compose up -d db redis
docker compose run --rm backend alembic upgrade head
docker compose up -d
```

### Useful commands

```bash
docker compose logs -f backend          # stream backend logs
docker compose logs -f frontend
docker compose down                     # stop all services
docker compose down -v                  # stop and wipe database volumes
docker compose build backend            # rebuild after dep changes
docker compose exec backend bash        # open shell in backend container
docker compose exec backend alembic revision --autogenerate -m "describe change"
```

---

## Running Locally (Without Docker)

Start just the infrastructure via Docker, then run the app processes directly:

```bash
docker compose up -d db redis
```

### Backend

```bash
cd backend
python -m venv .venv
source .venv/bin/activate      # Linux / macOS
.venv\Scripts\activate         # Windows

pip install -r requirements.txt
alembic upgrade head
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

API: `http://localhost:8000` · Docs (dev only): `http://localhost:8000/api/docs`

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Frontend: `http://localhost:3000`

---

## Scanner API Connectors

VulnOps pulls findings directly from scanner APIs — no CSV export required. Credentials are stored encrypted per-org using the `EncryptedString` TypeDecorator; they never leave your instance.

### Supported connectors

| Provider | Status | Auth method |
|----------|--------|-------------|
| Tenable.io | **Live** | `X-ApiKeys: accessKey=…;secretKey=…` |
| Qualys VMDR | **Live** | HTTP Basic (`username:password`) |
| Rapid7 InsightVM | Beta | API key |
| Nessus Professional | Beta | API key |
| Microsoft Defender | Beta | OAuth2 client credentials |

### Add a connector via UI

1. Go to **Settings → Connectors** in the web app.
2. Click **Add connector** and select a provider.
3. Fill in the required credentials.
4. Click **Test** to verify the connection.
5. Click **Sync now** for an immediate pull, or enable scheduled sync.

### Add a connector via API

```bash
# Create a Tenable connector
curl -X POST http://localhost:8000/api/v1/scanner-connections/ \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Prod Tenable",
    "provider": "tenable",
    "config": {
      "access_key": "your-access-key",
      "secret_key": "your-secret-key"
    },
    "enabled": true
  }'

# Test it
curl -X POST http://localhost:8000/api/v1/scanner-connections/{id}/test \
  -H "Authorization: Bearer $TOKEN"

# Trigger a one-shot sync
curl -X POST http://localhost:8000/api/v1/scanner-connections/{id}/sync \
  -H "Authorization: Bearer $TOKEN"
```

### Required config keys per provider

```bash
# List providers and their required config keys
curl http://localhost:8000/api/v1/scanner-connections/providers \
  -H "Authorization: Bearer $TOKEN"
```

---

## Scheduled Sync

Enable background sync to have VulnOps automatically pull findings from all enabled connectors on a schedule:

```env
# In your .env or deployment env vars
SCHEDULER_ENABLED=true
SCHEDULER_SYNC_INTERVAL_HOURS=6   # default: every 6 hours
```

When enabled, APScheduler starts an `AsyncIOScheduler` in the FastAPI lifespan. Each tick iterates all enabled `ScannerConnection` rows across all orgs, decrypts their credentials under the correct per-org DEK, and calls the connector's `fetch_findings()` → `ingest_batch()` pipeline.

Disable for test environments or if you're using an external cron / task queue.

---

## Database Migrations

```bash
# Apply all pending migrations
alembic upgrade head

# Check current state
alembic current

# Generate a migration after model changes
alembic revision --autogenerate -m "describe your change"

# Roll back one step
alembic downgrade -1
```

### Migration history

| Revision | Description |
|----------|-------------|
| `001` | Organizations, users, refresh tokens |
| `002` | Vulnerabilities table with `enc_*` columns and scoring fields |
| `003` | Assets table + asset–vulnerability association |
| `004` | Scanner connections table (`enc_config`, sync state) |

---

## Deploying Online

### Option 1 — Self-hosted VPS (most control, recommended for production)

A $6–12/month VPS (DigitalOcean, Hetzner, Linode) handles the full stack comfortably.

```bash
# On your server (Ubuntu 22.04):

# 1. Install Docker
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER && newgrp docker

# 2. Clone
git clone https://github.com/cybersecbalaji/vulnops && cd vulnops

# 3. Generate secrets
python scripts/setup.py --non-interactive

# 4. Set production env vars
export DOMAIN="yourdomain.com"
export POSTGRES_PASSWORD="$(openssl rand -hex 32)"

# 5. Start the production stack (Caddy handles TLS automatically)
docker compose -f docker-compose.prod.yml up -d --build

# 6. Run migrations
docker compose -f docker-compose.prod.yml exec backend alembic upgrade head
```

Point your domain's A record to the server IP. Caddy obtains a Let's Encrypt certificate automatically.

**Minimum spec:** 1 vCPU · 1 GB RAM · 20 GB SSD  
**Recommended:** 2 vCPU · 2 GB RAM · 40 GB SSD

---

### Option 2 — Railway

Use the included `deploy/railway.toml` manifest.

1. Push to GitHub.
2. [railway.app](https://railway.app) → **New Project → Deploy from GitHub repo**.
3. Add **PostgreSQL** and **Redis** plugins.
4. In **Variables**, set everything from `backend/.env` plus:
   ```
   APP_ENV=production
   DEBUG=false
   CORS_ORIGINS=["https://your-frontend.up.railway.app"]
   ```
5. Set the start command:
   ```
   alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port $PORT
   ```
6. Deploy the frontend separately; set `BACKEND_URL` to the Railway backend internal URL.

> **Known issue:** Railway uses HTTP for internal service communication. Set `BACKEND_URL` to the internal Railway DNS (`http://backend.railway.internal:8000`) — do not use the public HTTPS URL for the proxy or you'll get 308 redirect loops.

---

### Option 3 — Fly.io

Use `deploy/fly.toml`. Requires the [Fly CLI](https://fly.io/docs/hands-on/install-flyctl/).

```bash
fly auth login
fly launch --config deploy/fly.toml
fly postgres create --name vulnops-db
fly redis create --name vulnops-redis
fly secrets set MASTER_ENCRYPTION_KEY="..." JWT_PRIVATE_KEY="..." ...
fly deploy
```

---

### Option 4 — Render

Use `deploy/render.yaml` (Blueprint).

1. Push to GitHub.
2. [render.com](https://render.com) → **Blueprints** → connect the repo.
3. Render reads `deploy/render.yaml` and provisions backend + managed Postgres + Redis automatically.
4. Add secrets in the Render dashboard (same vars as the self-hosted `.env`).

---

### Environment variables checklist for all cloud deploys

| Variable | Source |
|----------|--------|
| `MASTER_ENCRYPTION_KEY` | `python scripts/setup.py` |
| `JWT_PRIVATE_KEY` | `python scripts/setup.py` |
| `JWT_PUBLIC_KEY` | `python scripts/setup.py` |
| `DATABASE_URL` | Managed Postgres — use `asyncpg://` scheme |
| `REDIS_URL` | Managed Redis |
| `CORS_ORIGINS` | `["https://your-frontend-domain.com"]` |
| `APP_ENV` | `production` |
| `DEBUG` | `false` |
| `BACKEND_URL` | Internal backend URL for the Next.js proxy |
| `SCHEDULER_ENABLED` | `true` if you want automatic scanner sync |

---

## Running Tests

Tests use SQLite in-memory and a mocked Redis client — no live Postgres or Redis required.

```bash
cd backend

# Run all 318 tests
pytest

# Verbose output
pytest -v

# Single file
pytest tests/test_scanner_connectors.py -v

# With coverage
pytest --cov=app --cov-report=term-missing
```

### Test suite

| File | Area | Tests |
|------|------|-------|
| `test_auth.py` | JWT auth, refresh tokens, sessions | 29 |
| `test_phase2.py` | Field encryption, sanitization | 30 |
| `test_phase3.py` | Ingestion, deduplication | 42 |
| `test_phase4.py` | KEV, EPSS, NVD enrichment | 31 |
| `test_phase5.py` | LLM abstraction, org settings | 29 |
| `test_phase6.py` | Context scoring agent | 29 |
| `test_phase7.py` | Remediation tickets, triage advice | 26 |
| `test_phase8.py` | Dashboard, PDF export, audit log | 21 |
| `test_scanner_connectors.py` | Scanner connectors (parse, encrypt, sync, RBAC) | 14 |
| `test_assets.py` | Asset management, CSV import | 7 |
| **Total** | | **318** |

---

## API Reference

All endpoints under `/api/v1`. Authentication: `Authorization: Bearer <access_token>`.

### Authentication

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/auth/register` | Create org + first admin user |
| `POST` | `/auth/login` | Get access + refresh tokens |
| `POST` | `/auth/refresh` | Rotate refresh token |
| `POST` | `/auth/logout` | Revoke session |
| `GET` | `/auth/sessions` | List active sessions |

### Vulnerabilities

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/vulnerabilities/` | Create single (manual) |
| `POST` | `/vulnerabilities/ingest/csv` | Bulk ingest CSV |
| `POST` | `/vulnerabilities/ingest/json` | Bulk ingest JSON |
| `GET` | `/vulnerabilities/` | List (paginated, filterable) |
| `GET` | `/vulnerabilities/{id}` | Get single |
| `PATCH` | `/vulnerabilities/{id}` | Update |
| `DELETE` | `/vulnerabilities/{id}` | Delete (admin) |
| `POST` | `/vulnerabilities/enrich` | Enrich all (KEV + EPSS + NVD) |
| `POST` | `/vulnerabilities/{id}/enrich` | Enrich single |
| `POST` | `/vulnerabilities/score` | AI-score all |
| `POST` | `/vulnerabilities/{id}/score` | AI-score single |

### Assets

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/assets/` | Create asset |
| `POST` | `/assets/ingest/csv` | Bulk import from CSV |
| `GET` | `/assets/` | List assets |
| `GET` | `/assets/{id}` | Get asset |
| `PATCH` | `/assets/{id}` | Update asset |
| `DELETE` | `/assets/{id}` | Delete asset (admin) |
| `POST` | `/assets/{id}/match` | Match asset to findings |

### Scanner Connections

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/scanner-connections/providers` | List available providers + required config keys |
| `GET` | `/scanner-connections/` | List org's connections |
| `POST` | `/scanner-connections/` | Create connection (admin) |
| `GET` | `/scanner-connections/{id}` | Get connection |
| `PATCH` | `/scanner-connections/{id}` | Update connection (admin) |
| `DELETE` | `/scanner-connections/{id}` | Delete connection (admin) |
| `POST` | `/scanner-connections/{id}/test` | Test credentials live |
| `POST` | `/scanner-connections/{id}/sync` | Trigger one-shot sync |

### Org Settings

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/org/settings` | Get LLM config + scoring thresholds |
| `PATCH` | `/org/settings` | Update (admin) |
| `POST` | `/org/settings/test-llm` | Validate LLM connectivity (admin) |

### Remediation

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/remediation/{id}/ticket` | Draft ticket (Markdown / Jira / both) |
| `POST` | `/remediation/triage-advice` | Generate bulk triage plan |

### Reports

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/reports/dashboard` | Stats by severity, status, priority |
| `GET` | `/reports/dashboard/pdf` | Download PDF |
| `GET` | `/reports/audit-log` | Paginated audit log (admin) |

### Health

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Liveness probe |
| `GET` | `/ready` | Readiness probe (checks DB + Redis) |

### Ingestion formats

**CSV** — required columns: `cve_id`, `title`, `description`, `severity`

```csv
cve_id,title,description,severity,cvss_score,epss_score
CVE-2024-1234,Apache Log4j RCE,Remote code execution via JNDI,critical,10.0,0.97
CVE-2024-5678,OpenSSL Buffer Overflow,Heap overflow in TLS,high,8.1,0.45
```

**JSON**

```json
[
  {
    "cve_id": "CVE-2024-1234",
    "title": "Apache Log4j RCE",
    "description": "Remote code execution via JNDI lookup",
    "severity": "critical",
    "cvss_score": 10.0,
    "epss_score": 0.97,
    "affected_component": "log4j-core 2.x"
  }
]
```

---

## LLM Provider Configuration

Configure via `PATCH /org/settings` (admin only). API keys are encrypted with the org DEK before storage and never returned in API responses.

| Provider | `ai_provider` | Notes |
|----------|--------------|-------|
| Anthropic Claude | `anthropic` | Requires `ai_api_key` |
| OpenAI GPT | `openai` | Requires `ai_api_key` |
| Google Gemini | `gemini` | Requires `ai_api_key` |
| Ollama (local) | `ollama` | Requires `ollama_base_url`, no API key |

```bash
# Configure Anthropic
curl -X PATCH http://localhost:8000/api/v1/org/settings \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "ai_provider": "anthropic",
    "ai_model": "claude-sonnet-4-6",
    "ai_api_key": "sk-ant-..."
  }'

# Configure local Ollama
curl -X PATCH http://localhost:8000/api/v1/org/settings \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "ai_provider": "ollama",
    "ai_model": "llama3",
    "ollama_base_url": "http://localhost:11434"
  }'

# Adjust scoring thresholds
curl -X PATCH http://localhost:8000/api/v1/org/settings \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "epss_immediate_threshold": 0.5,
    "cvss_immediate_threshold": 9.0,
    "kev_sla_days": 7,
    "non_kev_critical_sla_days": 30
  }'
```

---

## Security Model

| Control | Implementation |
|---------|---------------|
| **Authentication** | RS256 JWT (15-min TTL, in-memory) + SHA-256 hashed refresh tokens, rotated on every use |
| **Field encryption** | Per-org Fernet DEK; `EncryptedString` TypeDecorator encrypts `enc_*` columns at the application layer |
| **Connector credentials** | Stored as encrypted JSON blobs (`enc_config`) under the org DEK — never plaintext in DB |
| **Multi-tenancy** | Every DB query scoped to `org_id`; enforced at the service layer |
| **Input sanitization** | HTML stripping, control character removal, Unicode NFC normalisation, length caps |
| **Password security** | bcrypt hashing + HaveIBeenPwned breach check on registration |
| **Rate limiting** | Redis-backed login attempt limiting (default: 10 attempts, 15-min lockout) |
| **LLM isolation** | All LLM calls through `LLMClient` abstraction; API keys encrypted, never logged |
| **Scoring determinism** | `temperature=0.0` enforced on all LLM scoring calls |
| **Audit log** | Append-only, org-scoped; admin-read-only |
| **HTTP security headers** | HSTS (1-year) · CSP · X-Frame-Options · X-Content-Type-Options on every response |

---

## Project Structure

```
vulnops/
├── .env.example                    # Root env template (used by Compose)
├── docker-compose.yml              # Dev stack
├── docker-compose.prod.yml         # Production stack (Caddy, built images)
├── Caddyfile                       # Reverse proxy + automatic TLS
├── scripts/
│   └── setup.py                    # Secret generation (--non-interactive flag)
├── deploy/
│   ├── railway.toml                # Railway deploy manifest
│   ├── fly.toml                    # Fly.io deploy manifest
│   └── render.yaml                 # Render Blueprint
├── docs/
│   └── DEPLOY.md                   # Detailed deploy guide + known issues
├── backend/
│   ├── requirements.txt
│   ├── alembic/
│   │   └── versions/
│   │       ├── 001_initial.py
│   │       ├── 002_vulnerabilities.py
│   │       ├── 003_assets.py
│   │       └── 004_scanner_connections.py
│   ├── app/
│   │   ├── main.py                 # App factory: CORS, headers, lifespan scheduler
│   │   ├── core/
│   │   │   ├── config.py           # Pydantic settings (SCHEDULER_ENABLED etc.)
│   │   │   ├── encryption.py       # EncryptedString + ContextVar
│   │   │   ├── security.py         # RS256 JWT + bcrypt
│   │   │   ├── sanitization.py
│   │   │   ├── clients/
│   │   │   │   ├── kev.py          # CISA KEV HTTP client
│   │   │   │   ├── epss.py         # FIRST EPSS client
│   │   │   │   ├── nvd.py          # NVD client
│   │   │   │   └── scanners/       # Scanner connector framework
│   │   │   │       ├── base.py     # ScannerClient ABC
│   │   │   │       ├── registry.py # Provider registry
│   │   │   │       ├── tenable.py  # Tenable.io connector
│   │   │   │       └── qualys.py   # Qualys VMDR connector
│   │   │   └── llm/                # LLM abstraction (Anthropic, OpenAI, Gemini, Ollama)
│   │   ├── api/
│   │   │   ├── deps.py
│   │   │   └── routes/
│   │   │       ├── auth.py
│   │   │       ├── vulnerabilities.py
│   │   │       ├── assets.py
│   │   │       ├── scanner_connections.py
│   │   │       ├── org_settings.py
│   │   │       ├── remediation.py
│   │   │       └── reports.py
│   │   ├── models/
│   │   │   ├── scanner_connection.py
│   │   │   └── ...
│   │   ├── schemas/
│   │   │   ├── scanner_connection.py
│   │   │   └── ...
│   │   └── services/
│   │       ├── scanner_connection.py   # CRUD + run_sync()
│   │       ├── vulnerability.py        # ingest_batch() (used by connectors)
│   │       └── ...
│   └── tests/
│       ├── conftest.py
│       ├── test_auth.py
│       ├── test_phase2.py – test_phase8.py
│       ├── test_scanner_connectors.py
│       └── test_assets.py
└── frontend/
    ├── src/
    │   ├── app/
    │   │   ├── page.tsx                    # Landing page
    │   │   ├── (dashboard)/
    │   │   │   ├── assets/
    │   │   │   ├── findings/
    │   │   │   ├── reports/
    │   │   │   ├── remediation/
    │   │   │   └── settings/
    │   │   │       └── connectors/page.tsx # Scanner connections UI
    │   │   └── api/v1/[...path]/route.ts   # Next.js server-side proxy
    │   ├── components/
    │   │   ├── theme-toggle.tsx
    │   │   └── ui/
    │   ├── contexts/
    │   │   ├── AuthContext.tsx
    │   │   └── ThemeContext.tsx
    │   └── lib/api.ts
    └── public/
        └── screenshots/
```

---

## Quick Start (End-to-End)

```bash
# 1. Start
docker compose up -d
docker compose exec backend alembic upgrade head

# 2. Register org + admin
curl -X POST http://localhost:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@myorg.com", "password": "SecurePass123!", "org_name": "My Org"}'

# 3. Get token
TOKEN=$(curl -s -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@myorg.com", "password": "SecurePass123!"}' \
  | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)

# 4. Configure LLM
curl -X PATCH http://localhost:8000/api/v1/org/settings \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"ai_provider": "anthropic", "ai_model": "claude-sonnet-4-6", "ai_api_key": "sk-ant-..."}'

# 5a. Add a scanner connector (pulls findings automatically)
curl -X POST http://localhost:8000/api/v1/scanner-connections/ \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "Prod Tenable", "provider": "tenable", "config": {"access_key": "…", "secret_key": "…"}, "enabled": true}'

# 5b. Or ingest from CSV
curl -X POST http://localhost:8000/api/v1/vulnerabilities/ingest/csv \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@your_vulns.csv"

# 6. Enrich with KEV + EPSS + NVD
curl -X POST http://localhost:8000/api/v1/vulnerabilities/enrich \
  -H "Authorization: Bearer $TOKEN"

# 7. AI-score all findings
curl -X POST http://localhost:8000/api/v1/vulnerabilities/score \
  -H "Authorization: Bearer $TOKEN"

# 8. Get the dashboard
curl http://localhost:8000/api/v1/reports/dashboard \
  -H "Authorization: Bearer $TOKEN"

# 9. Download PDF report
curl http://localhost:8000/api/v1/reports/dashboard/pdf \
  -H "Authorization: Bearer $TOKEN" \
  -o dashboard.pdf
```

---

## Contributing

Issues and PRs welcome at https://github.com/cybersecbalaji/vulnops.  
This is an experimental side project — scope is intentionally focused. See `CONTRIBUTING.md` for guidelines.

## License

[Apache 2.0](LICENSE) — free to use, modify, and distribute.
