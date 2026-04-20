# VulnOps Triage Console

A full-stack vulnerability triage platform for security operations teams. Ingest CVEs from CSV, JSON, or manual entry; enrich them with KEV, EPSS, and NVD data; score them with an LLM-powered triage agent; draft remediation tickets; and export PDF dashboard reports — all with per-organisation field encryption and a full audit log.

---

## Table of Contents

- [Architecture](#architecture)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Quick Local Setup (5 minutes)](#quick-local-setup-5-minutes)
- [Environment Setup (manual)](#environment-setup-manual)
- [Running with Docker (Recommended)](#running-with-docker-recommended)
- [Running Locally (Without Docker)](#running-locally-without-docker)
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
                           │ HTTP / REST
┌──────────────────────────▼──────────────────────────┐
│                  FastAPI Backend                      │
│             (Python 3.12 · SQLAlchemy)               │
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

**Stack:** Next.js 14 · FastAPI · PostgreSQL 16 · Redis 7 · Fernet encryption · fpdf2 · Recharts

---

## Features

| Phase | Feature |
|-------|---------|
| 1 | JWT auth (RS256, 15-min access tokens) · refresh token rotation · multi-org |
| 2 | Per-org field encryption (Fernet) · input sanitization pipeline |
| 3 | Vulnerability ingestion — CSV, JSON, manual · deduplication |
| 4 | Enrichment — CISA KEV · FIRST EPSS · NVD · Redis caching |
| 5 | LLM abstraction (Anthropic, OpenAI, Gemini, Ollama) · org settings |
| 6 | Context scoring agent — rule-based + LLM triage priority · temperature=0.0 |
| 7 | Remediation ticket drafter (Markdown + Jira) · bulk triage advisor |
| 8 | Dashboard stats · PDF export · append-only audit log |

---

## Quick Local Setup (5 minutes)

The fastest path to a running stack — requires only Docker Desktop and Python.

```bash
# 1. Clone the repo
git clone <repo-url> && cd Vuln_ops

# 2. Generate all secrets and create backend/.env automatically
python scripts/setup.py

# 3. Start everything
docker compose up -d

# 4. Apply database migrations (first time only)
docker compose exec backend alembic upgrade head

# Done!
#   Frontend → http://localhost:3000
#   API docs  → http://localhost:8000/api/docs
```

Register your first user at `http://localhost:3000` — the first registered user in an org becomes the admin.

---

## Prerequisites

| Tool | Minimum Version | Notes |
|------|----------------|-------|
| Docker + Docker Compose | 24.x / 2.x | Recommended path |
| Python | 3.11+ | Local dev only |
| Node.js | 20.x | Local dev only |
| PostgreSQL | 16 | Provided by Docker |
| Redis | 7 | Provided by Docker |

---

## Environment Setup

### 1. Generate required secrets

```bash
# Generate a Fernet master encryption key
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

# Generate an RSA 4096-bit key pair for JWT signing
openssl genrsa -out jwt_private.pem 4096
openssl rsa -in jwt_private.pem -pubout -out jwt_public.pem
```

### 2. Create the backend `.env` file

```bash
cp backend/.env.example backend/.env
```

Edit `backend/.env` and fill in all required values:

```env
# ── Application ────────────────────────────────────────────────────────────
APP_ENV=development
DEBUG=true

# ── Database ────────────────────────────────────────────────────────────────
DATABASE_URL=postgresql+asyncpg://vulnops:changeme@localhost:5432/vulnops

# ── Redis ────────────────────────────────────────────────────────────────────
REDIS_URL=redis://localhost:6379/0

# ── Encryption ───────────────────────────────────────────────────────────────
# Generate with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
MASTER_ENCRYPTION_KEY=your-generated-fernet-key-here

# ── JWT (RS256) ───────────────────────────────────────────────────────────────
# Paste PEM content — replace literal newlines with \n in the .env file
JWT_PRIVATE_KEY=-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----
JWT_PUBLIC_KEY=-----BEGIN PUBLIC KEY-----\nMIIB...\n-----END PUBLIC KEY-----
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=15
REFRESH_TOKEN_EXPIRE_DAYS=30

# ── External APIs (optional but recommended) ──────────────────────────────────
NVD_API_KEY=your-nvd-api-key       # https://nvd.nist.gov/developers/request-an-api-key

# ── CORS ─────────────────────────────────────────────────────────────────────
CORS_ORIGINS=["http://localhost:3000"]

# ── Rate Limiting ─────────────────────────────────────────────────────────────
MAX_LOGIN_ATTEMPTS=10
LOCKOUT_MINUTES=15
```

> **Tip:** To put PEM keys into a `.env` file, replace every newline inside the PEM with `\n`. The config loader converts `\n` literals back to real newlines automatically.

---

## Running with Docker (Recommended)

```bash
# 1. Clone the repo
git clone <repo-url>
cd Vuln_ops

# 2. Create and populate backend/.env (see Environment Setup above)
cp backend/.env.example backend/.env
# ... edit backend/.env ...

# 3. Start infrastructure (Postgres + Redis)
docker compose up -d db redis

# 4. Wait for services to be healthy, then run migrations
docker compose run --rm backend alembic upgrade head

# 5. Start the full stack
docker compose up -d

# Services:
#   API docs:    http://localhost:8000/api/docs
#   Frontend:    http://localhost:3000
#   API base:    http://localhost:8000/api/v1
```

### Docker commands reference

```bash
# View logs
docker compose logs -f backend
docker compose logs -f frontend

# Stop everything
docker compose down

# Stop and remove volumes (wipes database)
docker compose down -v

# Rebuild backend image after dependency changes
docker compose build backend

# Open a shell in the backend container
docker compose exec backend bash

# Run a one-off command (e.g. create migration)
docker compose exec backend alembic revision --autogenerate -m "add new table"
```

---

## Running Locally (Without Docker)

You still need PostgreSQL 16 and Redis 7 running. The easiest way is to start just the infra containers:

```bash
docker compose up -d db redis
```

### Backend

```bash
cd backend

# Create a virtual environment
python -m venv .venv
source .venv/bin/activate        # Linux/macOS
.venv\Scripts\activate           # Windows

# Install dependencies
pip install -r requirements.txt

# Set environment variables (or use a .env file)
# ... ensure backend/.env is populated ...

# Run database migrations
alembic upgrade head

# Start the development server (auto-reload)
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

API will be available at `http://localhost:8000`.  
Interactive docs (development only): `http://localhost:8000/api/docs`

### Frontend

```bash
cd frontend

# Install dependencies
npm install

# Start the development server
npm run dev
```

Frontend will be available at `http://localhost:3000`.

---

## Database Migrations

Migrations are managed with Alembic.

```bash
# Apply all migrations (run from backend/ directory or via Docker)
alembic upgrade head

# Check current migration state
alembic current

# Generate a new migration after model changes
alembic revision --autogenerate -m "describe your change"

# Roll back one migration
alembic downgrade -1

# Roll back to a specific revision
alembic downgrade <revision_id>
```

### Migration history

| Revision | Description |
|----------|-------------|
| `001` | Initial schema — organizations, users, refresh tokens |
| `002` | Vulnerabilities table with enc_* columns and scoring fields |

> **Note:** Phases 3–8 added columns via subsequent migrations. Run `alembic upgrade head` to apply them all in order.

---

## Deploying Online

### Option 1 — Railway (Easiest, recommended for getting started)

Railway auto-detects Docker and provides managed Postgres and Redis. Free tier covers light usage.

1. Push the repo to GitHub.
2. Go to [railway.app](https://railway.app) → **New Project → Deploy from GitHub repo**.
3. Add a **PostgreSQL** plugin and a **Redis** plugin from the Railway dashboard.
4. In the **backend** service settings → **Variables**, add every value from `backend/.env` (run `python scripts/setup.py` locally first to generate the crypto secrets). Set:
   ```
   DATABASE_URL    → (copy from Railway's Postgres plugin — use asyncpg:// scheme)
   REDIS_URL       → (copy from Railway's Redis plugin)
   APP_ENV         → production
   DEBUG           → false
   CORS_ORIGINS    → ["https://your-frontend.up.railway.app"]
   ```
5. In the **Deploy** section, set the start command to:
   ```
   alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port $PORT
   ```
6. Add the **frontend** service, set `NEXT_PUBLIC_API_URL` to the backend's Railway URL.
7. Deploy. Railway handles TLS automatically.

---

### Option 2 — Render (Good free tier)

1. Push to GitHub.
2. Create a **PostgreSQL** database and a **Redis** instance on [render.com](https://render.com).
3. Create a **Web Service** for the backend:
   - **Runtime**: Docker
   - **Root directory**: `backend`
   - **Start command**: `alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port $PORT`
   - Add all env vars from `backend/.env`
4. Create a **Static Site** or **Web Service** for the frontend:
   - **Build command**: `npm install && npm run build`
   - **Start command**: `npm run start`
   - Set `NEXT_PUBLIC_API_URL` to your backend Render URL
5. Render provides free TLS on all services.

---

### Option 3 — Self-hosted VPS (DigitalOcean, Linode, Hetzner — most control)

Best for production workloads. A $12/month Droplet (2 vCPU, 2 GB RAM) handles the full stack comfortably.

```bash
# On your server (Ubuntu 22.04):

# 1. Install Docker
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER && newgrp docker

# 2. Clone the repo
git clone <repo-url> && cd Vuln_ops

# 3. Copy your generated backend/.env to the server
scp backend/.env user@your-server:/path/to/Vuln_ops/backend/.env

# 4. Set required env vars for production compose
export POSTGRES_PASSWORD="$(openssl rand -hex 32)"
export DOMAIN="yourdomain.com"
export NEXT_PUBLIC_API_URL="https://api.yourdomain.com"

# 5. Edit Caddyfile — replace yourdomain.com with your actual domain
nano Caddyfile

# 6. Start the production stack (no live-reload, built images, Caddy HTTPS)
docker compose -f docker-compose.prod.yml up -d --build

# 7. Run migrations
docker compose -f docker-compose.prod.yml exec backend alembic upgrade head

# Caddy automatically obtains a Let's Encrypt TLS certificate.
# Point your domain's A record to the server IP and you're done.
```

**Minimum VPS spec:** 1 vCPU · 1 GB RAM · 20 GB SSD  
**Recommended:** 2 vCPU · 2 GB RAM · 40 GB SSD

---

### Online deployment: environment variables checklist

Regardless of platform, set these before deploying:

| Variable | Where to get it |
|----------|----------------|
| `MASTER_ENCRYPTION_KEY` | `python scripts/setup.py` |
| `JWT_PRIVATE_KEY` | `python scripts/setup.py` |
| `JWT_PUBLIC_KEY` | `python scripts/setup.py` |
| `DATABASE_URL` | Your managed Postgres connection string (use `asyncpg://` scheme) |
| `REDIS_URL` | Your managed Redis connection string |
| `CORS_ORIGINS` | `["https://your-frontend-domain.com"]` |
| `APP_ENV` | `production` |
| `DEBUG` | `false` |
| `NVD_API_KEY` | Optional — [nvd.nist.gov](https://nvd.nist.gov/developers/request-an-api-key) |

> **Important:** The `MASTER_ENCRYPTION_KEY` encrypts all sensitive vulnerability data. Back it up securely — losing it means losing access to all encrypted fields in the database.

---

## Running Tests

Tests use SQLite in-memory (no live Postgres needed) and a mocked Redis client.

```bash
cd backend

# Run all 237 tests
pytest

# Run with verbose output
pytest -v

# Run a specific phase
pytest tests/test_phase3.py -v

# Run with coverage report
pytest --cov=app --cov-report=term-missing

# Run a single test class
pytest tests/test_phase8.py::TestAuditLogEndpoint -v
```

### Test summary

| File | Phase | Tests |
|------|-------|-------|
| `test_auth.py` | Auth + JWT + refresh tokens | 29 |
| `test_phase2.py` | Encryption + sanitization | 30 |
| `test_phase3.py` | Ingestion + deduplication | 42 |
| `test_phase4.py` | KEV + EPSS + NVD enrichment | 31 |
| `test_phase5.py` | LLM abstraction + org settings | 29 |
| `test_phase6.py` | Context scoring agent | 29 |
| `test_phase7.py` | Remediation tickets + triage advice | 26 |
| `test_phase8.py` | Dashboard + PDF + audit log | 21 |
| **Total** | | **237** |

---

## API Reference

All endpoints are under `/api/v1`. Authentication uses `Authorization: Bearer <access_token>`.

### Authentication

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/auth/register` | Create org + first admin user |
| `POST` | `/auth/login` | Get access + refresh tokens |
| `POST` | `/auth/refresh` | Rotate refresh token, get new access token |
| `POST` | `/auth/logout` | Revoke current session |
| `GET` | `/auth/sessions` | List active sessions |

### Vulnerabilities

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/vulnerabilities/` | Create a single vulnerability (manual) |
| `POST` | `/vulnerabilities/ingest/csv` | Bulk ingest from CSV upload |
| `POST` | `/vulnerabilities/ingest/json` | Bulk ingest from JSON upload |
| `GET` | `/vulnerabilities/` | List (paginated, filterable by severity/status) |
| `GET` | `/vulnerabilities/{id}` | Get single vulnerability |
| `PATCH` | `/vulnerabilities/{id}` | Partial update |
| `DELETE` | `/vulnerabilities/{id}` | Delete (admin only) |
| `POST` | `/vulnerabilities/enrich` | Enrich all vulns (KEV + EPSS + NVD) |
| `POST` | `/vulnerabilities/{id}/enrich` | Enrich single vulnerability |
| `POST` | `/vulnerabilities/score` | Score all vulns with LLM |
| `POST` | `/vulnerabilities/{id}/score` | Score single vulnerability |

### Org Settings

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/org/settings` | Get org LLM config + scoring thresholds |
| `PATCH` | `/org/settings` | Update settings (admin only) |
| `POST` | `/org/settings/test-llm` | Validate LLM connectivity (admin only) |

### Remediation

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/remediation/{id}/ticket` | Draft a remediation ticket (Markdown/Jira/both) |
| `POST` | `/remediation/triage-advice` | Generate strategic triage plan |

### Reports

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/reports/dashboard` | Vulnerability statistics (by severity, status, priority) |
| `GET` | `/reports/dashboard/pdf` | Download dashboard as PDF |
| `GET` | `/reports/audit-log` | Paginated audit log (admin only) |

### CSV Ingestion Format

Required columns: `cve_id`, `title`, `description`, `severity`  
Optional columns: `affected_component`, `notes`, `remediation_advice`, `cvss_score`, `epss_score`, `source_id`, `status`

```csv
cve_id,title,description,severity,cvss_score,epss_score
CVE-2024-1234,Apache Log4j RCE,Remote code execution via JNDI lookup,critical,10.0,0.97
CVE-2024-5678,OpenSSL Buffer Overflow,Heap buffer overflow in TLS handling,high,8.1,0.45
```

### JSON Ingestion Format

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

Configure your LLM provider via `PATCH /org/settings` (admin only). API keys are encrypted with the org DEK before storage and never returned in API responses.

### Supported providers

| Provider | `ai_provider` value | Notes |
|----------|--------------------|----|
| Anthropic Claude | `anthropic` | Default. Requires `ai_api_key` |
| OpenAI GPT | `openai` | Requires `ai_api_key` |
| Google Gemini | `gemini` | Requires `ai_api_key` |
| Ollama (local) | `ollama` | Requires `ollama_base_url`, no API key |

### Example: configure Anthropic

```bash
curl -X PATCH http://localhost:8000/api/v1/org/settings \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "ai_provider": "anthropic",
    "ai_model": "claude-sonnet-4-6",
    "ai_api_key": "sk-ant-..."
  }'
```

### Example: configure Ollama (local)

```bash
curl -X PATCH http://localhost:8000/api/v1/org/settings \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "ai_provider": "ollama",
    "ai_model": "llama3",
    "ollama_base_url": "http://localhost:11434"
  }'
```

### Scoring thresholds

Scoring thresholds are also configurable per org:

```bash
curl -X PATCH http://localhost:8000/api/v1/org/settings \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "epss_immediate_threshold": 0.5,
    "epss_this_week_threshold": 0.3,
    "cvss_immediate_threshold": 9.0,
    "cvss_this_week_threshold": 7.0,
    "kev_sla_days": 7,
    "non_kev_critical_sla_days": 30
  }'
```

---

## Security Model

| Control | Implementation |
|---------|---------------|
| **Authentication** | RS256 JWT access tokens (15-min TTL, in-memory only) + SHA-256 hashed refresh tokens (rotated on every use) |
| **Field encryption** | Per-org Fernet DEK; sensitive text fields (`enc_*`) encrypted at application layer before write |
| **Multi-tenancy** | Every DB query scoped to `org_id`; enforced at service layer |
| **Input sanitization** | HTML stripping, control character removal, Unicode NFC normalisation, length caps on all text fields |
| **Password security** | bcrypt hashing + HaveIBeenPwned breach check on registration |
| **Rate limiting** | Redis-backed login attempt limiting (default: 10 attempts, 15-min lockout) |
| **LLM isolation** | All LLM calls through `LLMClient` abstraction; API keys encrypted before storage, never logged |
| **Scoring determinism** | `temperature=0.0` enforced on all LLM scoring calls |
| **Audit log** | Append-only, org-scoped event log; admin-only read access |
| **HTTP security headers** | HSTS (1-year), CSP, X-Frame-Options, X-Content-Type-Options on every response |

---

## Project Structure

```
Vuln_ops/
├── docker-compose.yml
├── scripts/
│   └── postgres-init.sql
├── backend/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── pytest.ini
│   ├── alembic/
│   │   └── versions/          # Database migrations
│   ├── app/
│   │   ├── main.py            # FastAPI app factory
│   │   ├── core/
│   │   │   ├── config.py      # Pydantic settings
│   │   │   ├── encryption.py  # Fernet field encryption + ContextVar
│   │   │   ├── sanitization.py
│   │   │   ├── security.py    # JWT + password hashing
│   │   │   ├── clients/       # HTTP clients (KEV, EPSS, NVD, Jira)
│   │   │   └── llm/           # LLM abstraction (Anthropic, OpenAI, Gemini, Ollama)
│   │   ├── api/
│   │   │   ├── deps.py        # FastAPI dependency injection
│   │   │   └── routes/        # Auth, vulnerabilities, org settings, remediation, reports
│   │   ├── models/            # SQLAlchemy ORM models
│   │   ├── schemas/           # Pydantic request/response schemas
│   │   └── services/          # Business logic (ingestion, enrichment, scoring, remediation, reports)
│   └── tests/
│       ├── conftest.py        # SQLite in-memory + mock Redis fixtures
│       └── test_phase*.py     # Phase-by-phase test suites
└── frontend/
    ├── package.json
    └── src/
        ├── app/               # Next.js App Router pages
        ├── components/        # shadcn/ui components
        ├── contexts/          # React context (auth state)
        ├── lib/               # API client, utilities
        └── types/             # TypeScript type definitions
```

---

## Quick Start (End-to-End)

```bash
# 1. Start services
docker compose up -d

# 2. Apply migrations
docker compose exec backend alembic upgrade head

# 3. Register your org and first admin user
curl -X POST http://localhost:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@myorg.com", "password": "SecurePass123!", "org_name": "My Org"}'

# 4. Login to get a token
TOKEN=$(curl -s -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@myorg.com", "password": "SecurePass123!"}' \
  | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)

# 5. Configure your LLM provider
curl -X PATCH http://localhost:8000/api/v1/org/settings \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"ai_provider": "anthropic", "ai_model": "claude-sonnet-4-6", "ai_api_key": "sk-ant-..."}'

# 6. Ingest vulnerabilities from CSV
curl -X POST http://localhost:8000/api/v1/vulnerabilities/ingest/csv \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@your_vulns.csv"

# 7. Enrich with KEV + EPSS + NVD data
curl -X POST http://localhost:8000/api/v1/vulnerabilities/enrich \
  -H "Authorization: Bearer $TOKEN"

# 8. Score all vulnerabilities with the LLM triage agent
curl -X POST http://localhost:8000/api/v1/vulnerabilities/score \
  -H "Authorization: Bearer $TOKEN"

# 9. Get the dashboard
curl http://localhost:8000/api/v1/reports/dashboard \
  -H "Authorization: Bearer $TOKEN"

# 10. Download the PDF report
curl http://localhost:8000/api/v1/reports/dashboard/pdf \
  -H "Authorization: Bearer $TOKEN" \
  -o dashboard.pdf
```
