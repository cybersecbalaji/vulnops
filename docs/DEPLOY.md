# VulnOps Deployment Guide

## Architecture

```
Browser
  → Vercel / Next.js frontend  (:443)
      → Route Handler proxy  (server-side, /api/v1/*)
          → FastAPI backend  (:8000)
              → PostgreSQL 16
              → Redis 7
```

The Next.js Route Handler at `frontend/src/app/api/v1/[...path]/route.ts` proxies
all `/api/v1/*` requests to the backend. The browser **never** makes a direct request
to the backend URL — only the Next.js server-side does. This means:
- You only need to expose the frontend publicly.
- The backend can be on a private network or use an internal service URL.
- No CORS issues from the browser (all API calls share the frontend origin).

---

## Option 1 — Self-hosted (Docker Compose)

### Requirements
- Docker + Docker Compose v2
- A domain name (for Caddy/TLS)
- A server with 1 GB RAM minimum

### Steps

```bash
git clone https://github.com/your-org/vulnops
cd vulnops

# 1. Generate secrets
python scripts/setup.py

# 2. Create root .env
cp .env.example .env
# Edit .env: set POSTGRES_PASSWORD and DOMAIN

# 3. Start
docker compose -f docker-compose.prod.yml up -d

# 4. Migrate DB (first time only)
docker compose -f docker-compose.prod.yml exec backend alembic upgrade head

# 5. Open https://yourdomain.com — register your first admin account
```

### Non-interactive setup (CI / one-click scripts)
```bash
python scripts/setup.py --non-interactive
```

---

## Option 2 — Vercel (frontend) + Railway (backend)

### Frontend on Vercel
1. Import the repo in Vercel.
2. Set **Root Directory** to `frontend`.
3. Set env var `BACKEND_URL` to your Railway backend internal URL, e.g.
   `http://vulnops-api.railway.internal:8000`.
4. Deploy.

### Backend on Railway
1. Create a new Railway project.
2. Add a **GitHub service** pointing to this repo; set **Root Directory** to `backend`.
3. Add a **PostgreSQL** plugin → Railway auto-sets `DATABASE_URL`.
4. Add a **Redis** plugin → Railway auto-sets `REDIS_URL`.
5. In the backend service settings → Variables, add:
   - `JWT_PRIVATE_KEY`, `JWT_PUBLIC_KEY`, `MASTER_ENCRYPTION_KEY` (from `backend/.env` after running setup.py)
   - `CORS_ORIGINS=["https://your-project.vercel.app"]`
   - `APP_ENV=production`, `DEBUG=false`
6. Run migrations: **Settings → Deploy** → add a start command:
   ```
   alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 2
   ```
7. Use `deploy/railway.toml` for config-as-code.

### Known Railway gotchas

| Issue | Root cause | Fix |
|---|---|---|
| Next.js rewrite strips trailing slashes | `next.config.js` `rewrites()` normalises paths before forwarding | Use the Route Handler proxy (`/api/v1/[...path]/route.ts`) — it preserves exact paths |
| FastAPI 308 redirect leaks internal Railway URL | `redirect_slashes=True` (FastAPI default) + trailing-slash mismatch | Route Handler follows redirects server-side; internal URL never reaches browser |
| Railway internal services are HTTP-only | `*.railway.internal` does not terminate TLS | Set `BACKEND_URL=http://...railway.internal:8000` (not https) |
| Cookie SameSite=Strict blocks cross-origin refresh | HttpOnly refresh token requires same origin | Frontend + backend must share origin (frontend proxies all API calls) |

---

## Option 3 — Fly.io (backend) + Vercel (frontend)

```bash
# Install flyctl, then:
fly auth login
fly postgres create --name vulnops-db
fly redis create --name vulnops-redis
fly launch --config deploy/fly.toml

fly secrets set \
  JWT_PRIVATE_KEY="$(cat backend/.env | grep JWT_PRIVATE_KEY | cut -d= -f2-)" \
  JWT_PUBLIC_KEY="$(cat backend/.env | grep JWT_PUBLIC_KEY | cut -d= -f2-)" \
  MASTER_ENCRYPTION_KEY="$(cat backend/.env | grep MASTER_ENCRYPTION_KEY | cut -d= -f2-)" \
  CORS_ORIGINS='["https://your-frontend.vercel.app"]'

fly deploy
fly ssh console -C "alembic upgrade head"
```

---

## Option 4 — Render Blueprint

1. Fork/import the repo on Render.
2. New → Blueprint → select `deploy/render.yaml`.
3. After provisioning, set `JWT_PRIVATE_KEY`, `JWT_PUBLIC_KEY`, `MASTER_ENCRYPTION_KEY`
   manually in the Render dashboard (Environment → Secret Files).

---

## Health endpoints

| Path | Purpose |
|---|---|
| `GET /health` | Liveness — returns 200 if the process is running |
| `GET /ready` | Readiness — checks DB + Redis connectivity; returns 503 if either is down |

Use `/ready` for Railway/Fly/Render health checks and Docker `HEALTHCHECK`.

---

## Scheduler (scanner sync)

Set `SCHEDULER_ENABLED=true` to enable automatic scanner sync every 6 hours.
Leave it `false` if you prefer external cron or manual "Sync now" via the UI.

On Railway you can use a separate cron service that calls `POST /api/v1/scanner-connections/{id}/sync`
with a service token instead of running the scheduler inside the backend process.
