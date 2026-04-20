# VulnOps Triage Console — developer shortcuts
# Usage: make <target>

.DEFAULT_GOAL := help
COMPOSE = docker compose

# ── First-time setup ──────────────────────────────────────────────────────────

.PHONY: setup
setup:          ## Generate secrets and create backend/.env
	python scripts/setup.py

# ── Docker Compose ────────────────────────────────────────────────────────────

.PHONY: up
up:             ## Start the full stack (build if needed)
	$(COMPOSE) up -d --build

.PHONY: down
down:           ## Stop all services
	$(COMPOSE) down

.PHONY: restart
restart:        ## Restart all services
	$(COMPOSE) restart

.PHONY: logs
logs:           ## Follow logs for all services
	$(COMPOSE) logs -f

.PHONY: logs-backend
logs-backend:   ## Follow backend logs only
	$(COMPOSE) logs -f backend

# ── Database ──────────────────────────────────────────────────────────────────

.PHONY: migrate
migrate:        ## Apply all pending migrations
	$(COMPOSE) exec backend alembic upgrade head

.PHONY: migration
migration:      ## Create a new migration (use: make migration MSG="describe change")
	$(COMPOSE) exec backend alembic revision --autogenerate -m "$(MSG)"

.PHONY: db-shell
db-shell:       ## Open a psql shell
	$(COMPOSE) exec db psql -U vulnops -d vulnops

# ── Testing ───────────────────────────────────────────────────────────────────

.PHONY: test
test:           ## Run all 237 tests
	cd backend && .venv/Scripts/python.exe -m pytest

.PHONY: test-v
test-v:         ## Run tests with verbose output
	cd backend && .venv/Scripts/python.exe -m pytest -v

.PHONY: test-cov
test-cov:       ## Run tests with coverage report
	cd backend && .venv/Scripts/python.exe -m pytest --cov=app --cov-report=term-missing

# ── Backend (local, no Docker) ────────────────────────────────────────────────

.PHONY: backend
backend:        ## Start backend in dev mode (requires venv activated)
	cd backend && uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

.PHONY: venv
venv:           ## Create backend virtual environment and install deps
	cd backend && python -m venv .venv && .venv/Scripts/pip install -r requirements.txt

# ── Frontend (local, no Docker) ───────────────────────────────────────────────

.PHONY: frontend
frontend:       ## Start frontend in dev mode
	cd frontend && npm run dev

.PHONY: frontend-install
frontend-install: ## Install frontend dependencies
	cd frontend && npm install

# ── Utilities ─────────────────────────────────────────────────────────────────

.PHONY: shell
shell:          ## Open a shell in the backend container
	$(COMPOSE) exec backend bash

.PHONY: clean
clean:          ## Stop services and remove volumes (DELETES ALL DATA)
	@echo "This will delete all database data. Press Ctrl-C to cancel."
	@sleep 3
	$(COMPOSE) down -v

.PHONY: help
help:           ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
