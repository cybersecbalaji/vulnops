-- PostgreSQL init script — runs once on first container startup.
-- Enables extensions needed by the application.

-- gen_random_uuid() for UUID primary key generation
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Row-level security is enabled per-table in Alembic migrations.
-- Nothing else needed here for Phase 1.
