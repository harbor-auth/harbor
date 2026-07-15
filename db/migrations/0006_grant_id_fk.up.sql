-- 0006_grant_id_fk (up) — add grant_id FK column to sessions so revocation can
-- be scoped to a specific user-client-grant family rather than revoking all
-- sessions for a (user_id, client_id) pair (DESIGN §3.5, §10, §11.3).
--
-- Expand pattern (docs/DESIGN.md §1.8, .agents/db-migrate.md):
--   This is a greenfield schema with no live rows, so we can add NOT NULL
--   directly. A production backfill would use the two-step approach:
--   add nullable → backfill → set NOT NULL.
--
-- The partial index on (grant_id) WHERE revoked_at IS NULL optimizes the
-- common lookup pattern: find active sessions for a grant to revoke them.
SET lock_timeout = '3s';
SET statement_timeout = '30s';

ALTER TABLE sessions ADD COLUMN grant_id UUID NOT NULL REFERENCES grants(id);

CREATE INDEX idx_sessions_grant_id ON sessions (grant_id)
    WHERE revoked_at IS NULL;
