-- 0006_sessions_grant_id (up) — add grant_id FK column to sessions so revocation
-- can be scoped to a specific user-client-grant family rather than revoking all
-- sessions for a (user_id, client_id) pair (DESIGN §3.5, §10, §11.3).
--
-- Expand pattern (docs/DESIGN.md §1.8, .agents/db-migrate.md):
--   Phase 1 (this file): additive, NULLABLE column so currently-running code
--   that omits grant_id keeps working. The FK to grants(id) is enforced from
--   the start; only the NOT NULL constraint is deferred.
--   Phase 2 (future, deploy dual-write code + batched backfill of existing rows).
--   Phase 3 (future contract migration): ALTER COLUMN grant_id SET NOT NULL once
--   every write path populates it and existing rows are backfilled.
--
-- The partial index on (grant_id) WHERE revoked_at IS NULL optimizes the common
-- lookup pattern: find active sessions for a grant in order to revoke them.
SET lock_timeout = '3s';
SET statement_timeout = '30s';

ALTER TABLE sessions ADD COLUMN grant_id UUID REFERENCES grants(id);

CREATE INDEX idx_sessions_grant_id ON sessions (grant_id)
    WHERE revoked_at IS NULL;
