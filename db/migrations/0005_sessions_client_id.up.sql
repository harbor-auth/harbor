-- 0005_sessions_client_id (up) — add client_id column to sessions so the
-- theft-signal revoke can be scoped to a (user, client) family rather than
-- revoking every session the user has across all RPs (DESIGN §3.5, §11.7).
--
-- Expand pattern (docs/DESIGN.md §1.8, .agents/db-migrate.md):
--   Phase 1 (this file): additive ALTER with NOT NULL DEFAULT ''. The DEFAULT
--   keeps any legacy INSERT that omits client_id working — the application
--   code landing alongside this migration always writes the real client_id, so
--   the default is only a safety net for the migration window.
--   Phase 2 (future, optional): DROP DEFAULT once every deploy path writes
--   client_id explicitly.
--
-- Greenfield schema (no live rows today) so the ALTER is instant, but we
-- follow the expand pattern for forward-compat with the first real deploy.
SET lock_timeout = '3s';
SET statement_timeout = '30s';

ALTER TABLE sessions ADD COLUMN client_id text NOT NULL DEFAULT '';

CREATE INDEX idx_sessions_user_client ON sessions (user_id, client_id)
    WHERE revoked_at IS NULL;
