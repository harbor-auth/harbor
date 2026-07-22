-- 0004_sessions_by_hash_index (up) — add UNIQUE index on sessions.refresh_token_hash.
--
-- The refresh-token rotation path (DESIGN §3.5) must look up a session by its
-- hashed token value, not its UUID.  Without this index the only options are a
-- full-table scan or keeping sessions solely in-memory — both unacceptable.
-- The UNIQUE constraint also enforces the one-token-per-session invariant at
-- the DB level, matching the in-memory guarantee in InMemorySessionStore.
--
-- Greenfield schema (no live rows) so we can add UNIQUE directly without the
-- CONCURRENTLY + NO TRANSACTION ceremony required on live tables
-- (.agents/db-migrate.md). A future production backfill would use CONCURRENTLY.
SET lock_timeout = '3s';
SET statement_timeout = '30s';

CREATE UNIQUE INDEX idx_sessions_refresh_token_hash
    ON sessions (refresh_token_hash);
