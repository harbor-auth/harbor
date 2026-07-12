-- 0004_sessions_by_hash_index (down) — remove the UNIQUE index on
-- sessions.refresh_token_hash added in the up migration.
SET lock_timeout = '3s';
SET statement_timeout = '30s';

DROP INDEX IF EXISTS idx_sessions_refresh_token_hash;
