-- 0006_sessions_grant_id (down) — remove the grant_id column and its partial
-- index added in the up migration.
SET lock_timeout = '3s';
SET statement_timeout = '30s';

DROP INDEX IF EXISTS idx_sessions_grant_id;
ALTER TABLE sessions DROP COLUMN IF EXISTS grant_id;
