-- 0005_sessions_client_id (down) — remove the client_id column and its index
-- added in the up migration.
SET lock_timeout = '3s';
SET statement_timeout = '30s';

DROP INDEX IF EXISTS idx_sessions_user_client;
ALTER TABLE sessions DROP COLUMN IF EXISTS client_id;
