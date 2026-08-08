-- 0020_relying_parties_namespace (down) — remove the namespace-ownership and
-- soft-delete columns added in the up migration.
SET lock_timeout = '3s';
SET statement_timeout = '30s';

DROP INDEX IF EXISTS idx_relying_parties_namespace_id;
ALTER TABLE relying_parties DROP COLUMN IF EXISTS deleted_at;
ALTER TABLE relying_parties DROP COLUMN IF EXISTS namespace_id;
