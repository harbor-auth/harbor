-- 0009_revocation_outbox (down) — drop the revocation outbox table and index.
SET lock_timeout = '3s';
SET statement_timeout = '30s';

DROP INDEX IF EXISTS idx_revocation_outbox_pending;
DROP TABLE IF EXISTS revocation_outbox;
