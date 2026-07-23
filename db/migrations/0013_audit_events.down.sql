-- 0013_audit_events (down) — remove the payload_encrypted column added in the
-- up migration.
SET lock_timeout = '3s';
SET statement_timeout = '30s';

ALTER TABLE audit_events DROP COLUMN IF EXISTS payload_encrypted;
