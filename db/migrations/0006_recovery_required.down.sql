-- 0006_recovery_required (down) — remove the recovery_required column added
-- in the up migration.
SET lock_timeout = '3s';
SET statement_timeout = '30s';

ALTER TABLE users DROP COLUMN IF EXISTS recovery_required;
