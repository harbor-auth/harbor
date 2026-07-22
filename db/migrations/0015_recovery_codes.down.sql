-- 0015_recovery_codes (down) — drop recovery tables and indexes.
SET lock_timeout = '3s';
SET statement_timeout = '30s';

DROP TABLE IF EXISTS recovery_attempts;
DROP INDEX IF EXISTS idx_recovery_codes_user_code_hash;
DROP INDEX IF EXISTS idx_recovery_codes_user_id;
DROP TABLE IF EXISTS recovery_codes;
