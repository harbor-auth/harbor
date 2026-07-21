-- 0011_consent_grants (down) — drop the consent ledger table and indexes.
SET lock_timeout = '3s';
SET statement_timeout = '30s';

DROP INDEX IF EXISTS idx_consent_grants_user_client_active;
DROP INDEX IF EXISTS idx_consent_grants_user_id;
DROP TABLE IF EXISTS consent_grants;
