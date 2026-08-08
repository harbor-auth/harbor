-- 0021_federated_identities (down) — drop the corporate-SSO identity mapping
-- table.
SET lock_timeout = '3s';
SET statement_timeout = '30s';

DROP INDEX IF EXISTS idx_federated_identities_user;
DROP TABLE IF EXISTS federated_identities;
