-- 0012_client_registration (down) — remove the dynamic client registration
-- columns added in the up migration.
SET lock_timeout = '3s';
SET statement_timeout = '30s';

ALTER TABLE relying_parties DROP COLUMN IF EXISTS created_at;
ALTER TABLE relying_parties DROP COLUMN IF EXISTS token_endpoint_auth_method;
ALTER TABLE relying_parties DROP COLUMN IF EXISTS response_types;
ALTER TABLE relying_parties DROP COLUMN IF EXISTS grant_types;
ALTER TABLE relying_parties DROP COLUMN IF EXISTS registration_access_token_hash;
ALTER TABLE relying_parties DROP COLUMN IF EXISTS client_secret_hash;
