SET lock_timeout = '3s';
SET statement_timeout = '30s';
-- A reconnect starts a new authorization lifetime, retaining revoked history.
DROP INDEX idx_grants_user_client;
CREATE UNIQUE INDEX idx_grants_user_client ON grants(user_id, client_id) WHERE revoked_at IS NULL;
-- Earlier email consent promised a relay address. Never reinterpret it as
-- permission to disclose the verified real address.
ALTER TABLE grants ADD COLUMN email_consent boolean NOT NULL DEFAULT false;
-- Empty ceilings deliberately invalidate sessions issued before this contract.
ALTER TABLE sessions ADD COLUMN scopes text[] NOT NULL DEFAULT '{}';
ALTER TABLE sessions ADD COLUMN auth_time bigint NOT NULL DEFAULT 0;
ALTER TABLE sessions ADD COLUMN acr text NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN amr text[] NOT NULL DEFAULT '{}';
