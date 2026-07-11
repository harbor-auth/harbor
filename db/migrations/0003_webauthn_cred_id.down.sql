-- 0003_webauthn_cred_id (down) — remove webauthn_cred_id from credentials.
SET lock_timeout = '3s';
SET statement_timeout = '30s';

DROP INDEX IF EXISTS idx_credentials_webauthn_cred_id;

ALTER TABLE credentials DROP CONSTRAINT credentials_type_fields;
ALTER TABLE credentials ADD CONSTRAINT credentials_type_fields CHECK (
    (type = 'passkey' AND webauthn_pubkey IS NOT NULL)
    OR (type = 'password' AND password_hash IS NOT NULL)
);

ALTER TABLE credentials DROP COLUMN webauthn_cred_id;
