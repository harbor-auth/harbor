-- 0003_webauthn_cred_id (up) — add webauthn_cred_id to credentials.
--
-- The WebAuthn credential ID (rawID returned by the authenticator) is distinct
-- from the stored public key and AAGUID. It is required to look up which
-- credential is being asserted during login (the assertion identifies itself by
-- credential ID, not public key). Without it, FinishLogin cannot resolve the
-- credential row.
--
-- This is an EXPAND step on a greenfield schema (no live data). The DB migrate
-- guide (.agents/db-migrate.md) expand/contract pattern applies to live tables;
-- here we can add NOT NULL directly.
SET lock_timeout = '3s';
SET statement_timeout = '30s';

ALTER TABLE credentials
    ADD COLUMN webauthn_cred_id bytea;

-- Update the type-field consistency constraint to also require webauthn_cred_id
-- for passkeys. Drop old, add new (greenfield: no live rows, no lock concerns).
ALTER TABLE credentials DROP CONSTRAINT credentials_type_fields;
ALTER TABLE credentials ADD CONSTRAINT credentials_type_fields CHECK (
    (type = 'passkey' AND webauthn_pubkey IS NOT NULL AND webauthn_cred_id IS NOT NULL)
    OR (type = 'password' AND password_hash IS NOT NULL)
);

CREATE UNIQUE INDEX idx_credentials_webauthn_cred_id ON credentials (webauthn_cred_id)
    WHERE webauthn_cred_id IS NOT NULL;
