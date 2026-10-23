SET lock_timeout = '3s';
SET statement_timeout = '30s';
ALTER TABLE credentials DROP COLUMN webauthn_flags;
