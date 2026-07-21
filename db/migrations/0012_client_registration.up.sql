-- 0012_client_registration (up) — add columns to relying_parties for RFC 7591
-- dynamic client registration and RFC 7592 client management.
--
-- Expand pattern (docs/DESIGN.md §1.8, .agents/db-migrate.md):
--   Phase 1 (this file): additive ALTERs with NULLABLE columns so existing
--   statically-registered clients continue working. Dynamic clients will
--   populate these fields at registration time.
--
-- All columns are nullable to support existing rows (statically-registered
-- clients that predate dynamic registration).
SET lock_timeout = '3s';
SET statement_timeout = '30s';

-- client_secret_hash: Argon2id hash of the client_secret for confidential clients.
-- NULL for public clients or clients using other auth methods.
ALTER TABLE relying_parties ADD COLUMN client_secret_hash bytea;

-- registration_access_token_hash: SHA-256 hash of the registration access token
-- (RFC 7592) used to read/update/delete the client registration. NULL for
-- statically-registered clients.
ALTER TABLE relying_parties ADD COLUMN registration_access_token_hash bytea;

-- grant_types: OAuth 2.0 grant types the client may use (e.g. 'authorization_code',
-- 'refresh_token'). NULL defaults to ['authorization_code'] per RFC 7591 §2.
ALTER TABLE relying_parties ADD COLUMN grant_types text[];

-- response_types: OAuth 2.0 response types the client may use (e.g. 'code').
-- NULL defaults to ['code'] per RFC 7591 §2.
ALTER TABLE relying_parties ADD COLUMN response_types text[];

-- token_endpoint_auth_method: client authentication method at the token endpoint
-- (e.g. 'client_secret_basic', 'client_secret_post', 'none'). NULL defaults to
-- 'client_secret_basic' per RFC 7591 §2.
ALTER TABLE relying_parties ADD COLUMN token_endpoint_auth_method text;

-- created_at: timestamp when the client was registered. NULL for legacy
-- statically-registered clients that predate this column.
ALTER TABLE relying_parties ADD COLUMN created_at timestamptz;
