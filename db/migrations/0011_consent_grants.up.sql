-- 0011_consent_grants (up) — per-(user, RP, scope) consent ledger (DESIGN §11).
--
-- Tracks explicit user consent for each RP and scope set. Enforced at /authorize
-- to ensure users have granted consent before tokens are issued. Grant/revoke
-- exposed via harbor-mgmt API.
--
-- Only one active consent record per (user, client) pair is allowed; the partial
-- unique index enforces this by excluding revoked rows.
--
-- Greenfield schema; follows expand pattern (.agents/db-migrate.md, DESIGN §1.8).
--
-- Fail fast so a stuck migration never stalls the hot path (/authorize, /token).
SET lock_timeout = '3s';
SET statement_timeout = '30s';

CREATE TABLE consent_grants (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    client_id   text NOT NULL REFERENCES relying_parties (client_id),
    scopes      text[] NOT NULL DEFAULT '{}',   -- canonical sorted scope set
    granted_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    revoked_at  timestamptz                     -- NULL while consent is active
);

-- Index for user-centric queries (list all consents for a user).
CREATE INDEX idx_consent_grants_user_id ON consent_grants (user_id);

-- Partial unique index: only one active (non-revoked) consent per (user, client).
-- Revoked rows are excluded, allowing historical records while enforcing the
-- single-active-consent invariant.
CREATE UNIQUE INDEX idx_consent_grants_user_client_active
    ON consent_grants (user_id, client_id)
    WHERE revoked_at IS NULL;
