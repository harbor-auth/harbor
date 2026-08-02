-- 0016_relay_addresses (up) — per-(user, RP) email relay mapping (DESIGN §7.5).
--
-- Stores the mapping from opaque relay tokens to user+client pairs. Each user
-- gets one unique, unlinkable relay address per RP. The relay_token is randomly
-- generated (not derived from user_id) so two RPs' addresses for the same user
-- are uncorrelated.
--
-- The enc_mapping column holds the envelope-encrypted real email address,
-- region-pinned and never cross-region replicated (§5).
--
-- State lifecycle: Active (forwarding enabled), Deactivated (hard-bounce kill
-- switch), BYO-domain (user's verified vanity domain). Deactivation is
-- independent of login grant revocation (§7.5.4).
--
-- Greenfield schema; follows expand pattern (.agents/db-migrate.md, DESIGN §1.8).
--
-- Fail fast so a stuck migration never stalls the hot path (/authorize, /token).
SET lock_timeout = '3s';
SET statement_timeout = '30s';

CREATE TABLE relay_addresses (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    relay_token     text NOT NULL,              -- opaque, unlinkable token (random, not user-id-derived)
    user_id         uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    client_id       text NOT NULL REFERENCES relying_parties (client_id),
    state           text NOT NULL DEFAULT 'active',  -- 'active' | 'deactivated' | 'byo_domain'
    enc_mapping     bytea NOT NULL,             -- envelope-encrypted real email address
    region          text NOT NULL,              -- user's home region; mapping never leaves this region
    created_at      timestamptz NOT NULL DEFAULT now(),
    deactivated_at  timestamptz,                -- NULL while active; set on deactivation

    -- state must be one of the known values
    CONSTRAINT relay_addresses_state_valid CHECK (state IN ('active', 'deactivated', 'byo_domain'))
);

-- Index for fast lookup by relay_token (the inbound MTA path).
CREATE UNIQUE INDEX idx_relay_addresses_relay_token ON relay_addresses (relay_token);

-- Unique constraint: one relay address per (user, client) pair.
-- This enforces the "mint one per (user, RP)" invariant.
CREATE UNIQUE INDEX idx_relay_addresses_user_client ON relay_addresses (user_id, client_id);

-- Index for user-centric queries (list all relay addresses for a user).
CREATE INDEX idx_relay_addresses_user_id ON relay_addresses (user_id);

-- BYO domains are user-owned, region-pinned domain verification challenges.
-- A domain can have only one owner globally: accepting duplicate registrations
-- would let a second user race or overwrite the legitimate owner's challenge.
CREATE TABLE byo_domains (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    domain          text NOT NULL UNIQUE,
    user_id         uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    challenge_token text NOT NULL,
    state           text NOT NULL DEFAULT 'pending',
    region          text NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    verified_at     timestamptz,
    expires_at      timestamptz NOT NULL,

    CONSTRAINT byo_domains_state_valid CHECK (state IN ('pending', 'verified', 'active', 'failed'))
);

-- Supports owner-scoped listing and ensures ownership checks stay indexed.
CREATE INDEX idx_byo_domains_user_id ON byo_domains (user_id);
