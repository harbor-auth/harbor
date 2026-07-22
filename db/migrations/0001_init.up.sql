-- 0001_init (up) — greenfield baseline schema.
--
-- This is the INITIAL schema, so a plain additive CREATE is correct. The
-- expand/contract pattern (see .agents/db-migrate.md, DESIGN §1.8) applies to
-- FUTURE changes to a live table, not to this baseline.
--
-- Fail fast so a stuck migration never stalls the hot path (/authorize, /token).
SET lock_timeout = '3s';
SET statement_timeout = '30s';

-- users — one row per person; PII lives ONLY in the home region (DESIGN §5, §10).
CREATE TABLE users (
    id              uuid PRIMARY KEY,
    region          text NOT NULL,          -- 'eu' | 'us' | ... (home jurisdiction)
    status          text NOT NULL,          -- active | locked | erased
    dek_wrapped     bytea NOT NULL,         -- per-user DEK, wrapped by regional KEK
    pairwise_secret bytea NOT NULL,         -- HMAC key for PPID derivation (DESIGN §3.2)
    created_at      timestamptz NOT NULL DEFAULT now()
);

-- relying_parties — RP/client registry. Holds NO user data.
CREATE TABLE relying_parties (
    client_id      text PRIMARY KEY,
    name           text NOT NULL,
    sector_id      text NOT NULL,           -- groups redirect URIs for PPID (DESIGN §3.2)
    redirect_uris  text[] NOT NULL DEFAULT '{}',
    token_format   text NOT NULL,           -- 'jwt' | 'opaque'
    scopes_allowed text[] NOT NULL DEFAULT '{}'
);

-- grants — user<->RP consent. pairwise_sub is the PPID this RP sees for this user.
CREATE TABLE grants (
    id           uuid PRIMARY KEY,
    region       text NOT NULL,             -- user-owned row: carries region (DESIGN §10)
    user_id      uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    client_id    text NOT NULL REFERENCES relying_parties (client_id),
    pairwise_sub text NOT NULL,             -- PPID: B64URL(HMAC-SHA256(secret, sector||user))
    scopes       text[] NOT NULL DEFAULT '{}',
    created_at   timestamptz NOT NULL DEFAULT now(),
    revoked_at   timestamptz
);

CREATE INDEX idx_grants_user_id ON grants (user_id);
CREATE UNIQUE INDEX idx_grants_user_client ON grants (user_id, client_id);

-- Deferred to 0002: credentials, mfa_factors, sessions, audit_events (DESIGN §10).
-- This baseline is intentionally a partial slice, not the full data model.
