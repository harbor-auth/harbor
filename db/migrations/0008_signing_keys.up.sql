-- 0008_signing_keys (up) — signing key lifecycle table for JWKS kid rotation
-- (DESIGN §7.3, §3.5.4).
--
-- Keys progress through states: pending → active → retired. Exactly one key
-- can be active at any time (the signer). Pending keys are published in JWKS
-- (giving RPs time to cache) but not yet signing. Retired keys are removed
-- from JWKS; tokens with a retired kid are rejected.
--
-- This is an additive CREATE on a greenfield schema; the expand/contract
-- pattern (.agents/db-migrate.md, DESIGN §1.8) applies to FUTURE changes.
--
-- Fail fast so a stuck migration never stalls the hot path (/authorize, /token).
SET lock_timeout = '3s';
SET statement_timeout = '30s';

-- signing_keys — ECDSA P-256 keys for JWT signing; exactly one active at a time.
CREATE TABLE signing_keys (
    id                  uuid PRIMARY KEY,
    kid                 text NOT NULL UNIQUE,   -- key identifier in JWKS (e.g. base64url(SHA256(pubkey)[:8]))
    state               text NOT NULL,          -- pending | active | retired
    public_key_bytes    bytea NOT NULL,         -- DER-encoded ECDSA P-256 public key
    private_key_wrapped bytea NOT NULL,         -- envelope-encrypted private key (wrapped by regional KEK)
    region              text NOT NULL,          -- data sovereignty: key belongs to this jurisdiction
    created_at          timestamptz NOT NULL DEFAULT now(),
    promoted_at         timestamptz,            -- when state changed to 'active'
    retired_at          timestamptz,            -- when state changed to 'retired'

    -- State must be one of the three valid lifecycle states.
    CONSTRAINT signing_keys_state_valid CHECK (state IN ('pending', 'active', 'retired')),

    -- Lifecycle timestamp invariants:
    --   - pending: promoted_at IS NULL, retired_at IS NULL
    --   - active:  promoted_at IS NOT NULL, retired_at IS NULL
    --   - retired: promoted_at IS NOT NULL, retired_at IS NOT NULL
    CONSTRAINT signing_keys_state_timestamps CHECK (
        (state = 'pending' AND promoted_at IS NULL AND retired_at IS NULL)
        OR (state = 'active' AND promoted_at IS NOT NULL AND retired_at IS NULL)
        OR (state = 'retired' AND promoted_at IS NOT NULL AND retired_at IS NOT NULL)
    )
);

-- Partial unique index: enforce exactly one active key at any time.
-- This is the signing key used for all new tokens; there must be exactly one.
CREATE UNIQUE INDEX idx_signing_keys_one_active
    ON signing_keys ((true))
    WHERE state = 'active';

-- Index for JWKS endpoint: quickly fetch all non-retired keys (pending + active).
CREATE INDEX idx_signing_keys_jwks
    ON signing_keys (state)
    WHERE state IN ('pending', 'active');

-- Index by region for multi-region deployments.
CREATE INDEX idx_signing_keys_region ON signing_keys (region);
