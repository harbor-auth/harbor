-- Queries for the signing_keys table (JWKS kid rotation; DESIGN §7.3, §3.5.4).
-- The query IS the contract (DESIGN §1.3): `sqlc generate` (via @codegen)
-- produces typed Go — never hand-write DB types.
--
-- Key lifecycle: pending → active → retired. Exactly one key can be active
-- at any time (the signer). Pending keys are published in JWKS (giving RPs
-- time to cache) but not yet signing. Retired keys are removed from JWKS.

-- name: CreateSigningKey :one
-- Creates a new signing key in 'pending' state. The key will be promoted to
-- 'active' after the grace period (allowing RP JWKS cache refresh).
INSERT INTO signing_keys (
    id, kid, state, public_key_bytes, private_key_wrapped, region
) VALUES (
    $1, $2, 'pending', $3, $4, $5
)
RETURNING *;

-- name: GetSigningKeyByKid :one
-- Retrieves a signing key by its kid (key identifier). Used for token
-- verification when the kid is known from the JWT header.
SELECT * FROM signing_keys
WHERE kid = $1;

-- name: GetActiveSigningKey :one
-- Returns the single active signing key used for signing new tokens.
-- The partial unique index idx_signing_keys_one_active guarantees at most one.
SELECT * FROM signing_keys
WHERE state = 'active';

-- name: ListLiveSigningKeys :many
-- Returns all keys that should appear in the JWKS endpoint: pending (new keys
-- awaiting promotion) and active (the current signer). Retired keys are
-- excluded — tokens signed by retired keys will fail verification.
SELECT * FROM signing_keys
WHERE state IN ('pending', 'active')
ORDER BY created_at DESC;

-- name: UpdateSigningKeyState :one
-- Promotes a key from pending → active or active → retired. The caller must
-- set promoted_at when promoting to active, and retired_at when retiring.
-- The CHECK constraint signing_keys_state_timestamps enforces invariants.
UPDATE signing_keys
SET state = $2,
    promoted_at = $3,
    retired_at = $4
WHERE id = $1
RETURNING *;

-- name: RetireSigningKey :one
-- Convenience query to retire a key by kid. Sets state to 'retired' and
-- retired_at to now(). Used during scheduled rotation (after overlap window)
-- or emergency rotation (immediate).
UPDATE signing_keys
SET state = 'retired',
    retired_at = now()
WHERE kid = $1
  AND state IN ('pending', 'active')
RETURNING *;
