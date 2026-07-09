-- Queries for the mfa_factors table (encrypted TOTP secrets + hashed recovery
-- codes; DESIGN §10). The query IS the contract (DESIGN §1.3): `sqlc generate`
-- (via @codegen) produces typed Go — never hand-write DB types.

-- name: GetMFAFactor :one
SELECT * FROM mfa_factors
WHERE id = $1;

-- name: ListMFAFactorsByUser :many
SELECT * FROM mfa_factors
WHERE user_id = $1
ORDER BY created_at DESC;

-- name: CreateMFAFactor :one
INSERT INTO mfa_factors (
    id, region, user_id, type, secret, code_hash
) VALUES (
    $1, $2, $3, $4, $5, $6
)
RETURNING *;

-- MarkMFAFactorUsed burns a one-time factor (e.g. a recovery code) so it can't
-- be replayed. Only flips unused → used, so a double-spend is a no-op.
-- name: MarkMFAFactorUsed :exec
UPDATE mfa_factors
SET used = true
WHERE id = $1
  AND used = false;

-- name: DeleteMFAFactor :exec
DELETE FROM mfa_factors
WHERE id = $1;
