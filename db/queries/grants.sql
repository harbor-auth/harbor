-- Queries for the grants table. The query IS the contract (DESIGN §1.3):
-- `sqlc generate` (via @codegen) produces typed Go — never hand-write DB types.

-- name: GetGrant :one
SELECT * FROM grants
WHERE id = $1;

-- name: ListGrantsByUser :many
SELECT * FROM grants
WHERE user_id = $1
  AND revoked_at IS NULL
ORDER BY created_at DESC;

-- name: CreateGrant :one
INSERT INTO grants (
    id, region, user_id, client_id, pairwise_sub, scopes
) VALUES (
    $1, $2, $3, $4, $5, $6
)
RETURNING *;

-- name: RevokeGrant :exec
UPDATE grants
SET revoked_at = now()
WHERE id = $1
  AND revoked_at IS NULL;
