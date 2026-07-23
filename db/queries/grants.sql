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

-- name: FindGrantByUserClient :one
SELECT * FROM grants
WHERE user_id = $1
  AND client_id = $2
  AND revoked_at IS NULL;

-- ListGrantsByClient returns all active grants for a specific client. Used
-- during client deletion (RFC 7592) to identify affected users.
-- name: ListGrantsByClient :many
SELECT * FROM grants
WHERE client_id = $1
  AND revoked_at IS NULL
ORDER BY created_at DESC;

-- RevokeGrantsByClient revokes all active grants for a specific client. Used
-- during client deletion (RFC 7592) to clean up user authorizations.
-- name: RevokeGrantsByClient :exec
UPDATE grants
SET revoked_at = now()
WHERE client_id = $1
  AND revoked_at IS NULL;

-- FindGrantByPPID looks up an active grant by its pairwise_sub (PPID) and
-- client_id. Used during RP-Initiated Logout to reverse-lookup the userID from
-- the id_token_hint's sub claim without exposing internal user IDs to RPs.
-- name: FindGrantByPPID :one
SELECT * FROM grants
WHERE pairwise_sub = $1
  AND client_id = $2
  AND revoked_at IS NULL;
