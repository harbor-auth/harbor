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

-- UpdateGrantScopes records an approved scope set on the canonical grant. It
-- deliberately cannot create a grant because region and pairwise_sub must come
-- from the PPID grant flow, not from consent input.
-- name: UpdateGrantScopes :one
UPDATE grants
SET scopes = $3
WHERE user_id = $1
  AND client_id = $2
  AND revoked_at IS NULL
RETURNING *;

-- RevokeGrantAndSessions is one PostgreSQL statement, so the grant and every
-- refresh session bound to it are revoked atomically on a single connection.
-- The shared timestamp also gives callers an unambiguous audit boundary.
-- name: RevokeGrantAndSessions :one
WITH revoked_grant AS (
    UPDATE grants AS canonical
    SET revoked_at = now()
    WHERE canonical.id = $1
      AND canonical.revoked_at IS NULL
    RETURNING canonical.id, canonical.revoked_at
), revoked_sessions AS (
    UPDATE sessions
    SET revoked_at = revoked_grant.revoked_at
    FROM revoked_grant
    WHERE sessions.grant_id = revoked_grant.id
      AND sessions.revoked_at IS NULL
    RETURNING sessions.id
)
SELECT EXISTS (SELECT 1 FROM revoked_grant) AS grant_revoked,
       count(*)::bigint AS sessions_revoked
FROM revoked_sessions;

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
