-- Queries for the sessions table (opaque, rotating, one-time-use refresh
-- tokens; DESIGN §3.5, §10). The query IS the contract (DESIGN §1.3):
-- `sqlc generate` (via @codegen) produces typed Go — never hand-write DB types.

-- name: GetSession :one
SELECT * FROM sessions
WHERE id = $1;

-- GetActiveSession returns a session ONLY when it is still usable — not revoked
-- and not expired. Auth flows (refresh-token rotation; DESIGN §3.5) MUST use
-- this rather than GetSession, which returns revoked/expired rows for
-- admin/audit purposes.
-- name: GetActiveSession :one
SELECT * FROM sessions
WHERE id = $1
  AND revoked_at IS NULL
  AND expires_at > now();

-- name: ListSessionsByUser :many
SELECT * FROM sessions
WHERE user_id = $1
  AND revoked_at IS NULL
ORDER BY created_at DESC;

-- name: CreateSession :one
INSERT INTO sessions (
    id, region, user_id, device_label, refresh_token_hash, expires_at
) VALUES (
    $1, $2, $3, $4, $5, $6
)
RETURNING *;

-- name: RevokeSession :exec
UPDATE sessions
SET revoked_at = now()
WHERE id = $1
  AND revoked_at IS NULL;

-- RevokeSessionsByUser revokes every active session for a user (e.g. "sign out
-- everywhere", or a forced logout on credential change; DESIGN §9).
-- name: RevokeSessionsByUser :exec
UPDATE sessions
SET revoked_at = now()
WHERE user_id = $1
  AND revoked_at IS NULL;

-- DeleteExpiredSessions reaps rows whose refresh token has expired — background
-- cleanup, off the hot path.
-- name: DeleteExpiredSessions :exec
DELETE FROM sessions
WHERE expires_at < now();
