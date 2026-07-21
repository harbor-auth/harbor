-- Queries for the consent_grants table (DESIGN §11). The query IS the contract
-- (DESIGN §1.3): `sqlc generate` (via @codegen) produces typed Go — never
-- hand-write DB types. Tracks per-(user, RP, scope) consent; enforced at
-- /authorize; grant/revoke exposed via harbor-mgmt.

-- name: UpsertConsentGrant :one
-- Inserts a new consent grant or updates an existing active grant's scopes.
-- The partial unique index idx_consent_grants_user_client_active ensures only
-- one active grant per (user, client) pair. On conflict, we update scopes and
-- updated_at to reflect the new consent.
INSERT INTO consent_grants (
    user_id, client_id, scopes
) VALUES (
    $1, $2, $3
)
ON CONFLICT (user_id, client_id) WHERE revoked_at IS NULL
DO UPDATE SET
    scopes = EXCLUDED.scopes,
    updated_at = now()
RETURNING *;

-- name: GetConsentGrantByUserClient :one
-- Retrieves the active consent grant for a (user, client) pair.
-- Returns NULL if no active grant exists (revoked grants are excluded).
SELECT * FROM consent_grants
WHERE user_id = $1
  AND client_id = $2
  AND revoked_at IS NULL;

-- name: ListConsentGrantsByUser :many
-- Lists all active consent grants for a user, ordered by most recent first.
-- Used by harbor-mgmt to show the user their connected apps.
SELECT * FROM consent_grants
WHERE user_id = $1
  AND revoked_at IS NULL
ORDER BY granted_at DESC;

-- name: RevokeConsentGrant :exec
-- Revokes a consent grant by setting revoked_at. Only affects active grants.
-- The partial unique index allows a new grant to be created after revocation.
UPDATE consent_grants
SET revoked_at = now()
WHERE id = $1
  AND revoked_at IS NULL;
