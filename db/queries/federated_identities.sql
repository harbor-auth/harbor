-- Queries for the federated_identities table (db/migrations/0021) — the
-- corporate-SSO handoff's namespace-scoped external-subject -> Harbor user_id
-- mapping. The query IS the contract (DESIGN §1.3): `sqlc generate` produces
-- typed Go — never hand-write DB types.

-- name: GetFederatedIdentity :one
SELECT * FROM federated_identities
WHERE namespace_id = $1 AND subject_hmac = $2 AND key_version = $3;

-- name: CreateFederatedIdentity :one
-- user_id must always be an id THIS request just created via CreateFederatedUser
-- (see internal/cloudapi/federated_store.go's ResolveOrCreateFederatedUser) —
-- this query never binds a federated subject to a pre-existing user.
INSERT INTO federated_identities (
    namespace_id, subject_hmac, key_version, user_id
) VALUES (
    $1, $2, $3, $4
)
RETURNING *;

-- name: TouchFederatedIdentity :exec
-- Bumps last_seen_at on an existing mapping (called on every successful
-- resolve, not just creation, so the row reflects the subject's most recent
-- SSO login).
UPDATE federated_identities
SET last_seen_at = now()
WHERE namespace_id = $1 AND subject_hmac = $2 AND key_version = $3;

-- name: DeleteFederatedIdentitiesByNamespace :exec
-- Removes every federated identity mapping for a namespace. Called when a
-- namespace is deleted (cloud_namespaces soft-delete, internal/cloudapi) so a
-- future namespace id reuse can never resolve through a stale mapping.
DELETE FROM federated_identities
WHERE namespace_id = $1;
