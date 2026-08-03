-- Queries for the cloud_sessions table — short-lived, namespace-scoped
-- provisioning credentials minted for Harbor Cloud (Harbor Cloud management
-- API contract; openspec/changes/harbor-cloud-management-api-contract-2ee993ea).
-- Not an OIDC/BFF session. The query IS the contract (DESIGN §1.3): `sqlc
-- generate` (via @codegen) produces typed Go — never hand-write DB types.

-- name: CreateCloudSession :one
-- Mints a namespace-scoped session. Only token_hash is persisted; the
-- plaintext bearer is returned once by the caller at mint time.
INSERT INTO cloud_sessions (
    session_id, namespace_id, token_hash, expires_at
) VALUES (
    $1, $2, $3, $4
)
RETURNING *;

-- name: GetCloudSession :one
-- Returns the session row regardless of expiry/consumption — the caller
-- decides 410 session_expired / 403 cross_tenant_forbidden from the
-- returned fields rather than have the store hide lifecycle state.
SELECT * FROM cloud_sessions
WHERE session_id = $1;
