-- Queries for the relying_parties table (RP/client registry; DESIGN §10, §3.2).
-- The query IS the contract (DESIGN §1.3): `sqlc generate` (via @codegen)
-- produces typed Go — never hand-write DB types.

-- GetRelyingParty backs client authentication on the hot path (/token,
-- /authorize, /introspect, /revoke), so the deleted_at filter is not
-- cosmetic: it is what makes a namespaced client's soft-delete
-- (SoftDeleteNamespacedClient) actually stop that client from authenticating.
-- name: GetRelyingParty :one
SELECT * FROM relying_parties
WHERE client_id = $1
  AND deleted_at IS NULL;

-- name: UpsertRelyingParty :one
INSERT INTO relying_parties (
    client_id, name, sector_id, redirect_uris, token_format, scopes_allowed
) VALUES (
    $1, $2, $3, $4, $5, $6
)
ON CONFLICT (client_id) DO UPDATE
    SET name           = EXCLUDED.name,
        sector_id      = EXCLUDED.sector_id,
        redirect_uris  = EXCLUDED.redirect_uris,
        token_format   = EXCLUDED.token_format,
        scopes_allowed = EXCLUDED.scopes_allowed
RETURNING *;

-- CreateRegisteredClient inserts a dynamically-registered client (RFC 7591).
-- Includes all new columns from migration 0012 for dynamic registration.
-- name: CreateRegisteredClient :one
INSERT INTO relying_parties (
    client_id, name, sector_id, redirect_uris, token_format, scopes_allowed,
    client_secret_hash, registration_access_token_hash,
    grant_types, response_types, token_endpoint_auth_method, created_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12
)
RETURNING *;

-- GetRegisteredClient retrieves a client by its registration_access_token_hash
-- (RFC 7592 client configuration endpoint). Returns sql.ErrNoRows if no match.
-- name: GetRegisteredClient :one
SELECT * FROM relying_parties
WHERE registration_access_token_hash = $1;

-- UpdateRegisteredClient updates a dynamically-registered client's metadata
-- (RFC 7592 PUT). Only fields that can be updated post-registration are
-- included; client_id, sector_id, and created_at are immutable.
-- name: UpdateRegisteredClient :one
UPDATE relying_parties
SET name                           = $2,
    redirect_uris                  = $3,
    token_format                   = $4,
    scopes_allowed                 = $5,
    client_secret_hash             = $6,
    registration_access_token_hash = $7,
    grant_types                    = $8,
    response_types                 = $9,
    token_endpoint_auth_method     = $10
WHERE client_id = $1
RETURNING *;

-- DeleteRelyingParty removes a client registration (RFC 7592 DELETE). Used for
-- dynamic client de-registration. Cascades to grants via FK.
-- name: DeleteRelyingParty :exec
DELETE FROM relying_parties
WHERE client_id = $1;

-- Namespace-scoped OIDC client CRUD (Harbor Cloud management API contract,
-- feat/cloud-oidc-client-provisioning). Every query below takes namespace_id
-- IN THE WHERE CLAUSE, not just as a post-hoc check, so a namespace can never
-- read, update, or delete a client it does not own — cross-tenant access is
-- structurally impossible rather than merely checked.

-- CreateNamespacedClient inserts a client owned by a Harbor Cloud namespace.
-- client_id is caller-supplied (Harbor Cloud mints it per its own scheme,
-- like NamespaceCreateRequest.id) and is the table's primary key, so a
-- duplicate id violates it regardless of which namespace (or no namespace)
-- already owns it; the caller maps that to 409 client_already_exists.
-- registration_access_token_hash is left NULL — this is not an RFC 7591
-- registration, so there is no RFC 7592 configuration-endpoint token.
-- name: CreateNamespacedClient :one
INSERT INTO relying_parties (
    client_id, name, sector_id, redirect_uris, token_format, scopes_allowed,
    client_secret_hash, grant_types, response_types, token_endpoint_auth_method,
    created_at, namespace_id
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12
)
RETURNING *;

-- GetNamespacedClient looks up a client by (client_id, namespace_id). A
-- client_id that exists but is owned by a different namespace, or is
-- soft-deleted, returns sql.ErrNoRows exactly like an absent client_id — the
-- caller must map both to 404 client_not_found, never 403 (403 would confirm
-- the id exists under someone else).
-- name: GetNamespacedClient :one
SELECT * FROM relying_parties
WHERE client_id = $1
  AND namespace_id = $2
  AND deleted_at IS NULL;

-- ListNamespacedClients returns every live client owned by namespace_id.
-- name: ListNamespacedClients :many
SELECT * FROM relying_parties
WHERE namespace_id = $1
  AND deleted_at IS NULL
ORDER BY client_id;

-- UpdateNamespacedClient updates a namespaced client's mutable metadata.
-- client_secret_hash uses COALESCE over a nullable (sqlc.narg) argument: a
-- NULL argument leaves the stored hash untouched, so a caller rotating only
-- redirect_uris does not have to re-submit (or blank out) the secret hash.
-- The WHERE clause requires namespace_id = $2 AND deleted_at IS NULL, so
-- updating a client owned by another namespace, or already deleted, affects
-- zero rows — the caller maps that to 404 client_not_found.
-- name: UpdateNamespacedClient :one
UPDATE relying_parties
SET name                       = $3,
    redirect_uris              = $4,
    scopes_allowed             = $5,
    token_endpoint_auth_method = $6,
    client_secret_hash         = COALESCE(sqlc.narg('client_secret_hash'), client_secret_hash)
WHERE client_id = $1
  AND namespace_id = $2
  AND deleted_at IS NULL
RETURNING *;

-- SoftDeleteNamespacedClient marks a namespaced client deleted. It affects
-- zero rows for an absent client_id, a client owned by a different
-- namespace, or an already-deleted client — the caller's DELETE handler
-- treats all three the same as success (204, always; DESIGN mirrors
-- SoftDeleteCloudNamespace's idempotent-delete contract). A hard DELETE is
-- not possible here: grants.client_id and relay_addresses.client_id
-- reference this table with no ON DELETE CASCADE (0001_init.up.sql,
-- 0016_relay_addresses.up.sql), so deleting a client any user has consented
-- to, or that has an active relay address, would raise SQLSTATE 23503.
-- name: SoftDeleteNamespacedClient :exec
UPDATE relying_parties
SET deleted_at = now()
WHERE client_id = $1
  AND namespace_id = $2
  AND deleted_at IS NULL;

-- SoftDeleteNamespaceClients cascades a namespace's soft-delete to every live
-- client it owns (Harbor Cloud management API H2 fix). Without this,
-- DeleteAdminV1Namespace only marked cloud_namespaces deleted: GetRelyingParty
-- filters relying_parties.deleted_at but never joins cloud_namespaces, so a
-- deleted tenant's clients kept authenticating at /token indefinitely, and
-- namespaceActive's 404-on-deleted-namespace meant an operator could not even
-- enumerate them through the namespaced routes to clean up by hand. Affects
-- zero rows when namespace_id owns no live clients — not an error, mirrors
-- SoftDeleteNamespacedClient's idempotent-no-op-on-zero-rows contract. Called
-- from cloudapi.DeleteAdminV1Namespace as a second, sequential statement, NOT
-- inside the same transaction as SoftDeleteCloudNamespace (cloudapi.Store and
-- clients.DBNamespacedClientStore are separate packages behind narrow
-- querier interfaces with no shared transaction handle — see
-- internal/cloudapi/namespaces.go's DeleteAdminV1Namespace for the ordering
-- this implies and why it is deliberate, not an oversight).
-- name: SoftDeleteNamespaceClients :exec
UPDATE relying_parties
SET deleted_at = now()
WHERE namespace_id = $1
  AND deleted_at IS NULL;
