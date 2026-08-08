-- Queries for the relying_parties table (RP/client registry; DESIGN §10, §3.2).
-- The query IS the contract (DESIGN §1.3): `sqlc generate` (via @codegen)
-- produces typed Go — never hand-write DB types.

-- GetRelyingParty backs client authentication on the hot path (/token,
-- /authorize, /introspect, /revoke), so the deleted_at filter is not
-- cosmetic: it is what makes a namespaced client's soft-delete
-- (SoftDeleteNamespacedClient) actually stop that client from authenticating.
--
-- H2 defence in depth: also reject a client whose OWNING namespace is
-- soft-deleted, not just a client that is itself soft-deleted. The primary
-- fix for the create-time TOCTOU race is CreateNamespacedClient's
-- INSERT ... WHERE EXISTS (this file) — that closes the race at the source,
-- so in steady state this join rarely rejects anything. Do not mistake that for
-- it being optional: this join is the LOAD-BEARING guard for the security
-- consequence. CreateNamespacedClient's FOR SHARE closes the create-side race,
-- but this is what re-checks namespace liveness on EVERY authentication, so no
-- orphan — a live relying_parties row under a dead cloud_namespaces row,
-- however it came to exist (a bug elsewhere, a manual DB fix gone wrong, future
-- code inserting without the guard) — can ever reach /token. It mirrors the
-- two-layer pattern H1 already uses for
-- token_endpoint_auth_method (resolveExplicitAuthMethod +
-- validateAuthMethodSecretPairing in internal/cloudapi/clients.go). The LEFT
-- JOIN is a single indexed primary-key lookup against cloud_namespaces (a
-- small table), so the added cost on this hot path is one extra index probe,
-- not a scan — mirrors GetActiveSession's identical
-- LEFT-JOIN-plus-NULL-tolerant-filter shape (db/queries/sessions.sql).
-- The `namespace_id IS NULL OR cloud_namespaces.deleted_at IS NULL` clause is
-- required, not optional: namespace_id IS NULL is the PERMANENT, legitimate
-- state for every operator-registered or dynamically-RFC-7591-registered
-- client (0020_relying_parties_namespace.up.sql) — without the IS NULL
-- escape hatch this join would reject every non-cloud client in the system.
-- Correctness also depends on the FK added by that migration: a DANGLING
-- namespace_id would be NULL-extended by the LEFT JOIN and therefore ALLOWED,
-- and it is the FK to cloud_namespaces(id) that makes such a row impossible.
-- name: GetRelyingParty :one
SELECT relying_parties.* FROM relying_parties
LEFT JOIN cloud_namespaces ON cloud_namespaces.id = relying_parties.namespace_id
WHERE relying_parties.client_id = $1
  AND relying_parties.deleted_at IS NULL
  AND (relying_parties.namespace_id IS NULL OR cloud_namespaces.deleted_at IS NULL);

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
--
-- H2 TOCTOU: cloudapi.PostAdminV1NamespacesClients checks namespaceActive
-- BEFORE calling this, but that check and this INSERT are two separate
-- statements — a concurrent DELETE /admin/v1/namespaces/{id} can soft-delete
-- the namespace in between, producing a live client owned by a dead tenant
-- (invisible to every namespaced route, since namespaceActive 404s on the
-- now-deleted namespace, and never stopped from authenticating at /token).
-- The WHERE EXISTS below collapses the liveness check and the insert into ONE
-- statement, which removes the Go-level window (a full round-trip) entirely.
--
-- It does NOT by itself make this race-free, and it is worth being precise
-- about why: under READ COMMITTED the sub-select takes a snapshot, not a lock,
-- so a concurrent soft-delete can commit between the EXISTS evaluating true and
-- this INSERT committing. The FK does not help either — the insert's FK check
-- takes FOR KEY SHARE on the parent while a soft-delete is a non-key UPDATE
-- taking FOR NO KEY UPDATE, and those two do not conflict. This was reproduced
-- against a real Postgres 16 before FOR SHARE was added.
--
-- FOR SHARE is what actually closes it: it conflicts with the soft-delete's
-- FOR NO KEY UPDATE, so the delete blocks until this statement commits.
-- Concurrent creates in the same namespace still do not block each other (the
-- lock is shared), and there is no lock-order cycle with the delete cascade,
-- because this inserts a NEW row and so never waits on rows the cascade holds.
--
-- The Go layer's pre-check stays as the fast, clear 404 for the common
-- non-racing case. Note that GetRelyingParty's join against cloud_namespaces is
-- the load-bearing guard for the security consequence: it re-checks namespace
-- liveness on every authentication, so even an orphan that somehow existed
-- could never reach /token.
-- name: CreateNamespacedClient :one
INSERT INTO relying_parties (
    client_id, name, sector_id, redirect_uris, token_format, scopes_allowed,
    client_secret_hash, grant_types, response_types, token_endpoint_auth_method,
    created_at, namespace_id
)
SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12
WHERE EXISTS (
    SELECT 1 FROM cloud_namespaces WHERE id = $12 AND deleted_at IS NULL FOR SHARE
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
