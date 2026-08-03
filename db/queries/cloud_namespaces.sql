-- Queries for the cloud_namespaces table (Harbor Cloud management API
-- contract; openspec/changes/harbor-cloud-management-api-contract-2ee993ea).
-- The query IS the contract (DESIGN §1.3): `sqlc generate` (via @codegen)
-- produces typed Go — never hand-write DB types.

-- name: CreateCloudNamespace :one
-- Creates a new namespace provisioning record. The id is caller-supplied
-- (Harbor Cloud mints it); a duplicate id violates the primary key and the
-- caller maps that to 409 namespace_already_exists.
INSERT INTO cloud_namespaces (
    id, status
) VALUES (
    $1, $2
)
RETURNING *;

-- name: GetCloudNamespace :one
-- Returns the namespace row regardless of deleted_at — the caller decides
-- whether a soft-deleted row should be treated as not-found (mirrors the
-- sessions store's "let the caller interpret lifecycle state" pattern).
SELECT * FROM cloud_namespaces
WHERE id = $1;

-- name: SoftDeleteCloudNamespace :exec
-- Marks a namespace deleted. Affects zero rows for an absent or
-- already-deleted namespace — the caller's DELETE handler treats that as
-- success (idempotent delete: 204, always).
UPDATE cloud_namespaces
SET deleted_at = now(),
    updated_at = now()
WHERE id = $1
  AND deleted_at IS NULL;
