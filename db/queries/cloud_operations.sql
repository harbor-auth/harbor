-- Queries for the cloud_operations table — the idempotency ledger shared by
-- namespace create/delete and session minting (Harbor Cloud management API
-- contract; openspec/changes/harbor-cloud-management-api-contract-2ee993ea).
-- The query IS the contract (DESIGN §1.3): `sqlc generate` (via @codegen)
-- produces typed Go — never hand-write DB types.

-- name: CreateCloudOperation :one
-- Records the first response for a given (idempotency_key, operation) pair.
-- A concurrent duplicate insert violates the primary key; the caller maps
-- that race to the same "replay the existing row" path as a normal lookup.
INSERT INTO cloud_operations (
    idempotency_key, operation, request_hash, response_body
) VALUES (
    $1, $2, $3, $4
)
RETURNING *;

-- name: GetCloudOperation :one
-- Looks up a prior operation by its idempotency key and operation name. The
-- caller compares request_hash to decide between replaying response_body
-- (same hash) and 409 idempotency_key_reused (different hash).
SELECT * FROM cloud_operations
WHERE idempotency_key = $1
  AND operation = $2;
