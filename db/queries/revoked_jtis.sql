-- Queries for the revoked_jtis table (emergency JWT revocation via bloom filter;
-- DESIGN §3.5). The query IS the contract (DESIGN §1.3): `sqlc generate` (via
-- @codegen) produces typed Go — never hand-write DB types.
--
-- This table is the persistent source of truth for revoked JTIs. The in-process
-- bloom filter is rehydrated from ListActive on startup and kept in sync via
-- Redis pub/sub.

-- InsertRevokedJTI upserts a revoked JTI. On conflict (re-revocation of same
-- JTI), update reason/expires_at to latest values. This is idempotent so
-- retries and duplicate pub/sub messages are safe.
-- name: InsertRevokedJTI :one
INSERT INTO revoked_jtis (jti, reason, expires_at)
VALUES ($1, $2, $3)
ON CONFLICT (jti) DO UPDATE
SET reason = EXCLUDED.reason,
    expires_at = EXCLUDED.expires_at,
    revoked_at = now()
RETURNING *;

-- ListActiveRevokedJTIs returns all JTIs that are still within their JWT's
-- original expiry window. Used to rehydrate the bloom filter on startup.
-- name: ListActiveRevokedJTIs :many
SELECT * FROM revoked_jtis
WHERE expires_at > now()
ORDER BY revoked_at DESC;

-- GetRevokedJTI checks if a specific JTI is revoked. Used for introspection
-- fallback when the bloom filter returns a hit (confirms true positive vs
-- false positive).
-- name: GetRevokedJTI :one
SELECT * FROM revoked_jtis
WHERE jti = $1;

-- GCExpiredRevokedJTIs deletes entries for JWTs that have expired — their JTIs
-- no longer need revocation (the JWT itself is invalid). Run nightly as
-- background cleanup, off the hot path.
-- name: GCExpiredRevokedJTIs :exec
DELETE FROM revoked_jtis
WHERE expires_at < now();
