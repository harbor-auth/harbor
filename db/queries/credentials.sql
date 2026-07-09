-- Queries for the credentials table (passkeys + optional password; DESIGN §10,
-- §3.1). The query IS the contract (DESIGN §1.3): `sqlc generate` (via @codegen)
-- produces typed Go — never hand-write DB types.

-- name: GetCredential :one
SELECT * FROM credentials
WHERE id = $1;

-- name: ListCredentialsByUser :many
SELECT * FROM credentials
WHERE user_id = $1
ORDER BY created_at DESC;

-- name: CreateCredential :one
INSERT INTO credentials (
    id, region, user_id, type, webauthn_pubkey, webauthn_aaguid, sign_count, password_hash
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8
)
RETURNING *;

-- UpdateCredentialSignCount advances a passkey's signature counter after an
-- assertion — a monotonically increasing counter is how WebAuthn detects a
-- cloned authenticator (DESIGN §3.1). The `sign_count < $2` guard makes the
-- update strictly increasing: an equal or regressed counter is a clone signal
-- and is a no-op here (the caller treats zero rows affected as a failure).
-- name: UpdateCredentialSignCount :exec
UPDATE credentials
SET sign_count = $2
WHERE id = $1
  AND sign_count < $2;

-- name: DeleteCredential :exec
DELETE FROM credentials
WHERE id = $1;
