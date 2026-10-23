-- Queries for the credentials table (passkeys + optional password; DESIGN §10,
-- §3.1). The query IS the contract (DESIGN §1.3): `sqlc generate` (via @codegen)
-- produces typed Go — never hand-write DB types.

-- name: GetCredential :one
SELECT * FROM credentials
WHERE id = $1;

-- GetCredentialByWebAuthnCredID resolves a credential by the WebAuthn credential
-- ID (rawID) returned by the authenticator during assertion. Required by the
-- login ceremony to locate which stored passkey is being used (DESIGN §3.1).
-- name: GetCredentialByWebAuthnCredID :one
SELECT * FROM credentials
WHERE webauthn_cred_id = $1;

-- name: ListCredentialsByUser :many
SELECT * FROM credentials
WHERE user_id = $1
ORDER BY created_at DESC;

-- CreateCredential persists a newly-registered passkey. webauthn_cred_id is the
-- opaque rawID from the authenticator (DESIGN §3.1); webauthn_pubkey is the COSE
-- public key; webauthn_aaguid identifies the authenticator model.
-- name: CreateCredential :one
INSERT INTO credentials (
    id, region, user_id, type, webauthn_cred_id, webauthn_pubkey, webauthn_aaguid, sign_count, password_hash, webauthn_flags
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10
)
RETURNING *;

-- Persist signed assertion flags and monotonically increasing counters together.
-- Counterless authenticators may stay at zero. Backup eligibility is immutable
-- once initialized, including if two replicas race to initialize a legacy row.
-- name: UpdateCredentialSignCount :execrows
UPDATE credentials
SET sign_count = $2, webauthn_flags = sqlc.arg(webauthn_flags)::smallint
WHERE id = $1
  AND (sign_count < $2 OR (sign_count = 0 AND $2 = 0))
  AND (webauthn_flags IS NULL
       OR (webauthn_flags & 8) = (sqlc.arg(webauthn_flags)::smallint & 8));

-- name: DeleteCredential :exec
DELETE FROM credentials
WHERE id = $1;
