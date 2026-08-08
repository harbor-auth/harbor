-- Queries for the users table (DESIGN §10). The query IS the contract (DESIGN
-- §1.3): `sqlc generate` (via @codegen) produces typed Go — never hand-write DB
-- types. All secrets (dek_wrapped, pairwise_secret) are stored as envelope-
-- encrypted bytea — never plaintext (DESIGN §4.4, §10).

-- name: CreateUser :one
INSERT INTO users (
    id, region, status, dek_wrapped, pairwise_secret
) VALUES (
    $1, $2, $3, $4, $5
)
RETURNING *;

-- name: GetUser :one
SELECT * FROM users
WHERE id = $1;

-- name: CreateFederatedUser :one
-- Creates a user record for a corporate-SSO subject (internal/identity's
-- EnrollFederated / internal/cloudapi's ResolveOrCreateFederatedUser).
-- status and recovery_required are SQL literals, not parameters, so no
-- caller can pass anything else:
--   status='active'            — not 'pending' (which means "awaiting
--     first-passkey activation", a ceremony an SSO user will never run: they
--     authenticate at their employer's IdP, never at a Harbor passkey
--     prompt).
--   recovery_required=false    — an SSO user has no Harbor-held credential
--     to recover; their recovery path is their employer's IdP. Issuing
--     Harbor recovery codes would mint a Harbor-local credential that
--     BYPASSES the corporate IdP entirely. `true` would also fence them into
--     SessionScopeEnrollmentOnly, where bff.RequireFullScope 403s the whole
--     dashboard for a user who will never complete the passkey ceremony that
--     clears it.
INSERT INTO users (
    id, region, status, dek_wrapped, pairwise_secret, recovery_required
) VALUES (
    $1, $2, 'active', $3, $4, false
)
RETURNING *;

-- name: SetUserStatus :exec
UPDATE users
SET status = $2
WHERE id = $1;

-- name: SetRecoveryComplete :exec
-- Marks a user as having completed account recovery setup (REQ-005).
-- Called after the user enrolls their recovery credential(s).
UPDATE users
SET recovery_required = false
WHERE id = $1;

-- name: EraseUserDEK :exec
-- Crypto-shreds a user account by atomically overwriting dek_wrapped with
-- an empty byte slice and setting status=erased in a single UPDATE.
-- This destroys the per-user DEK so all envelope-encrypted PII (audit
-- payloads, relay mappings, etc.) becomes permanently unrecoverable in one
-- stroke (DESIGN §compliance-export, invariant 1). NOT a row deletion.
UPDATE users
SET dek_wrapped = '\x'::bytea,
    status      = 'erased'
WHERE id = $1;
