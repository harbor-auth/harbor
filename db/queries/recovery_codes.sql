-- Queries for the recovery_codes and recovery_attempts tables (DESIGN §10,
-- fail-closed account recovery). The query IS the contract (DESIGN §1.3):
-- `sqlc generate` (via @codegen) produces typed Go — never hand-write DB types.
-- All codes are stored as hashed bytea with per-code salt — never plaintext.

-- name: InsertRecoveryCodes :copyfrom
-- Batch insert recovery codes for a user. Used when generating a new set of
-- recovery codes (typically 10 codes at enrollment time).
INSERT INTO recovery_codes (
    id, user_id, code_hash, salt, created_at
) VALUES (
    $1, $2, $3, $4, $5
);

-- name: GetRecoveryCodesByUser :many
-- Retrieves all recovery codes for a user (used and unused).
-- Caller uses this to validate a submitted code against the hashes.
SELECT * FROM recovery_codes
WHERE user_id = $1
ORDER BY created_at;

-- name: ConsumeRecoveryCode :one
-- Atomically marks a recovery code as used (only if unused). Returns the
-- updated row if successful, or no rows if the code was already used.
-- This is the core fail-closed operation: a code can only be consumed once.
UPDATE recovery_codes
SET used_at = now()
WHERE id = $1
  AND used_at IS NULL
RETURNING *;

-- name: CountUnusedCodes :one
-- Counts remaining unused recovery codes for a user. Used to warn users
-- when they're running low on codes and should generate new ones.
SELECT COUNT(*) FROM recovery_codes
WHERE user_id = $1
  AND used_at IS NULL;

-- name: DeleteRecoveryCodesByUser :exec
-- Deletes all recovery codes for a user. Used when regenerating codes
-- (old codes are invalidated when new ones are issued).
DELETE FROM recovery_codes
WHERE user_id = $1;

-- name: GetRecoveryAttempts :one
-- Gets the current lockout state for a user. Returns NULL if no record
-- exists (user has never failed a recovery attempt).
SELECT * FROM recovery_attempts
WHERE user_id = $1;

-- name: UpsertRecoveryAttempts :one
-- Upserts the recovery attempts record for a user. Used to increment
-- failed_count or set locked_until after too many failures.
INSERT INTO recovery_attempts (
    user_id, failed_count, locked_until
) VALUES (
    $1, $2, $3
)
ON CONFLICT (user_id)
DO UPDATE SET
    failed_count = EXCLUDED.failed_count,
    locked_until = EXCLUDED.locked_until
RETURNING *;

-- name: ResetRecoveryAttempts :exec
-- Resets the lockout state for a user after successful recovery.
-- Clears failed_count and locked_until.
UPDATE recovery_attempts
SET failed_count = 0,
    locked_until = NULL
WHERE user_id = $1;
