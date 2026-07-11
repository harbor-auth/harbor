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

-- name: SetUserStatus :exec
UPDATE users
SET status = $2
WHERE id = $1;
