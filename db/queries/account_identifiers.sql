-- name: CreateAccountIdentifier :exec
INSERT INTO account_identifiers (user_id, region, kind, lookup_hash, encrypted_value)
VALUES ($1, $2, $3, $4, $5);

-- name: ListAccountIdentifiers :many
SELECT * FROM account_identifiers WHERE user_id = $1 ORDER BY kind;

-- name: FindAccountIdentifier :one
SELECT u.* FROM users u JOIN account_identifiers i ON i.user_id = u.id
WHERE i.region = $1 AND i.kind = $2 AND i.lookup_hash = $3
FOR UPDATE OF u;

-- name: DeleteExpiredPendingSignup :execrows
DELETE FROM users u WHERE u.id = $1 AND u.status = 'pending'
AND u.created_at < now() - interval '20 minutes'
AND NOT EXISTS (SELECT 1 FROM credentials c WHERE c.user_id = u.id);
