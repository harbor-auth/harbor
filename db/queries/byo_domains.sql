-- Queries for user-owned BYO-domain verification challenges. Domain names are
-- globally unique, while reads by name are owner-scoped to avoid disclosing
-- another user's registration.

-- name: CreateBYODomain :one
INSERT INTO byo_domains (
    id, domain, user_id, challenge_token, state, region, created_at, verified_at, expires_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9
)
RETURNING *;

-- name: GetBYODomainByName :one
SELECT * FROM byo_domains
WHERE user_id = $1
  AND domain = $2;

-- name: ListBYODomainsByUser :many
SELECT * FROM byo_domains
WHERE user_id = $1
ORDER BY created_at DESC;

-- name: UpdateBYODomainState :one
UPDATE byo_domains
SET state = $2,
    verified_at = CASE WHEN $2 = 'verified' THEN now() ELSE verified_at END
WHERE id = $1
RETURNING *;

-- name: DeleteBYODomain :one
DELETE FROM byo_domains
WHERE id = $1
RETURNING id;
