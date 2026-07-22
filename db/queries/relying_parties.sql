-- Queries for the relying_parties table (RP/client registry; DESIGN §10, §3.2).
-- The query IS the contract (DESIGN §1.3): `sqlc generate` (via @codegen)
-- produces typed Go — never hand-write DB types.

-- name: GetRelyingParty :one
SELECT * FROM relying_parties
WHERE client_id = $1;

-- name: ListRelyingParties :many
SELECT * FROM relying_parties
ORDER BY client_id;

-- name: UpsertRelyingParty :one
INSERT INTO relying_parties (
    client_id, name, sector_id, redirect_uris, token_format, scopes_allowed
) VALUES (
    $1, $2, $3, $4, $5, $6
)
ON CONFLICT (client_id) DO UPDATE
    SET name           = EXCLUDED.name,
        sector_id      = EXCLUDED.sector_id,
        redirect_uris  = EXCLUDED.redirect_uris,
        token_format   = EXCLUDED.token_format,
        scopes_allowed = EXCLUDED.scopes_allowed
RETURNING *;

-- CreateRegisteredClient inserts a dynamically-registered client (RFC 7591).
-- Includes all new columns from migration 0012 for dynamic registration.
-- name: CreateRegisteredClient :one
INSERT INTO relying_parties (
    client_id, name, sector_id, redirect_uris, token_format, scopes_allowed,
    client_secret_hash, registration_access_token_hash,
    grant_types, response_types, token_endpoint_auth_method, created_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12
)
RETURNING *;

-- GetRegisteredClient retrieves a client by its registration_access_token_hash
-- (RFC 7592 client configuration endpoint). Returns sql.ErrNoRows if no match.
-- name: GetRegisteredClient :one
SELECT * FROM relying_parties
WHERE registration_access_token_hash = $1;

-- UpdateRegisteredClient updates a dynamically-registered client's metadata
-- (RFC 7592 PUT). Only fields that can be updated post-registration are
-- included; client_id, sector_id, and created_at are immutable.
-- name: UpdateRegisteredClient :one
UPDATE relying_parties
SET name                           = $2,
    redirect_uris                  = $3,
    token_format                   = $4,
    scopes_allowed                 = $5,
    client_secret_hash             = $6,
    registration_access_token_hash = $7,
    grant_types                    = $8,
    response_types                 = $9,
    token_endpoint_auth_method     = $10
WHERE client_id = $1
RETURNING *;

-- DeleteRelyingParty removes a client registration (RFC 7592 DELETE). Used for
-- dynamic client de-registration. Cascades to grants via FK.
-- name: DeleteRelyingParty :exec
DELETE FROM relying_parties
WHERE client_id = $1;
