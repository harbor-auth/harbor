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
