-- Queries for the relay_addresses table (DESIGN §7.5). The query IS the contract
-- (DESIGN §1.3): `sqlc generate` (via @codegen) produces typed Go — never
-- hand-write DB types. Stores per-(user, RP) email relay mappings with
-- envelope-encrypted real email, region-pinned and never cross-region replicated.

-- name: CreateRelayAddress :one
-- Mints a new relay address for a (user, client) pair. The unique index
-- idx_relay_addresses_user_client enforces one relay address per (user, RP).
-- The relay_token is an opaque, unlinkable token (randomly generated, not
-- derived from user_id). The enc_mapping holds the envelope-encrypted real
-- email address.
INSERT INTO relay_addresses (
    relay_token, user_id, client_id, state, enc_mapping, region
) VALUES (
    $1, $2, $3, $4, $5, $6
)
RETURNING *;

-- name: GetRelayAddressByToken :one
-- Region-pinned lookup by relay_token — the inbound MTA path. The caller MUST
-- verify the region matches the user's home region (regional data residency).
-- Returns the full row including enc_mapping for decryption.
SELECT * FROM relay_addresses
WHERE relay_token = $1;

-- name: GetActiveRelayAddressByToken :one
-- Region-pinned lookup by relay_token for active addresses only. Used by the
-- inbound MTA to reject mail to deactivated addresses (hard-bounce kill switch).
SELECT * FROM relay_addresses
WHERE relay_token = $1
  AND state = 'active';

-- name: GetRelayAddressByUserClient :one
-- Lookup by (user_id, client_id) pair — used to check if a relay address
-- already exists before minting a new one.
SELECT * FROM relay_addresses
WHERE user_id = $1
  AND client_id = $2;

-- name: ListRelayAddressesByUser :many
-- Lists all relay addresses for a user, ordered by most recent first.
-- Used by harbor-mgmt to show the user their relay addresses per RP.
SELECT * FROM relay_addresses
WHERE user_id = $1
ORDER BY created_at DESC;

-- name: DeactivateRelayAddress :exec
-- Deactivates a relay address (hard-bounce kill switch). Sets state to
-- 'deactivated' and records deactivated_at timestamp. Deactivation is
-- independent of login grant revocation (§7.5.4).
UPDATE relay_addresses
SET state = 'deactivated',
    deactivated_at = now()
WHERE id = $1
  AND state = 'active';

-- name: DeactivateRelayAddressByUserClient :exec
-- Deactivates a relay address by (user_id, client_id) pair. Convenience
-- method for when the caller has the user/client but not the address ID.
UPDATE relay_addresses
SET state = 'deactivated',
    deactivated_at = now()
WHERE user_id = $1
  AND client_id = $2
  AND state = 'active';

-- name: ReactivateRelayAddress :exec
-- Reactivates a previously deactivated relay address. Clears deactivated_at
-- and sets state back to 'active'.
UPDATE relay_addresses
SET state = 'active',
    deactivated_at = NULL
WHERE id = $1
  AND state = 'deactivated';

-- name: SetRelayAddressBYODomain :exec
-- Transitions a relay address to BYO-domain state after the user has verified
-- ownership of their custom domain.
UPDATE relay_addresses
SET state = 'byo_domain'
WHERE id = $1
  AND state = 'active';
