-- Queries for the audit_events table (the user-visible auth trail; DESIGN §10,
-- §11.6). This log is APPEND-ONLY — no update/delete — so users get a truthful,
-- tamper-evident history. The query IS the contract (DESIGN §1.3): `sqlc
-- generate` (via @codegen) produces typed Go — never hand-write DB types.

-- name: CreateAuditEvent :one
INSERT INTO audit_events (
    id, region, user_id, event_type, client_id
) VALUES (
    $1, $2, $3, $4, $5
)
RETURNING *;

-- CreateAuditEventWithPayload inserts an event with an envelope-encrypted
-- payload (DESIGN §4.4, §10). The payload_encrypted column holds ciphertext
-- under the user's DEK; the operator sees only event_type + timestamp.
-- name: CreateAuditEventWithPayload :one
INSERT INTO audit_events (
    id, region, user_id, event_type, client_id, payload_encrypted
) VALUES (
    $1, $2, $3, $4, $5, $6
)
RETURNING *;

-- ListAuditEventsByUser powers the dashboard audit-log viewer (DESIGN §9).
-- Newest-first with limit/offset paging, served by idx_audit_events_user_time.
-- name: ListAuditEventsByUser :many
SELECT * FROM audit_events
WHERE user_id = $1
ORDER BY occurred_at DESC
LIMIT $2 OFFSET $3;

-- ListAuditEventsByUserWithPayload returns events including payload_encrypted
-- so the caller can decrypt under the user's DEK (DESIGN §4.4). Only the
-- owning user's endpoint decrypts; the operator has no plaintext read path.
-- name: ListAuditEventsByUserWithPayload :many
SELECT * FROM audit_events
WHERE user_id = $1
ORDER BY occurred_at DESC
LIMIT $2 OFFSET $3;
