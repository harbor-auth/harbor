-- Queries for the revocation_outbox table (durable theft-signal delivery;
-- DESIGN §3.5, §3.5.2, §10). The query IS the contract (DESIGN §1.3):
-- `sqlc generate` (via @codegen) produces typed Go — never hand-write DB types.
--
-- The outbox pattern: signalRefreshReuse/signalCodeReuse INSERT here first,
-- then a background worker polls and delivers with retry.

-- name: EnqueueRevocation :one
-- Enqueue a revocation signal for durable delivery. Called by signalRefreshReuse
-- and signalCodeReuse after (or instead of) the inline best-effort attempt.
INSERT INTO revocation_outbox (
    reason, user_id, client_id, grant_id
) VALUES (
    $1, $2, $3, $4
)
RETURNING *;

-- name: FetchPendingRevocations :many
-- Fetch pending revocation signals ready for delivery. Uses FOR UPDATE SKIP
-- LOCKED to allow multiple workers without contention. Limited to batch_size
-- rows to avoid long transactions. Only fetches rows whose next_attempt_at
-- has passed (respecting exponential backoff).
SELECT * FROM revocation_outbox
WHERE status = 'pending'
  AND next_attempt_at <= now()
ORDER BY next_attempt_at ASC
LIMIT $1
FOR UPDATE SKIP LOCKED;

-- name: MarkRevocationDelivered :exec
-- Mark a revocation signal as successfully delivered. Called after
-- RevocationSink.RevokeSessionsByUserClient succeeds.
UPDATE revocation_outbox
SET status = 'delivered'
WHERE id = $1;

-- name: IncrementRevocationRetry :exec
-- Increment retry count and set next attempt time with exponential backoff.
-- Called when delivery fails but retries remain. The caller computes
-- next_attempt_at based on the retry policy (5s, 30s, 5m, 30m, 1h cap).
UPDATE revocation_outbox
SET retry_count = retry_count + 1,
    next_attempt_at = $2
WHERE id = $1;

-- name: MarkRevocationFailed :exec
-- Mark a revocation signal as permanently failed (dead-letter). Called when
-- TTL (24h) expires or max retries exceeded. Triggers alerting.
UPDATE revocation_outbox
SET status = 'failed'
WHERE id = $1;

-- name: DeleteDeliveredRevocations :exec
-- Clean up delivered revocation signals older than the retention period.
-- Background cleanup, off the hot path.
DELETE FROM revocation_outbox
WHERE status = 'delivered'
  AND created_at < $1;

-- name: GetRevocation :one
-- Get a single revocation entry by ID (for debugging/admin).
SELECT * FROM revocation_outbox
WHERE id = $1;

-- name: CountPendingRevocations :one
-- Count pending revocations (for monitoring/alerting).
SELECT COUNT(*) FROM revocation_outbox
WHERE status = 'pending';
