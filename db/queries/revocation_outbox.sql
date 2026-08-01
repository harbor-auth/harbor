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
-- Atomically lease pending signals before returning them. A bare SELECT FOR
-- UPDATE is insufficient here because sqlc executes it in its own implicit
-- transaction and releases the locks before delivery. Moving next_attempt_at
-- forward in the same statement ensures sibling replicas cannot claim the
-- same signal while this worker is delivering it. A crashed worker's lease
-- expires after 30 seconds and the durable row becomes eligible again.
WITH claimed AS (
    SELECT id FROM revocation_outbox
    WHERE status = 'pending'
      AND next_attempt_at <= now()
    ORDER BY next_attempt_at ASC
    LIMIT $1
    FOR UPDATE SKIP LOCKED
)
UPDATE revocation_outbox AS outbox
SET next_attempt_at = now() + interval '30 seconds'
FROM claimed
WHERE outbox.id = claimed.id
RETURNING outbox.*;

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
