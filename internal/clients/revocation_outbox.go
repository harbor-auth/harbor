package clients

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	db "github.com/harbor/harbor/internal/gen/db"
	"github.com/harbor/harbor/internal/oidc"
)

// Retry policy constants (docs/plans/revocation-outbox.md):
// Attempt 1: 5s, Attempt 2: 30s, Attempt 3: 5m, Attempt 4: 30m, Attempt 5+: 1h (cap)
// TTL: 24h (then status='failed', alert)
var retryDelays = []time.Duration{
	5 * time.Second,
	30 * time.Second,
	5 * time.Minute,
	30 * time.Minute,
	1 * time.Hour, // cap
}

// outboxTTL is the maximum age of a pending revocation before it is marked
// as permanently failed (dead-letter). After 24h the token is likely expired
// anyway (default refresh TTL is 14d, but we fail loudly for observability).
const outboxTTL = 24 * time.Hour

// defaultBatchSize is the number of pending revocations fetched per
// DeliverPending call. Small enough to keep transactions short, large enough
// to amortize DB round-trips.
const defaultBatchSize = 50

// outboxQuerier is the narrow sqlc surface DBRevocationOutbox needs. Using a
// subset keeps this file testable with a fake and documents exactly which
// generated queries the revocation outbox path depends on.
type outboxQuerier interface {
	EnqueueRevocation(ctx context.Context, arg db.EnqueueRevocationParams) (db.RevocationOutbox, error)
	FetchPendingRevocations(ctx context.Context, limit int32) ([]db.RevocationOutbox, error)
	MarkRevocationDelivered(ctx context.Context, id pgtype.UUID) error
	IncrementRevocationRetry(ctx context.Context, arg db.IncrementRevocationRetryParams) error
	MarkRevocationFailed(ctx context.Context, id pgtype.UUID) error
}

// OutboxEntry is the domain type for a revocation signal queued in the outbox.
// It maps 1:1 with db.RevocationOutbox but keeps the oidc package free of sqlc
// types (same pattern as RefreshSession in sessions.go).
type OutboxEntry struct {
	ID            string
	Reason        string // "refresh_reuse" | "code_reuse"
	UserID        string
	ClientID      string
	GrantID       string // may be empty if grant-id-fk is not yet wired
	Status        string // "pending" | "delivered" | "failed"
	RetryCount    int
	NextAttemptAt time.Time
	CreatedAt     time.Time
}

// RevocationOutbox enqueues and delivers durable revocation signals via the
// transactional outbox pattern (docs/plans/revocation-outbox.md, DESIGN §3.5).
type RevocationOutbox interface {
	// Enqueue inserts a revocation signal into the outbox for durable delivery.
	// Called by signalRefreshReuse/signalCodeReuse after (or instead of) the
	// inline best-effort attempt.
	Enqueue(ctx context.Context, entry OutboxEntry) error

	// DeliverPending fetches pending revocations and attempts delivery via the
	// provided RevocationSink. Successfully delivered entries are marked
	// 'delivered'; failed entries have their retry_count incremented and
	// next_attempt_at set according to exponential backoff. Entries past the
	// 24h TTL are marked 'failed' (dead-letter).
	DeliverPending(ctx context.Context, sink oidc.SessionStore) error
}

// DBRevocationOutbox implements RevocationOutbox over the revocation_outbox
// table (docs/DESIGN.md §3.5, §10). Each method converts domain types to/from
// sqlc types.
type DBRevocationOutbox struct {
	q      outboxQuerier
	logger *slog.Logger
	now    func() time.Time // seam for deterministic tests
}

// NewDBRevocationOutbox wraps a sqlc Queries (or any outboxQuerier).
func NewDBRevocationOutbox(q outboxQuerier, logger *slog.Logger) *DBRevocationOutbox {
	if logger == nil {
		logger = slog.Default()
	}
	return &DBRevocationOutbox{q: q, logger: logger, now: time.Now}
}

// WithNow sets a custom time source (for deterministic tests).
func (o *DBRevocationOutbox) WithNow(now func() time.Time) *DBRevocationOutbox {
	o.now = now
	return o
}

// Compile-time proof that DBRevocationOutbox implements RevocationOutbox.
var _ RevocationOutbox = (*DBRevocationOutbox)(nil)

// Enqueue implements RevocationOutbox.
func (o *DBRevocationOutbox) Enqueue(ctx context.Context, entry OutboxEntry) error {
	var userID pgtype.UUID
	if err := userID.Scan(entry.UserID); err != nil {
		return fmt.Errorf("revocation_outbox: parse user ID %q: %w", entry.UserID, err)
	}

	var grantID pgtype.UUID
	if entry.GrantID != "" {
		if err := grantID.Scan(entry.GrantID); err != nil {
			return fmt.Errorf("revocation_outbox: parse grant ID %q: %w", entry.GrantID, err)
		}
	}
	// grantID.Valid remains false if entry.GrantID is empty (nullable FK)

	_, err := o.q.EnqueueRevocation(ctx, db.EnqueueRevocationParams{
		Reason:   entry.Reason,
		UserID:   userID,
		ClientID: entry.ClientID,
		GrantID:  grantID,
	})
	if err != nil {
		return fmt.Errorf("revocation_outbox: enqueue: %w", err)
	}
	return nil
}

// DeliverPending implements RevocationOutbox.
func (o *DBRevocationOutbox) DeliverPending(ctx context.Context, sink oidc.SessionStore) error {
	rows, err := o.q.FetchPendingRevocations(ctx, defaultBatchSize)
	if err != nil {
		return fmt.Errorf("revocation_outbox: fetch pending: %w", err)
	}

	now := o.now()
	for _, row := range rows {
		entry := rowToOutboxEntry(row)

		// TTL check: if the entry is older than 24h, mark it as permanently failed.
		if now.Sub(entry.CreatedAt) > outboxTTL {
			if markErr := o.q.MarkRevocationFailed(ctx, row.ID); markErr != nil {
				o.logger.ErrorContext(ctx, "revocation_outbox: failed to mark entry as failed (TTL exceeded)",
					slog.String("entry_id", entry.ID),
					slog.Any("error", markErr))
			} else {
				o.logger.WarnContext(ctx, "revocation_outbox: entry marked failed after TTL exceeded",
					slog.String("entry_id", entry.ID),
					slog.String("client_id", entry.ClientID))
			}
			continue
		}

		// Attempt delivery via the session store's RevokeSessionsByUserClient.
		deliveryErr := sink.RevokeSessionsByUserClient(ctx, entry.UserID, entry.ClientID)
		if deliveryErr == nil {
			// Success: mark as delivered.
			if markErr := o.q.MarkRevocationDelivered(ctx, row.ID); markErr != nil {
				o.logger.ErrorContext(ctx, "revocation_outbox: failed to mark entry as delivered",
					slog.String("entry_id", entry.ID),
					slog.Any("error", markErr))
			}
			continue
		}

		// Delivery failed: increment retry count and schedule next attempt.
		o.logger.WarnContext(ctx, "revocation_outbox: delivery attempt failed, scheduling retry",
			slog.String("entry_id", entry.ID),
			slog.String("client_id", entry.ClientID),
			slog.Int("retry_count", entry.RetryCount),
			slog.Any("error", deliveryErr))

		nextAttempt := computeNextAttempt(now, entry.RetryCount)
		var nextAttemptAt pgtype.Timestamptz
		if err := nextAttemptAt.Scan(nextAttempt); err != nil {
			o.logger.ErrorContext(ctx, "revocation_outbox: failed to parse next_attempt_at",
				slog.String("entry_id", entry.ID),
				slog.Any("error", err))
			continue
		}

		if retryErr := o.q.IncrementRevocationRetry(ctx, db.IncrementRevocationRetryParams{
			ID:            row.ID,
			NextAttemptAt: nextAttemptAt,
		}); retryErr != nil {
			o.logger.ErrorContext(ctx, "revocation_outbox: failed to increment retry",
				slog.String("entry_id", entry.ID),
				slog.Any("error", retryErr))
		}
	}

	return nil
}

// computeNextAttempt calculates the next attempt time based on retry count
// using exponential backoff with a 1h cap.
func computeNextAttempt(now time.Time, retryCount int) time.Time {
	idx := retryCount
	if idx >= len(retryDelays) {
		idx = len(retryDelays) - 1 // cap at 1h
	}
	return now.Add(retryDelays[idx])
}

// rowToOutboxEntry converts a sqlc RevocationOutbox row to the domain type.
func rowToOutboxEntry(row db.RevocationOutbox) OutboxEntry {
	var nextAttemptAt, createdAt time.Time
	if row.NextAttemptAt.Valid {
		nextAttemptAt = row.NextAttemptAt.Time
	}
	if row.CreatedAt.Valid {
		createdAt = row.CreatedAt.Time
	}
	return OutboxEntry{
		ID:            uuidToString(row.ID),
		Reason:        row.Reason,
		UserID:        uuidToString(row.UserID),
		ClientID:      row.ClientID,
		GrantID:       uuidToString(row.GrantID),
		Status:        row.Status,
		RetryCount:    int(row.RetryCount),
		NextAttemptAt: nextAttemptAt,
		CreatedAt:     createdAt,
	}
}
