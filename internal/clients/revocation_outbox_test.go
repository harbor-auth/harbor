package clients

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	db "github.com/harbor/harbor/internal/gen/db"
	"github.com/harbor/harbor/internal/oidc"
)

// mockOutboxQuerier is a test fake for outboxQuerier.
type mockOutboxQuerier struct {
	enqueueFunc        func(ctx context.Context, arg db.EnqueueRevocationParams) (db.RevocationOutbox, error)
	fetchPendingFunc   func(ctx context.Context, limit int32) ([]db.RevocationOutbox, error)
	markDeliveredFunc  func(ctx context.Context, id pgtype.UUID) error
	incrementRetryFunc func(ctx context.Context, arg db.IncrementRevocationRetryParams) error
	markFailedFunc     func(ctx context.Context, id pgtype.UUID) error

	// Tracking for assertions
	enqueueCalls        []db.EnqueueRevocationParams
	markDeliveredCalls  []pgtype.UUID
	incrementRetryCalls []db.IncrementRevocationRetryParams
	markFailedCalls     []pgtype.UUID
}

func (m *mockOutboxQuerier) EnqueueRevocation(ctx context.Context, arg db.EnqueueRevocationParams) (db.RevocationOutbox, error) {
	m.enqueueCalls = append(m.enqueueCalls, arg)
	if m.enqueueFunc != nil {
		return m.enqueueFunc(ctx, arg)
	}
	return db.RevocationOutbox{}, nil
}

func (m *mockOutboxQuerier) FetchPendingRevocations(ctx context.Context, limit int32) ([]db.RevocationOutbox, error) {
	if m.fetchPendingFunc != nil {
		return m.fetchPendingFunc(ctx, limit)
	}
	return nil, nil
}

func (m *mockOutboxQuerier) MarkRevocationDelivered(ctx context.Context, id pgtype.UUID) error {
	m.markDeliveredCalls = append(m.markDeliveredCalls, id)
	if m.markDeliveredFunc != nil {
		return m.markDeliveredFunc(ctx, id)
	}
	return nil
}

func (m *mockOutboxQuerier) IncrementRevocationRetry(ctx context.Context, arg db.IncrementRevocationRetryParams) error {
	m.incrementRetryCalls = append(m.incrementRetryCalls, arg)
	if m.incrementRetryFunc != nil {
		return m.incrementRetryFunc(ctx, arg)
	}
	return nil
}

func (m *mockOutboxQuerier) MarkRevocationFailed(ctx context.Context, id pgtype.UUID) error {
	m.markFailedCalls = append(m.markFailedCalls, id)
	if m.markFailedFunc != nil {
		return m.markFailedFunc(ctx, id)
	}
	return nil
}

// mockSessionStore is a test fake for oidc.SessionStore (only RevokeSessionsByUserClient).
type mockSessionStore struct {
	revokeFunc  func(ctx context.Context, userID, clientID string) error
	revokeCalls []struct{ UserID, ClientID string }
}

func (m *mockSessionStore) RevokeSessionsByUserClient(ctx context.Context, userID, clientID string) error {
	m.revokeCalls = append(m.revokeCalls, struct{ UserID, ClientID string }{userID, clientID})
	if m.revokeFunc != nil {
		return m.revokeFunc(ctx, userID, clientID)
	}
	return nil
}

// Implement the rest of oidc.SessionStore interface (unused in these tests).
func (m *mockSessionStore) CreateSession(ctx context.Context, rs oidc.RefreshSession) error {
	return nil
}
func (m *mockSessionStore) GetSessionByTokenHash(ctx context.Context, hash []byte) (oidc.RefreshSession, error) {
	return oidc.RefreshSession{}, nil
}
func (m *mockSessionStore) RevokeSession(ctx context.Context, id string) error { return nil }
func (m *mockSessionStore) RotateSession(ctx context.Context, oldID string, newSession oidc.RefreshSession) error {
	return nil
}
func (m *mockSessionStore) RevokeSessionsByGrant(ctx context.Context, grantID string) error {
	return nil
}

// Compile-time proof that mockSessionStore implements oidc.SessionStore.
var _ oidc.SessionStore = (*mockSessionStore)(nil)

func TestEnqueue_Success(t *testing.T) {
	mock := &mockOutboxQuerier{}
	outbox := NewDBRevocationOutbox(mock, nil)

	entry := oidc.OutboxEntry{
		Reason:   "refresh_reuse",
		UserID:   "550e8400-e29b-41d4-a716-446655440000",
		ClientID: "test-client",
	}

	err := outbox.Enqueue(context.Background(), entry)
	if err != nil {
		t.Fatalf("Enqueue() error = %v", err)
	}

	if len(mock.enqueueCalls) != 1 {
		t.Fatalf("expected 1 enqueue call, got %d", len(mock.enqueueCalls))
	}

	call := mock.enqueueCalls[0]
	if call.Reason != "refresh_reuse" {
		t.Errorf("Reason = %q, want %q", call.Reason, "refresh_reuse")
	}
	if call.ClientID != "test-client" {
		t.Errorf("ClientID = %q, want %q", call.ClientID, "test-client")
	}
}

func TestEnqueue_InvalidUserID(t *testing.T) {
	mock := &mockOutboxQuerier{}
	outbox := NewDBRevocationOutbox(mock, nil)

	entry := oidc.OutboxEntry{
		Reason:   "refresh_reuse",
		UserID:   "not-a-uuid",
		ClientID: "test-client",
	}

	err := outbox.Enqueue(context.Background(), entry)
	if err == nil {
		t.Fatal("Enqueue() expected error for invalid UUID")
	}
}

func TestEnqueue_WithGrantID(t *testing.T) {
	mock := &mockOutboxQuerier{}
	outbox := NewDBRevocationOutbox(mock, nil)

	entry := oidc.OutboxEntry{
		Reason:   "code_reuse",
		UserID:   "550e8400-e29b-41d4-a716-446655440000",
		ClientID: "test-client",
		GrantID:  "660e8400-e29b-41d4-a716-446655440001",
	}

	err := outbox.Enqueue(context.Background(), entry)
	if err != nil {
		t.Fatalf("Enqueue() error = %v", err)
	}

	if len(mock.enqueueCalls) != 1 {
		t.Fatalf("expected 1 enqueue call, got %d", len(mock.enqueueCalls))
	}

	call := mock.enqueueCalls[0]
	if !call.GrantID.Valid {
		t.Error("GrantID should be valid when provided")
	}
}

func TestDeliverPending_SuccessfulDelivery(t *testing.T) {
	userUUID := mustParseUUID(t, "550e8400-e29b-41d4-a716-446655440000")
	entryUUID := mustParseUUID(t, "660e8400-e29b-41d4-a716-446655440001")

	now := time.Now()
	mock := &mockOutboxQuerier{
		fetchPendingFunc: func(ctx context.Context, limit int32) ([]db.RevocationOutbox, error) {
			return []db.RevocationOutbox{{
				ID:            entryUUID,
				Reason:        "refresh_reuse",
				UserID:        userUUID,
				ClientID:      "test-client",
				Status:        "pending",
				RetryCount:    0,
				NextAttemptAt: pgtype.Timestamptz{Time: now, Valid: true},
				CreatedAt:     pgtype.Timestamptz{Time: now, Valid: true},
			}}, nil
		},
	}

	sink := &mockSessionStore{}
	outbox := NewDBRevocationOutbox(mock, nil).WithNow(func() time.Time { return now })

	err := outbox.DeliverPending(context.Background(), sink)
	if err != nil {
		t.Fatalf("DeliverPending() error = %v", err)
	}

	// Should have called RevokeSessionsByUserClient
	if len(sink.revokeCalls) != 1 {
		t.Fatalf("expected 1 revoke call, got %d", len(sink.revokeCalls))
	}

	// Should have marked as delivered
	if len(mock.markDeliveredCalls) != 1 {
		t.Fatalf("expected 1 markDelivered call, got %d", len(mock.markDeliveredCalls))
	}
}

func TestDeliverPending_FailedDelivery_SchedulesRetry(t *testing.T) {
	userUUID := mustParseUUID(t, "550e8400-e29b-41d4-a716-446655440000")
	entryUUID := mustParseUUID(t, "660e8400-e29b-41d4-a716-446655440001")

	now := time.Now()
	mock := &mockOutboxQuerier{
		fetchPendingFunc: func(ctx context.Context, limit int32) ([]db.RevocationOutbox, error) {
			return []db.RevocationOutbox{{
				ID:            entryUUID,
				Reason:        "refresh_reuse",
				UserID:        userUUID,
				ClientID:      "test-client",
				Status:        "pending",
				RetryCount:    0,
				NextAttemptAt: pgtype.Timestamptz{Time: now, Valid: true},
				CreatedAt:     pgtype.Timestamptz{Time: now, Valid: true},
			}}, nil
		},
	}

	sink := &mockSessionStore{
		revokeFunc: func(ctx context.Context, userID, clientID string) error {
			return errors.New("transient DB error")
		},
	}
	outbox := NewDBRevocationOutbox(mock, nil).WithNow(func() time.Time { return now })

	err := outbox.DeliverPending(context.Background(), sink)
	if err != nil {
		t.Fatalf("DeliverPending() error = %v", err)
	}

	// Should have attempted revoke
	if len(sink.revokeCalls) != 1 {
		t.Fatalf("expected 1 revoke call, got %d", len(sink.revokeCalls))
	}

	// Should NOT have marked as delivered
	if len(mock.markDeliveredCalls) != 0 {
		t.Fatalf("expected 0 markDelivered calls, got %d", len(mock.markDeliveredCalls))
	}

	// Should have incremented retry
	if len(mock.incrementRetryCalls) != 1 {
		t.Fatalf("expected 1 incrementRetry call, got %d", len(mock.incrementRetryCalls))
	}

	// Next attempt should be 5s from now (first retry)
	nextAttempt := mock.incrementRetryCalls[0].NextAttemptAt.Time
	expected := now.Add(5 * time.Second)
	if !nextAttempt.Equal(expected) {
		t.Errorf("NextAttemptAt = %v, want %v", nextAttempt, expected)
	}
}

func TestDeliverPending_TTLExceeded_MarksAsFailed(t *testing.T) {
	userUUID := mustParseUUID(t, "550e8400-e29b-41d4-a716-446655440000")
	entryUUID := mustParseUUID(t, "660e8400-e29b-41d4-a716-446655440001")

	now := time.Now()
	createdAt := now.Add(-25 * time.Hour) // older than 24h TTL

	mock := &mockOutboxQuerier{
		fetchPendingFunc: func(ctx context.Context, limit int32) ([]db.RevocationOutbox, error) {
			return []db.RevocationOutbox{{
				ID:            entryUUID,
				Reason:        "refresh_reuse",
				UserID:        userUUID,
				ClientID:      "test-client",
				Status:        "pending",
				RetryCount:    10,
				NextAttemptAt: pgtype.Timestamptz{Time: now, Valid: true},
				CreatedAt:     pgtype.Timestamptz{Time: createdAt, Valid: true},
			}}, nil
		},
	}

	sink := &mockSessionStore{}
	outbox := NewDBRevocationOutbox(mock, nil).WithNow(func() time.Time { return now })

	err := outbox.DeliverPending(context.Background(), sink)
	if err != nil {
		t.Fatalf("DeliverPending() error = %v", err)
	}

	// Should NOT have attempted revoke (TTL exceeded first)
	if len(sink.revokeCalls) != 0 {
		t.Fatalf("expected 0 revoke calls, got %d", len(sink.revokeCalls))
	}

	// Should have marked as failed
	if len(mock.markFailedCalls) != 1 {
		t.Fatalf("expected 1 markFailed call, got %d", len(mock.markFailedCalls))
	}
}

// TestDeliverPending_IdempotentDelivery verifies that delivering the same
// outbox entry twice succeeds without error. This is the property that lets the
// inline best-effort revoke (in signalRefreshReuse) and the background worker
// both fire for the same signal without harm: RevokeSessionsByUserClient is
// idempotent, so a duplicate delivery is a no-op on the second pass. Without
// this guarantee, the enqueue-first-then-inline pattern in service.go would
// double-revoke and could surface spurious errors.
func TestDeliverPending_IdempotentDelivery(t *testing.T) {
	userUUID := mustParseUUID(t, "550e8400-e29b-41d4-a716-446655440000")
	entryUUID := mustParseUUID(t, "660e8400-e29b-41d4-a716-446655440001")

	now := time.Now()
	mock := &mockOutboxQuerier{
		fetchPendingFunc: func(ctx context.Context, limit int32) ([]db.RevocationOutbox, error) {
			return []db.RevocationOutbox{{
				ID:            entryUUID,
				Reason:        "refresh_reuse",
				UserID:        userUUID,
				ClientID:      "test-client",
				Status:        "pending",
				RetryCount:    0,
				NextAttemptAt: pgtype.Timestamptz{Time: now, Valid: true},
				CreatedAt:     pgtype.Timestamptz{Time: now, Valid: true},
			}}, nil
		},
	}
	sink := &mockSessionStore{}
	outbox := NewDBRevocationOutbox(mock, nil).WithNow(func() time.Time { return now })

	// Deliver the same entry twice (simulating inline + worker, or two worker
	// ticks racing on the same pending row). Both cycles must succeed.
	for i := 0; i < 2; i++ {
		if err := outbox.DeliverPending(context.Background(), sink); err != nil {
			t.Fatalf("DeliverPending() cycle %d error = %v", i, err)
		}
	}

	if len(sink.revokeCalls) != 2 {
		t.Fatalf("expected 2 idempotent revoke calls, got %d", len(sink.revokeCalls))
	}
	if len(mock.markDeliveredCalls) != 2 {
		t.Fatalf("expected 2 markDelivered calls, got %d", len(mock.markDeliveredCalls))
	}
	// No retries or dead-letters on the happy path.
	if len(mock.incrementRetryCalls) != 0 {
		t.Fatalf("expected 0 retry increments, got %d", len(mock.incrementRetryCalls))
	}
	if len(mock.markFailedCalls) != 0 {
		t.Fatalf("expected 0 markFailed calls, got %d", len(mock.markFailedCalls))
	}
}

// TestDeliverPending_EventuallySucceedsAfterRetries verifies the core durability
// promise of the outbox: a signal whose inline delivery failed is retried by the
// worker across polling cycles and eventually succeeds. The first two delivery
// attempts fail (scheduling a retry each time); the third succeeds and marks the
// entry delivered.
func TestDeliverPending_EventuallySucceedsAfterRetries(t *testing.T) {
	userUUID := mustParseUUID(t, "550e8400-e29b-41d4-a716-446655440000")
	entryUUID := mustParseUUID(t, "660e8400-e29b-41d4-a716-446655440001")

	now := time.Now()

	// retryCount mirrors what IncrementRevocationRetry would persist between
	// polling cycles, so each FetchPending reflects the growing retry count.
	retryCount := int32(0)
	mock := &mockOutboxQuerier{
		fetchPendingFunc: func(ctx context.Context, limit int32) ([]db.RevocationOutbox, error) {
			return []db.RevocationOutbox{{
				ID:            entryUUID,
				Reason:        "refresh_reuse",
				UserID:        userUUID,
				ClientID:      "test-client",
				Status:        "pending",
				RetryCount:    retryCount,
				NextAttemptAt: pgtype.Timestamptz{Time: now, Valid: true},
				CreatedAt:     pgtype.Timestamptz{Time: now, Valid: true},
			}}, nil
		},
		incrementRetryFunc: func(ctx context.Context, arg db.IncrementRevocationRetryParams) error {
			retryCount++
			return nil
		},
	}

	// Fail the first two delivery attempts, succeed on the third.
	attempts := 0
	sink := &mockSessionStore{
		revokeFunc: func(ctx context.Context, userID, clientID string) error {
			attempts++
			if attempts < 3 {
				return errors.New("transient DB error")
			}
			return nil
		},
	}
	outbox := NewDBRevocationOutbox(mock, nil).WithNow(func() time.Time { return now })

	// Three polling cycles: two fail (retry scheduled), the third succeeds.
	for i := 0; i < 3; i++ {
		if err := outbox.DeliverPending(context.Background(), sink); err != nil {
			t.Fatalf("DeliverPending() cycle %d error = %v", i, err)
		}
	}

	if attempts != 3 {
		t.Fatalf("expected 3 revoke attempts, got %d", attempts)
	}
	if len(mock.incrementRetryCalls) != 2 {
		t.Fatalf("expected 2 retry increments before success, got %d", len(mock.incrementRetryCalls))
	}
	if len(mock.markDeliveredCalls) != 1 {
		t.Fatalf("expected 1 markDelivered call after eventual success, got %d", len(mock.markDeliveredCalls))
	}
	if len(mock.markFailedCalls) != 0 {
		t.Fatalf("entry succeeded before TTL — expected 0 markFailed calls, got %d", len(mock.markFailedCalls))
	}
}

func TestComputeNextAttempt_ExponentialBackoff(t *testing.T) {
	now := time.Now()

	tests := []struct {
		retryCount int
		wantDelay  time.Duration
	}{
		{0, 5 * time.Second},
		{1, 30 * time.Second},
		{2, 5 * time.Minute},
		{3, 30 * time.Minute},
		{4, 1 * time.Hour},
		{5, 1 * time.Hour},  // capped
		{10, 1 * time.Hour}, // capped
	}

	for _, tt := range tests {
		got := computeNextAttempt(now, tt.retryCount)
		want := now.Add(tt.wantDelay)
		if !got.Equal(want) {
			t.Errorf("computeNextAttempt(now, %d) = %v, want %v", tt.retryCount, got, want)
		}
	}
}

func mustParseUUID(t *testing.T, s string) pgtype.UUID {
	t.Helper()
	var u pgtype.UUID
	if err := u.Scan(s); err != nil {
		t.Fatalf("failed to parse UUID %q: %v", s, err)
	}
	return u
}
