package clients

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/harbor/harbor/internal/gen/db"
)

// fakeRevokedJTIQuerier is an in-memory revokedJTIQuerier fake for unit tests.
type fakeRevokedJTIQuerier struct {
	rows  map[string]*db.RevokedJti // keyed by JTI string
	dbErr error                     // if non-nil, every call returns this
}

func newFakeRevokedJTIQuerier() *fakeRevokedJTIQuerier {
	return &fakeRevokedJTIQuerier{rows: make(map[string]*db.RevokedJti)}
}

func (f *fakeRevokedJTIQuerier) InsertRevokedJTI(_ context.Context, arg db.InsertRevokedJTIParams) (db.RevokedJti, error) {
	if f.dbErr != nil {
		return db.RevokedJti{}, f.dbErr
	}
	row := &db.RevokedJti{
		Jti:       arg.Jti,
		RevokedAt: pgtype.Timestamptz{Time: time.Now(), Valid: true},
		Reason:    arg.Reason,
		ExpiresAt: arg.ExpiresAt,
	}
	f.rows[arg.Jti] = row
	return *row, nil
}

func (f *fakeRevokedJTIQuerier) GetRevokedJTI(_ context.Context, jti string) (db.RevokedJti, error) {
	if f.dbErr != nil {
		return db.RevokedJti{}, f.dbErr
	}
	row, ok := f.rows[jti]
	if !ok {
		return db.RevokedJti{}, pgx.ErrNoRows
	}
	return *row, nil
}

func (f *fakeRevokedJTIQuerier) ListActiveRevokedJTIs(_ context.Context) ([]db.RevokedJti, error) {
	if f.dbErr != nil {
		return nil, f.dbErr
	}
	now := time.Now()
	var out []db.RevokedJti
	for _, row := range f.rows {
		// Only return active (not expired) entries
		if row.ExpiresAt.Valid && row.ExpiresAt.Time.After(now) {
			out = append(out, *row)
		}
	}
	return out, nil
}

func (f *fakeRevokedJTIQuerier) GCExpiredRevokedJTIs(_ context.Context) error {
	if f.dbErr != nil {
		return f.dbErr
	}
	now := time.Now()
	for jti, row := range f.rows {
		if row.ExpiresAt.Valid && row.ExpiresAt.Time.Before(now) {
			delete(f.rows, jti)
		}
	}
	return nil
}

// Helper to create a pgtype.Timestamptz from a time.Time
func pgTimestamp(t time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: t, Valid: true}
}

func TestDBRevokedJTIStore_Insert(t *testing.T) {
	q := newFakeRevokedJTIQuerier()
	s := NewDBRevokedJTIStore(q)
	ctx := context.Background()

	expiresAt := time.Now().Add(15 * time.Minute)
	result, err := s.Insert(ctx, "jti-12345", "emergency_kill", expiresAt)
	if err != nil {
		t.Fatalf("Insert: %v", err)
	}

	if result.JTI != "jti-12345" {
		t.Errorf("JTI: got %q, want %q", result.JTI, "jti-12345")
	}
	if result.Reason != "emergency_kill" {
		t.Errorf("Reason: got %q, want %q", result.Reason, "emergency_kill")
	}
	if result.RevokedAt.IsZero() {
		t.Error("RevokedAt should not be zero")
	}
}

func TestDBRevokedJTIStore_InsertIdempotent(t *testing.T) {
	// Verify that Insert is idempotent (upsert behavior)
	q := newFakeRevokedJTIQuerier()
	s := NewDBRevokedJTIStore(q)
	ctx := context.Background()

	expiresAt := time.Now().Add(15 * time.Minute)

	// First insert
	_, err := s.Insert(ctx, "jti-upsert", "emergency_kill", expiresAt)
	if err != nil {
		t.Fatalf("First Insert: %v", err)
	}

	// Second insert with different reason (should update)
	result, err := s.Insert(ctx, "jti-upsert", "key_rotation", expiresAt.Add(5*time.Minute))
	if err != nil {
		t.Fatalf("Second Insert: %v", err)
	}

	// The reason should be updated (in real DB; our fake just overwrites)
	if result.Reason != "key_rotation" {
		t.Errorf("Reason after upsert: got %q, want %q", result.Reason, "key_rotation")
	}

	// Should still be only one entry
	if len(q.rows) != 1 {
		t.Errorf("expected 1 row after upsert, got %d", len(q.rows))
	}
}

func TestDBRevokedJTIStore_InsertDBError(t *testing.T) {
	q := &fakeRevokedJTIQuerier{rows: make(map[string]*db.RevokedJti), dbErr: errors.New("db insert failed")}
	s := NewDBRevokedJTIStore(q)

	_, err := s.Insert(context.Background(), "jti-fail", "emergency_kill", time.Now().Add(time.Hour))
	if err == nil {
		t.Error("expected error propagation from DB error")
	}
}

func TestDBRevokedJTIStore_GetByJTI(t *testing.T) {
	q := newFakeRevokedJTIQuerier()
	s := NewDBRevokedJTIStore(q)
	ctx := context.Background()

	// Insert a JTI first
	expiresAt := time.Now().Add(15 * time.Minute)
	_, err := s.Insert(ctx, "jti-lookup", "emergency_kill", expiresAt)
	if err != nil {
		t.Fatalf("Insert: %v", err)
	}

	// Get by JTI should find it
	result, found, err := s.GetByJTI(ctx, "jti-lookup")
	if err != nil {
		t.Fatalf("GetByJTI: %v", err)
	}
	if !found {
		t.Error("expected found=true for existing JTI")
	}
	if result.JTI != "jti-lookup" {
		t.Errorf("JTI: got %q, want %q", result.JTI, "jti-lookup")
	}
	if result.Reason != "emergency_kill" {
		t.Errorf("Reason: got %q, want %q", result.Reason, "emergency_kill")
	}
}

func TestDBRevokedJTIStore_GetByJTI_NotFound(t *testing.T) {
	q := newFakeRevokedJTIQuerier()
	s := NewDBRevokedJTIStore(q)

	// GetByJTI for non-existent JTI should return found=false
	_, found, err := s.GetByJTI(context.Background(), "nonexistent-jti")
	if err != nil {
		t.Fatalf("GetByJTI: %v", err)
	}
	if found {
		t.Error("expected found=false for non-existent JTI")
	}
}

func TestDBRevokedJTIStore_GetByJTI_DBError(t *testing.T) {
	q := &fakeRevokedJTIQuerier{rows: make(map[string]*db.RevokedJti), dbErr: errors.New("db query failed")}
	s := NewDBRevokedJTIStore(q)

	_, _, err := s.GetByJTI(context.Background(), "any-jti")
	if err == nil {
		t.Error("expected error propagation from DB error")
	}
}

func TestDBRevokedJTIStore_ListActive(t *testing.T) {
	q := newFakeRevokedJTIQuerier()
	s := NewDBRevokedJTIStore(q)
	ctx := context.Background()

	// Insert some active JTIs (not expired)
	activeExpiry := time.Now().Add(15 * time.Minute)
	if _, err := s.Insert(ctx, "jti-active-1", "emergency_kill", activeExpiry); err != nil {
		t.Fatalf("Insert jti-active-1: %v", err)
	}
	if _, err := s.Insert(ctx, "jti-active-2", "key_rotation", activeExpiry); err != nil {
		t.Fatalf("Insert jti-active-2: %v", err)
	}

	// Insert an expired JTI
	expiredTime := time.Now().Add(-1 * time.Hour)
	q.rows["jti-expired"] = &db.RevokedJti{
		Jti:       "jti-expired",
		RevokedAt: pgTimestamp(time.Now().Add(-2 * time.Hour)),
		Reason:    "emergency_kill",
		ExpiresAt: pgTimestamp(expiredTime),
	}

	// ListActive should return only the active entries
	active, err := s.ListActive(ctx)
	if err != nil {
		t.Fatalf("ListActive: %v", err)
	}

	if len(active) != 2 {
		t.Errorf("expected 2 active JTIs, got %d", len(active))
	}

	// Verify expired JTI is not in the list
	for _, jti := range active {
		if jti.JTI == "jti-expired" {
			t.Error("expired JTI should not be in ListActive result")
		}
	}
}

func TestDBRevokedJTIStore_ListActive_Empty(t *testing.T) {
	q := newFakeRevokedJTIQuerier()
	s := NewDBRevokedJTIStore(q)

	active, err := s.ListActive(context.Background())
	if err != nil {
		t.Fatalf("ListActive: %v", err)
	}
	if len(active) != 0 {
		t.Errorf("expected empty list, got %d entries", len(active))
	}
}

func TestDBRevokedJTIStore_ListActive_DBError(t *testing.T) {
	q := &fakeRevokedJTIQuerier{rows: make(map[string]*db.RevokedJti), dbErr: errors.New("db list failed")}
	s := NewDBRevokedJTIStore(q)

	_, err := s.ListActive(context.Background())
	if err == nil {
		t.Error("expected error propagation from DB error")
	}
}

func TestDBRevokedJTIStore_GCExpired(t *testing.T) {
	q := newFakeRevokedJTIQuerier()
	s := NewDBRevokedJTIStore(q)
	ctx := context.Background()

	// Insert an active JTI (not expired)
	activeExpiry := time.Now().Add(15 * time.Minute)
	if _, err := s.Insert(ctx, "jti-keep", "emergency_kill", activeExpiry); err != nil {
		t.Fatalf("Insert jti-keep: %v", err)
	}

	// Insert expired JTIs directly into the fake
	expiredTime := time.Now().Add(-1 * time.Hour)
	q.rows["jti-gc-1"] = &db.RevokedJti{
		Jti:       "jti-gc-1",
		RevokedAt: pgTimestamp(time.Now().Add(-2 * time.Hour)),
		Reason:    "emergency_kill",
		ExpiresAt: pgTimestamp(expiredTime),
	}
	q.rows["jti-gc-2"] = &db.RevokedJti{
		Jti:       "jti-gc-2",
		RevokedAt: pgTimestamp(time.Now().Add(-3 * time.Hour)),
		Reason:    "key_rotation",
		ExpiresAt: pgTimestamp(expiredTime),
	}

	// Verify we have 3 entries before GC
	if len(q.rows) != 3 {
		t.Fatalf("expected 3 rows before GC, got %d", len(q.rows))
	}

	// Run GC
	err := s.GCExpired(ctx)
	if err != nil {
		t.Fatalf("GCExpired: %v", err)
	}

	// Should have only 1 entry remaining (the active one)
	if len(q.rows) != 1 {
		t.Errorf("expected 1 row after GC, got %d", len(q.rows))
	}

	// The active JTI should still exist
	if _, ok := q.rows["jti-keep"]; !ok {
		t.Error("active JTI 'jti-keep' should not be GC'd")
	}

	// The expired JTIs should be gone
	if _, ok := q.rows["jti-gc-1"]; ok {
		t.Error("expired JTI 'jti-gc-1' should be GC'd")
	}
	if _, ok := q.rows["jti-gc-2"]; ok {
		t.Error("expired JTI 'jti-gc-2' should be GC'd")
	}
}

func TestDBRevokedJTIStore_GCExpired_DBError(t *testing.T) {
	q := &fakeRevokedJTIQuerier{rows: make(map[string]*db.RevokedJti), dbErr: errors.New("db gc failed")}
	s := NewDBRevokedJTIStore(q)

	err := s.GCExpired(context.Background())
	if err == nil {
		t.Error("expected error propagation from DB error")
	}
}

func TestRowToRevokedJTI(t *testing.T) {
	now := time.Now().Truncate(time.Millisecond)
	expiresAt := now.Add(15 * time.Minute)

	row := db.RevokedJti{
		Jti:       "jti-row-test",
		RevokedAt: pgtype.Timestamptz{Time: now, Valid: true},
		Reason:    "emergency_kill",
		ExpiresAt: pgtype.Timestamptz{Time: expiresAt, Valid: true},
	}

	result := rowToRevokedJTI(row)

	if result.JTI != "jti-row-test" {
		t.Errorf("JTI: got %q, want %q", result.JTI, "jti-row-test")
	}
	if result.Reason != "emergency_kill" {
		t.Errorf("Reason: got %q, want %q", result.Reason, "emergency_kill")
	}
	if result.RevokedAt.IsZero() {
		t.Error("RevokedAt should not be zero")
	}
	if result.ExpiresAt.IsZero() {
		t.Error("ExpiresAt should not be zero")
	}
}

func TestRowToRevokedJTI_InvalidTimestamps(t *testing.T) {
	// Test with invalid (zero) timestamps
	row := db.RevokedJti{
		Jti:       "jti-invalid-ts",
		RevokedAt: pgtype.Timestamptz{Valid: false},
		Reason:    "emergency_kill",
		ExpiresAt: pgtype.Timestamptz{Valid: false},
	}

	result := rowToRevokedJTI(row)

	// Should return zero times without panicking
	if !result.RevokedAt.IsZero() {
		t.Error("RevokedAt should be zero for invalid timestamp")
	}
	if !result.ExpiresAt.IsZero() {
		t.Error("ExpiresAt should be zero for invalid timestamp")
	}
}
