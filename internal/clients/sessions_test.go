package clients

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	db "github.com/harbor/harbor/internal/gen/db"
	"github.com/harbor/harbor/internal/oidc"
)

// fakeSessionQuerier is an in-memory sessionQuerier for tests. It uses UUIDs
// as string keys so tests don't need a real Postgres connection.
type fakeSessionQuerier struct {
	mu       sync.Mutex
	byID     map[string]db.Session
	byUserID map[string][]string // userID → []sessionID
}

func newFakeSessionQuerier() *fakeSessionQuerier {
	return &fakeSessionQuerier{
		byID:     make(map[string]db.Session),
		byUserID: make(map[string][]string),
	}
}

func (f *fakeSessionQuerier) CreateSession(_ context.Context, arg db.CreateSessionParams) (db.Session, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	row := db.Session{
		ID:               arg.ID,
		Region:           arg.Region,
		UserID:           arg.UserID,
		DeviceLabel:      arg.DeviceLabel,
		RefreshTokenHash: arg.RefreshTokenHash,
		ExpiresAt:        arg.ExpiresAt,
	}
	key := arg.ID.String()
	f.byID[key] = row
	uid := arg.UserID.String()
	f.byUserID[uid] = append(f.byUserID[uid], key)
	return row, nil
}

func (f *fakeSessionQuerier) GetSession(_ context.Context, id pgtype.UUID) (db.Session, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	row, ok := f.byID[id.String()]
	if !ok {
		return db.Session{}, fmt.Errorf("session not found")
	}
	return row, nil
}

func (f *fakeSessionQuerier) GetActiveSession(_ context.Context, id pgtype.UUID) (db.Session, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	row, ok := f.byID[id.String()]
	if !ok {
		return db.Session{}, fmt.Errorf("session not found")
	}
	if isRevoked(row) {
		return db.Session{}, fmt.Errorf("session revoked")
	}
	if row.ExpiresAt.Valid && time.Now().After(row.ExpiresAt.Time) {
		return db.Session{}, fmt.Errorf("session expired")
	}
	return row, nil
}

func (f *fakeSessionQuerier) ListSessionsByUser(_ context.Context, userID pgtype.UUID) ([]db.Session, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	ids := f.byUserID[userID.String()]
	var out []db.Session
	for _, id := range ids {
		row := f.byID[id]
		if !isRevoked(row) {
			out = append(out, row)
		}
	}
	return out, nil
}

func (f *fakeSessionQuerier) RevokeSession(_ context.Context, id pgtype.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	row, ok := f.byID[id.String()]
	if !ok {
		return nil // idempotent
	}
	var revokedAt pgtype.Timestamptz
	if err := revokedAt.Scan(time.Now()); err != nil {
		return err
	}
	row.RevokedAt = revokedAt
	f.byID[id.String()] = row
	return nil
}

func (f *fakeSessionQuerier) RevokeSessionsByUser(_ context.Context, userID pgtype.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, sid := range f.byUserID[userID.String()] {
		row := f.byID[sid]
		var revokedAt pgtype.Timestamptz
		if err := revokedAt.Scan(time.Now()); err != nil {
			return err
		}
		row.RevokedAt = revokedAt
		f.byID[sid] = row
	}
	return nil
}

// helpers

func mustUUID(t *testing.T, s string) pgtype.UUID {
	t.Helper()
	var u pgtype.UUID
	if err := u.Scan(s); err != nil {
		t.Fatalf("mustUUID(%q): %v", s, err)
	}
	return u
}

const (
	sessTestUserID   = "00000000-0000-0000-0000-000000000001"
	sessTestClientID = "test-rp"
	sessTestRegion   = "us"
)

func buildTestSession(t *testing.T, id, userID string, hash []byte, ttl time.Duration) oidc.RefreshSession {
	t.Helper()
	return oidc.RefreshSession{
		ID:        id,
		Region:    sessTestRegion,
		UserID:    userID,
		ClientID:  sessTestClientID,
		TokenHash: hash,
		ExpiresAt: time.Now().Add(ttl),
	}
}

// TestDBSessionStoreCreateAndRevoke exercises the create → revoke lifecycle.
func TestDBSessionStoreCreateAndRevoke(t *testing.T) {
	q := newFakeSessionQuerier()
	store := NewDBSessionStore(q)

	hash := []byte("sha256-placeholder-32-bytes-------")
	rs := buildTestSession(t, "00000000-0000-0000-0000-000000000101", sessTestUserID, hash, 14*24*time.Hour)

	if err := store.CreateSession(context.Background(), rs); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	// GetSessionByTokenHash is SCAFFOLD (fails closed) — verified below via the
	// fake querier directly.
	row, err := q.GetActiveSession(context.Background(), mustUUID(t, rs.ID))
	if err != nil {
		t.Fatalf("GetActiveSession after create: %v", err)
	}
	if string(row.RefreshTokenHash) != string(hash) {
		t.Fatalf("stored hash mismatch")
	}

	// Revoke and confirm the row is no longer active.
	if err := store.RevokeSession(context.Background(), rs.ID); err != nil {
		t.Fatalf("RevokeSession: %v", err)
	}
	_, err = q.GetActiveSession(context.Background(), mustUUID(t, rs.ID))
	if err == nil {
		t.Fatal("expected error on GetActiveSession after revoke")
	}
}

// TestDBSessionStoreRevokesByUser verifies that RevokeSessionsByUserClient
// revokes every active session for the user (conservative superset; see the
// scaffold comment in sessions.go).
func TestDBSessionStoreRevokesByUser(t *testing.T) {
	q := newFakeSessionQuerier()
	store := NewDBSessionStore(q)

	sessIDs := []string{
		"00000000-0000-0000-0000-000000000201",
		"00000000-0000-0000-0000-000000000202",
		"00000000-0000-0000-0000-000000000203",
	}
	for i, id := range sessIDs {
		rs := buildTestSession(t, id, sessTestUserID, []byte{byte(i)}, 14*24*time.Hour)
		if err := store.CreateSession(context.Background(), rs); err != nil {
			t.Fatalf("CreateSession %s: %v", id, err)
		}
	}

	// clientID is ignored (scaffold) — all user sessions are revoked.
	if err := store.RevokeSessionsByUserClient(context.Background(), sessTestUserID, sessTestClientID); err != nil {
		t.Fatalf("RevokeSessionsByUserClient: %v", err)
	}

	active, err := q.ListSessionsByUser(context.Background(), mustUUID(t, sessTestUserID))
	if err != nil {
		t.Fatalf("ListSessionsByUser: %v", err)
	}
	if len(active) != 0 {
		t.Fatalf("expected 0 active sessions after family revoke, got %d", len(active))
	}
}

// TestDBSessionStoreGetByHashScaffold confirms the SCAFFOLD implementation of
// GetSessionByTokenHash fails closed (returns ErrRefreshTokenNotFound) so the
// DB path never silently accepts tokens before the hash-index query is added.
func TestDBSessionStoreGetByHashScaffold(t *testing.T) {
	q := newFakeSessionQuerier()
	store := NewDBSessionStore(q)

	_, err := store.GetSessionByTokenHash(context.Background(), []byte("any-hash"))
	if !errors.Is(err, oidc.ErrRefreshTokenNotFound) {
		t.Fatalf("expected ErrRefreshTokenNotFound (scaffold), got %v", err)
	}
}
