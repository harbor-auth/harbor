package clients

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
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
		ClientID:         arg.ClientID,
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

func (f *fakeSessionQuerier) GetSessionByHash(_ context.Context, hash []byte) (db.Session, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, row := range f.byID {
		if bytes.Equal(row.RefreshTokenHash, hash) {
			return row, nil
		}
	}
	// Return pgx.ErrNoRows so DBSessionStore.GetSessionByTokenHash maps this
	// correctly to ErrRefreshTokenNotFound (matching real pgx behaviour).
	return db.Session{}, pgx.ErrNoRows
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

func (f *fakeSessionQuerier) RevokeSessionsByUserClient(_ context.Context, arg db.RevokeSessionsByUserClientParams) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, sid := range f.byUserID[arg.UserID.String()] {
		row := f.byID[sid]
		if row.ClientID != arg.ClientID {
			continue
		}
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

// TestDBSessionStoreScopedRevoke verifies that RevokeSessionsByUserClient
// revokes ONLY the (user, client) family and leaves sessions for OTHER clients
// untouched (DESIGN §3.5, §11.7; INV-REFRESH-THEFT-SIGNAL-FAMILY-REVOKE).
func TestDBSessionStoreScopedRevoke(t *testing.T) {
	q := newFakeSessionQuerier()
	store := NewDBSessionStore(q)
	ctx := context.Background()

	const otherClientID = "other-rp"

	// Three sessions for sessTestClientID ("test-rp") + one for a different RP.
	targetIDs := []string{
		"00000000-0000-0000-0000-000000000201",
		"00000000-0000-0000-0000-000000000202",
		"00000000-0000-0000-0000-000000000203",
	}
	for i, id := range targetIDs {
		rs := buildTestSession(t, id, sessTestUserID, []byte{byte(i)}, 14*24*time.Hour)
		if err := store.CreateSession(ctx, rs); err != nil {
			t.Fatalf("CreateSession %s: %v", id, err)
		}
	}

	// One session for a DIFFERENT client — must survive the revoke.
	otherSess := oidc.RefreshSession{
		ID:        "00000000-0000-0000-0000-000000000204",
		Region:    sessTestRegion,
		UserID:    sessTestUserID,
		ClientID:  otherClientID,
		TokenHash: []byte{0xff},
		ExpiresAt: time.Now().Add(14 * 24 * time.Hour),
	}
	if err := store.CreateSession(ctx, otherSess); err != nil {
		t.Fatalf("CreateSession other-rp: %v", err)
	}

	// Revoke (user, test-rp) family only.
	if err := store.RevokeSessionsByUserClient(ctx, sessTestUserID, sessTestClientID); err != nil {
		t.Fatalf("RevokeSessionsByUserClient: %v", err)
	}

	// All test-rp sessions must be revoked.
	for _, id := range targetIDs {
		row := q.byID[id]
		if !isRevoked(row) {
			t.Errorf("session %s (client %q) should be revoked but is not", id, sessTestClientID)
		}
	}

	// The other-rp session must still be active.
	otherRow := q.byID[otherSess.ID]
	if isRevoked(otherRow) {
		t.Errorf("session %s (client %q) must NOT be revoked by a %q family revoke",
			otherSess.ID, otherClientID, sessTestClientID)
	}
}

// TestDBSessionStoreGetByTokenHash exercises the real by-hash lookup backed by
// the GetSessionByHash query (migration 0004): unknown → not-found, valid →
// session, revoked → revoked (with the row returned for the theft signal),
// expired → not-found (fail closed).
func TestDBSessionStoreGetByTokenHash(t *testing.T) {
	q := newFakeSessionQuerier()
	store := NewDBSessionStore(q)
	ctx := context.Background()

	// Unknown hash → not-found.
	if _, err := store.GetSessionByTokenHash(ctx, []byte("no-such-hash")); !errors.Is(err, oidc.ErrRefreshTokenNotFound) {
		t.Fatalf("unknown hash: expected ErrRefreshTokenNotFound, got %v", err)
	}

	// Valid hash → returns the session.
	hash := []byte("sha256-valid-hash-32-bytes-------")
	rs := buildTestSession(t, "00000000-0000-0000-0000-000000000301", sessTestUserID, hash, 14*24*time.Hour)
	if err := store.CreateSession(ctx, rs); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	got, err := store.GetSessionByTokenHash(ctx, hash)
	if err != nil {
		t.Fatalf("GetSessionByTokenHash valid: %v", err)
	}
	if got.ID != rs.ID {
		t.Fatalf("expected session ID %q, got %q", rs.ID, got.ID)
	}

	// Revoked session → ErrRefreshTokenRevoked, and the revoked row is returned
	// so the caller can fire the theft-signal family revoke.
	if err := store.RevokeSession(ctx, rs.ID); err != nil {
		t.Fatalf("RevokeSession: %v", err)
	}
	revoked, err := store.GetSessionByTokenHash(ctx, hash)
	if !errors.Is(err, oidc.ErrRefreshTokenRevoked) {
		t.Fatalf("revoked hash: expected ErrRefreshTokenRevoked, got %v", err)
	}
	if revoked.ID != rs.ID {
		t.Fatalf("revoked session must be returned; expected ID %q, got %q", rs.ID, revoked.ID)
	}

	// Expired session → not-found (fail closed).
	expHash := []byte("sha256-expired-hash-32-bytes-----")
	exp := buildTestSession(t, "00000000-0000-0000-0000-000000000302", sessTestUserID, expHash, -time.Hour)
	if err := store.CreateSession(ctx, exp); err != nil {
		t.Fatalf("CreateSession expired: %v", err)
	}
	if _, err := store.GetSessionByTokenHash(ctx, expHash); !errors.Is(err, oidc.ErrRefreshTokenNotFound) {
		t.Fatalf("expired hash: expected ErrRefreshTokenNotFound, got %v", err)
	}
}

// TestDBSessionStoreRotateSession verifies that RotateSession (sequential
// fallback path — no pgxpool wired) atomically revokes the old token and
// creates the new one. The old token must come back as ErrRefreshTokenRevoked
// (not just not-found) so the theft signal can still fire if it is replayed.
func TestDBSessionStoreRotateSession(t *testing.T) {
	q := newFakeSessionQuerier()
	store := NewDBSessionStore(q)
	ctx := context.Background()

	hash1 := []byte("sha256-old-hash-32-bytes---------")
	rs1 := buildTestSession(t, "00000000-0000-0000-0000-000000000401", sessTestUserID, hash1, 14*24*time.Hour)
	if err := store.CreateSession(ctx, rs1); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	hash2 := []byte("sha256-new-hash-32-bytes---------")
	rs2 := buildTestSession(t, "00000000-0000-0000-0000-000000000402", sessTestUserID, hash2, 14*24*time.Hour)
	if err := store.RotateSession(ctx, rs1.ID, rs2); err != nil {
		t.Fatalf("RotateSession: %v", err)
	}

	// Old token → revoked (not just not-found) so theft signal can still fire.
	_, err := store.GetSessionByTokenHash(ctx, hash1)
	if !errors.Is(err, oidc.ErrRefreshTokenRevoked) {
		t.Fatalf("old token after rotation: expected ErrRefreshTokenRevoked, got %v", err)
	}

	// New token → active and returns the correct session.
	got, err := store.GetSessionByTokenHash(ctx, hash2)
	if err != nil {
		t.Fatalf("new token after rotation: %v", err)
	}
	if got.ID != rs2.ID {
		t.Fatalf("expected new session ID %q, got %q", rs2.ID, got.ID)
	}
}

// TestDBSessionStoreGetByTokenHash_RevokedAndExpired verifies the revoked check
// takes precedence over the expiry check: a session that is BOTH revoked and
// past its ExpiresAt must still return ErrRefreshTokenRevoked (with the row
// populated) so a replayed stolen-and-rotated token fires the theft-signal
// family revoke (INV-REFRESH-THEFT-SIGNAL-FAMILY-REVOKE) instead of silently
// collapsing to not-found.
func TestDBSessionStoreGetByTokenHash_RevokedAndExpired(t *testing.T) {
	q := newFakeSessionQuerier()
	store := NewDBSessionStore(q)
	ctx := context.Background()

	// Create an already-expired session (negative TTL), then revoke it.
	hash := []byte("sha256-revoked-expired-32-bytes--")
	rs := buildTestSession(t, "00000000-0000-0000-0000-000000000501", sessTestUserID, hash, -time.Hour)
	if err := store.CreateSession(ctx, rs); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if err := store.RevokeSession(ctx, rs.ID); err != nil {
		t.Fatalf("RevokeSession: %v", err)
	}

	got, err := store.GetSessionByTokenHash(ctx, hash)
	if !errors.Is(err, oidc.ErrRefreshTokenRevoked) {
		t.Fatalf("revoked+expired: expected ErrRefreshTokenRevoked, got %v", err)
	}
	if got.ID != rs.ID {
		t.Fatalf("revoked session must be returned for the theft signal; expected ID %q, got %q", rs.ID, got.ID)
	}
}

// errSessionQuerier is a sessionQuerier whose GetSessionByHash returns a
// non-ErrNoRows error, simulating a transient DB failure. Only GetSessionByHash
// is exercised; the other methods panic because they must never be reached on
// this path.
type errSessionQuerier struct{ err error }

func (e *errSessionQuerier) GetSessionByHash(context.Context, []byte) (db.Session, error) {
	return db.Session{}, e.err
}
func (e *errSessionQuerier) CreateSession(context.Context, db.CreateSessionParams) (db.Session, error) {
	panic("unexpected CreateSession")
}
func (e *errSessionQuerier) GetSession(context.Context, pgtype.UUID) (db.Session, error) {
	panic("unexpected GetSession")
}
func (e *errSessionQuerier) GetActiveSession(context.Context, pgtype.UUID) (db.Session, error) {
	panic("unexpected GetActiveSession")
}
func (e *errSessionQuerier) ListSessionsByUser(context.Context, pgtype.UUID) ([]db.Session, error) {
	panic("unexpected ListSessionsByUser")
}
func (e *errSessionQuerier) RevokeSession(context.Context, pgtype.UUID) error {
	panic("unexpected RevokeSession")
}
func (e *errSessionQuerier) RevokeSessionsByUser(context.Context, pgtype.UUID) error {
	panic("unexpected RevokeSessionsByUser")
}
func (e *errSessionQuerier) RevokeSessionsByUserClient(context.Context, db.RevokeSessionsByUserClientParams) error {
	panic("unexpected RevokeSessionsByUserClient")
}

// TestDBSessionStoreGetByTokenHash_DBError verifies a transient (non-ErrNoRows)
// DB error is propagated as-is and NOT masked as ErrRefreshTokenNotFound.
// Masking a DB outage as not-found would surface as invalid_grant and silently
// reject valid tokens, triggering a mass logout (docs/DESIGN.md §10).
func TestDBSessionStoreGetByTokenHash_DBError(t *testing.T) {
	dbErr := errors.New("connection reset by peer")
	store := NewDBSessionStore(&errSessionQuerier{err: dbErr})

	_, err := store.GetSessionByTokenHash(context.Background(), []byte("any-hash"))
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if errors.Is(err, oidc.ErrRefreshTokenNotFound) {
		t.Fatalf("DB error must not be masked as ErrRefreshTokenNotFound; got %v", err)
	}
	if !errors.Is(err, dbErr) {
		t.Fatalf("expected wrapped DB error %v, got %v", dbErr, err)
	}
}
