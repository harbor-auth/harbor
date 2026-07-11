package clients

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/harbor/harbor/internal/gen/db"
	"github.com/harbor/harbor/internal/oidc"
)

// fakeGrantQuerier is an in-memory grantQuerier fake for unit tests.
type fakeGrantQuerier struct {
	rows  map[string]*db.Grant // keyed by UUID string
	dbErr error                // if non-nil, every call returns this
}

func newFakeGrantQuerier() *fakeGrantQuerier {
	return &fakeGrantQuerier{rows: make(map[string]*db.Grant)}
}

func pgUUID(s string) pgtype.UUID {
	var u pgtype.UUID
	if err := u.Scan(s); err != nil {
		panic("pgUUID: invalid UUID " + s + ": " + err.Error())
	}
	return u
}

func (f *fakeGrantQuerier) FindGrantByUserClient(_ context.Context, arg db.FindGrantByUserClientParams) (db.Grant, error) {
	if f.dbErr != nil {
		return db.Grant{}, f.dbErr
	}
	for _, g := range f.rows {
		if g.UserID == arg.UserID && g.ClientID == arg.ClientID && !g.RevokedAt.Valid {
			return *g, nil
		}
	}
	return db.Grant{}, pgx.ErrNoRows
}

func (f *fakeGrantQuerier) CreateGrant(_ context.Context, arg db.CreateGrantParams) (db.Grant, error) {
	if f.dbErr != nil {
		return db.Grant{}, f.dbErr
	}
	row := &db.Grant{
		ID:          arg.ID,
		Region:      arg.Region,
		UserID:      arg.UserID,
		ClientID:    arg.ClientID,
		PairwiseSub: arg.PairwiseSub,
		Scopes:      arg.Scopes,
		CreatedAt:   pgtype.Timestamptz{Time: time.Now(), Valid: true},
	}
	f.rows[uuidToString(arg.ID)] = row
	return *row, nil
}

func (f *fakeGrantQuerier) RevokeGrant(_ context.Context, id pgtype.UUID) error {
	if f.dbErr != nil {
		return f.dbErr
	}
	key := uuidToString(id)
	row, ok := f.rows[key]
	if !ok {
		return nil
	}
	row.RevokedAt = pgtype.Timestamptz{Time: time.Now(), Valid: true}
	return nil
}

func (f *fakeGrantQuerier) ListGrantsByUser(_ context.Context, userID pgtype.UUID) ([]db.Grant, error) {
	if f.dbErr != nil {
		return nil, f.dbErr
	}
	var out []db.Grant
	for _, g := range f.rows {
		if g.UserID == userID && !g.RevokedAt.Valid {
			out = append(out, *g)
		}
	}
	return out, nil
}

const testUserID = "a0000000-0000-0000-0000-000000000001"

func TestRowToGrant(t *testing.T) {
	now := time.Now().Truncate(time.Millisecond)
	row := db.Grant{
		ID:          pgUUID("b0000000-0000-0000-0000-000000000002"),
		Region:      "eu-1",
		UserID:      pgUUID(testUserID),
		ClientID:    "rp-1",
		PairwiseSub: "ppid-abc",
		Scopes:      []string{"openid", "email"},
		CreatedAt:   pgtype.Timestamptz{Time: now, Valid: true},
	}
	g := rowToGrant(row)
	if g.Region != "eu-1" {
		t.Errorf("Region: got %q", g.Region)
	}
	if g.ClientID != "rp-1" {
		t.Errorf("ClientID: got %q", g.ClientID)
	}
	if g.PairwiseSub != "ppid-abc" {
		t.Errorf("PairwiseSub: got %q", g.PairwiseSub)
	}
	if len(g.Scopes) != 2 {
		t.Errorf("Scopes: got %d, want 2", len(g.Scopes))
	}
	if g.RevokedAt != nil {
		t.Error("RevokedAt should be nil for active grant")
	}
}

func TestRowToGrantRevoked(t *testing.T) {
	now := time.Now()
	row := db.Grant{
		ID:        pgUUID("c0000000-0000-0000-0000-000000000003"),
		UserID:    pgUUID(testUserID),
		ClientID:  "rp-2",
		CreatedAt: pgtype.Timestamptz{Time: now, Valid: true},
		RevokedAt: pgtype.Timestamptz{Time: now, Valid: true},
	}
	g := rowToGrant(row)
	if g.RevokedAt == nil {
		t.Error("RevokedAt should be non-nil for revoked grant")
	}
}

func TestDBGrantStoreCreateAndFind(t *testing.T) {
	q := newFakeGrantQuerier()
	s := NewDBGrantStore(q)
	ctx := context.Background()

	created, err := s.CreateGrant(ctx, oidc.NewGrant{
		Region:      "eu-1",
		UserID:      testUserID,
		ClientID:    "rp-1",
		PairwiseSub: "ppid-xyz",
		Scopes:      []string{"openid"},
	})
	if err != nil {
		t.Fatalf("CreateGrant: %v", err)
	}
	if created.ID == "" {
		t.Error("created grant should have a non-empty ID")
	}
	if created.PairwiseSub != "ppid-xyz" {
		t.Errorf("PairwiseSub: got %q", created.PairwiseSub)
	}

	// FindGrant should return the just-created grant.
	g, found, err := s.FindGrant(ctx, testUserID, "rp-1")
	if err != nil {
		t.Fatalf("FindGrant: %v", err)
	}
	if !found {
		t.Fatal("expected found=true after CreateGrant")
	}
	if g.PairwiseSub != "ppid-xyz" {
		t.Errorf("PairwiseSub: got %q", g.PairwiseSub)
	}
}

func TestDBGrantStoreActiveOnlyAfterRevoke(t *testing.T) {
	//harbor:invariant INV-GRANT-ACTIVE-ONLY
	q := newFakeGrantQuerier()
	s := NewDBGrantStore(q)
	ctx := context.Background()

	created, err := s.CreateGrant(ctx, oidc.NewGrant{
		UserID: testUserID, ClientID: "rp-1", PairwiseSub: "ppid-1",
	})
	if err != nil {
		t.Fatalf("CreateGrant: %v", err)
	}

	// Revoke it.
	if err := s.RevokeGrant(ctx, created.ID); err != nil {
		t.Fatalf("RevokeGrant: %v", err)
	}

	// FindGrant must not return the revoked grant.
	_, found, err := s.FindGrant(ctx, testUserID, "rp-1")
	if err != nil {
		t.Fatalf("FindGrant after revoke: %v", err)
	}
	if found {
		t.Error("revoked grant must not be returned by FindGrant")
	}
}

func TestDBGrantStoreFindNotFound(t *testing.T) {
	s := NewDBGrantStore(newFakeGrantQuerier())
	_, found, err := s.FindGrant(context.Background(), testUserID, "nonexistent")
	if err != nil {
		t.Fatalf("FindGrant: %v", err)
	}
	if found {
		t.Error("expected found=false for nonexistent grant")
	}
}

func TestDBGrantStoreFindDBError(t *testing.T) {
	q := &fakeGrantQuerier{rows: make(map[string]*db.Grant), dbErr: errors.New("db timeout")}
	s := NewDBGrantStore(q)
	_, _, err := s.FindGrant(context.Background(), testUserID, "rp-1")
	if err == nil {
		t.Error("expected error propagation from DB error")
	}
}

func TestDBGrantStorePPIDBound(t *testing.T) {
	//harbor:invariant INV-GRANT-PPID-BOUND
	q := newFakeGrantQuerier()
	s := NewDBGrantStore(q)
	ctx := context.Background()

	created, err := s.CreateGrant(ctx, oidc.NewGrant{
		UserID: testUserID, ClientID: "rp-1", PairwiseSub: "ppid-bound-at-consent",
	})
	if err != nil {
		t.Fatalf("CreateGrant: %v", err)
	}

	// The pairwise_sub stored is exactly what was supplied at consent time.
	if created.PairwiseSub != "ppid-bound-at-consent" {
		t.Errorf("PairwiseSub not preserved: got %q", created.PairwiseSub)
	}

	// Re-reading via FindGrant returns the same value.
	g, found, err := s.FindGrant(ctx, testUserID, "rp-1")
	if err != nil || !found {
		t.Fatalf("FindGrant: err=%v found=%v", err, found)
	}
	if g.PairwiseSub != "ppid-bound-at-consent" {
		t.Errorf("PairwiseSub changed on read: got %q", g.PairwiseSub)
	}
}

func TestDBGrantStoreListByUser(t *testing.T) {
	q := newFakeGrantQuerier()
	s := NewDBGrantStore(q)
	ctx := context.Background()

	if _, err := s.CreateGrant(ctx, oidc.NewGrant{
		UserID: testUserID, ClientID: "rp-1", PairwiseSub: "ppid-1",
	}); err != nil {
		t.Fatalf("CreateGrant: %v", err)
	}
	if _, err := s.CreateGrant(ctx, oidc.NewGrant{
		UserID: testUserID, ClientID: "rp-2", PairwiseSub: "ppid-2",
	}); err != nil {
		t.Fatalf("CreateGrant: %v", err)
	}

	grants, err := s.ListGrantsByUser(ctx, testUserID)
	if err != nil {
		t.Fatalf("ListGrantsByUser: %v", err)
	}
	if len(grants) != 2 {
		t.Errorf("expected 2 grants, got %d", len(grants))
	}
}

func TestDBGrantStoreInvalidUUID(t *testing.T) {
	s := NewDBGrantStore(newFakeGrantQuerier())
	_, _, err := s.FindGrant(context.Background(), "not-a-uuid", "rp-1")
	if err == nil {
		t.Error("expected error for invalid UUID")
	}
}

func TestDBGrantStoreImplementsInterface(t *testing.T) {
	var _ oidc.GrantStore = (*DBGrantStore)(nil)
}

// --- Additional edge case tests ---

func TestDBGrantStoreCreateGrantDBError(t *testing.T) {
	q := &fakeGrantQuerier{rows: make(map[string]*db.Grant), dbErr: errors.New("db insert failed")}
	s := NewDBGrantStore(q)
	_, err := s.CreateGrant(context.Background(), oidc.NewGrant{
		UserID:   testUserID,
		ClientID: "rp-1",
	})
	if err == nil {
		t.Error("expected error propagation from DB error")
	}
}

func TestDBGrantStoreCreateGrantInvalidUUID(t *testing.T) {
	s := NewDBGrantStore(newFakeGrantQuerier())
	_, err := s.CreateGrant(context.Background(), oidc.NewGrant{
		UserID:   "not-a-valid-uuid",
		ClientID: "rp-1",
	})
	if err == nil {
		t.Error("expected error for invalid UUID")
	}
}

func TestDBGrantStoreRevokeGrantDBError(t *testing.T) {
	q := &fakeGrantQuerier{rows: make(map[string]*db.Grant), dbErr: errors.New("db revoke failed")}
	s := NewDBGrantStore(q)
	err := s.RevokeGrant(context.Background(), "b0000000-0000-0000-0000-000000000002")
	if err == nil {
		t.Error("expected error propagation from DB error")
	}
}

func TestDBGrantStoreRevokeGrantInvalidUUID(t *testing.T) {
	s := NewDBGrantStore(newFakeGrantQuerier())
	err := s.RevokeGrant(context.Background(), "not-a-valid-uuid")
	if err == nil {
		t.Error("expected error for invalid UUID")
	}
}

func TestDBGrantStoreListGrantsByUserDBError(t *testing.T) {
	q := &fakeGrantQuerier{rows: make(map[string]*db.Grant), dbErr: errors.New("db list failed")}
	s := NewDBGrantStore(q)
	_, err := s.ListGrantsByUser(context.Background(), testUserID)
	if err == nil {
		t.Error("expected error propagation from DB error")
	}
}

func TestDBGrantStoreListGrantsByUserInvalidUUID(t *testing.T) {
	s := NewDBGrantStore(newFakeGrantQuerier())
	_, err := s.ListGrantsByUser(context.Background(), "not-a-valid-uuid")
	if err == nil {
		t.Error("expected error for invalid UUID")
	}
}

func TestDBGrantStoreListGrantsByUserEmpty(t *testing.T) {
	s := NewDBGrantStore(newFakeGrantQuerier())
	grants, err := s.ListGrantsByUser(context.Background(), testUserID)
	if err != nil {
		t.Fatalf("ListGrantsByUser: %v", err)
	}
	if len(grants) != 0 {
		t.Errorf("expected empty list, got %d grants", len(grants))
	}
}

func TestDBGrantStoreRevokeNonexistentGrant(t *testing.T) {
	s := NewDBGrantStore(newFakeGrantQuerier())
	// Should not error when revoking a grant that doesn't exist.
	err := s.RevokeGrant(context.Background(), "b0000000-0000-0000-0000-000000000099")
	if err != nil {
		t.Errorf("RevokeGrant on nonexistent: %v", err)
	}
}

func TestRowToGrantWithNilScopes(t *testing.T) {
	row := db.Grant{
		ID:        pgUUID("d0000000-0000-0000-0000-000000000004"),
		UserID:    pgUUID(testUserID),
		ClientID:  "rp-nil-scopes",
		Scopes:    nil, // nil slice
		CreatedAt: pgtype.Timestamptz{Time: time.Now(), Valid: true},
	}
	g := rowToGrant(row)
	// nil scopes is acceptable; verify no panic and length is 0.
	if len(g.Scopes) != 0 {
		t.Errorf("expected empty scopes, got %d", len(g.Scopes))
	}
}

func TestUUIDToStringInvalid(t *testing.T) {
	// An invalid (zero) pgtype.UUID should return the zero UUID string.
	var invalid pgtype.UUID // Valid = false by default
	result := uuidToString(invalid)
	if result != "00000000-0000-0000-0000-000000000000" {
		t.Errorf("expected zero UUID string, got %q", result)
	}
}
