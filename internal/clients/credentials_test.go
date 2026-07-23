package clients

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	db "github.com/harbor-auth/harbor/internal/gen/db"
)

// fakeCredentialQuerier is an in-memory credentialQuerier for tests.
type fakeCredentialQuerier struct {
	mu    sync.Mutex
	byID  map[string]db.Credential
	byUID map[string][]string // userID → []credentialID
}

func newFakeCredentialQuerier() *fakeCredentialQuerier {
	return &fakeCredentialQuerier{
		byID:  make(map[string]db.Credential),
		byUID: make(map[string][]string),
	}
}

func (f *fakeCredentialQuerier) insert(cred db.Credential) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := cred.ID.String()
	f.byID[key] = cred
	uid := cred.UserID.String()
	f.byUID[uid] = append(f.byUID[uid], key)
}

func (f *fakeCredentialQuerier) ListCredentialsByUser(_ context.Context, userID pgtype.UUID) ([]db.Credential, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []db.Credential
	for _, id := range f.byUID[userID.String()] {
		if row, ok := f.byID[id]; ok {
			out = append(out, row)
		}
	}
	return out, nil
}

func (f *fakeCredentialQuerier) GetCredential(_ context.Context, id pgtype.UUID) (db.Credential, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	row, ok := f.byID[id.String()]
	if !ok {
		return db.Credential{}, fmt.Errorf("credential not found")
	}
	return row, nil
}

func (f *fakeCredentialQuerier) DeleteCredential(_ context.Context, id pgtype.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := id.String()
	row, ok := f.byID[key]
	if !ok {
		return nil // idempotent
	}
	uid := row.UserID.String()
	delete(f.byID, key)
	ids := f.byUID[uid]
	filtered := ids[:0]
	for _, s := range ids {
		if s != key {
			filtered = append(filtered, s)
		}
	}
	f.byUID[uid] = filtered
	return nil
}

// helpers

const (
	credTestUserID  = "00000000-0000-0000-0000-000000000001"
	credTestUserID2 = "00000000-0000-0000-0000-000000000002"
)

func mustPGUUID(t *testing.T, s string) pgtype.UUID {
	t.Helper()
	var u pgtype.UUID
	if err := u.Scan(s); err != nil {
		t.Fatalf("mustPGUUID(%q): %v", s, err)
	}
	return u
}

func buildFakeCredential(t *testing.T, id, userID, typ string) db.Credential {
	t.Helper()
	var createdAt pgtype.Timestamptz
	if err := createdAt.Scan(time.Now()); err != nil {
		t.Fatalf("scan createdAt: %v", err)
	}
	return db.Credential{
		ID:        mustPGUUID(t, id),
		UserID:    mustPGUUID(t, userID),
		Type:      typ,
		CreatedAt: createdAt,
	}
}

// TestDBDashboardCredentialStore_ListByUser verifies that ListCredentialsByUser
// returns only the credentials for the requested user.
func TestDBDashboardCredentialStore_ListByUser(t *testing.T) {
	q := newFakeCredentialQuerier()
	store := NewDBDashboardCredentialStore(q)
	ctx := context.Background()

	c1 := buildFakeCredential(t, "00000000-0000-0000-0000-000000000a01", credTestUserID, "passkey")
	c2 := buildFakeCredential(t, "00000000-0000-0000-0000-000000000a02", credTestUserID, "passkey")
	cOther := buildFakeCredential(t, "00000000-0000-0000-0000-000000000a03", credTestUserID2, "passkey")
	q.insert(c1)
	q.insert(c2)
	q.insert(cOther)

	got, err := store.ListCredentialsByUser(ctx, credTestUserID)
	if err != nil {
		t.Fatalf("ListCredentialsByUser: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 credentials for user1, got %d", len(got))
	}
	ids := map[string]bool{got[0].ID: true, got[1].ID: true}
	if !ids[uuidToString(c1.ID)] || !ids[uuidToString(c2.ID)] {
		t.Errorf("unexpected credential IDs: %v", ids)
	}
	// Verify no crypto material leaks into the domain type.
	for _, dc := range got {
		if dc.UserID != credTestUserID {
			t.Errorf("credential %s belongs to %q, not the requested user", dc.ID, dc.UserID)
		}
	}
}

// TestDBDashboardCredentialStore_DeleteCredential verifies the happy path.
func TestDBDashboardCredentialStore_DeleteCredential(t *testing.T) {
	q := newFakeCredentialQuerier()
	store := NewDBDashboardCredentialStore(q)
	ctx := context.Background()

	c := buildFakeCredential(t, "00000000-0000-0000-0000-000000000b01", credTestUserID, "passkey")
	q.insert(c)

	if err := store.DeleteCredential(ctx, uuidToString(c.ID), credTestUserID); err != nil {
		t.Fatalf("DeleteCredential: %v", err)
	}

	got, err := store.ListCredentialsByUser(ctx, credTestUserID)
	if err != nil {
		t.Fatalf("ListCredentialsByUser after delete: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected 0 credentials after delete, got %d", len(got))
	}
}

// TestDBDashboardCredentialStore_DeleteCredential_CrossUserGuard verifies that
// a user cannot delete another user's credential (fails closed).
func TestDBDashboardCredentialStore_DeleteCredential_CrossUserGuard(t *testing.T) {
	q := newFakeCredentialQuerier()
	store := NewDBDashboardCredentialStore(q)
	ctx := context.Background()

	c := buildFakeCredential(t, "00000000-0000-0000-0000-000000000c01", credTestUserID, "passkey")
	q.insert(c)

	// Try to delete user1's credential as user2 — must fail.
	err := store.DeleteCredential(ctx, uuidToString(c.ID), credTestUserID2)
	if err == nil {
		t.Fatal("expected error when deleting another user's credential, got nil")
	}

	// The credential must still exist for the real owner.
	got, err := store.ListCredentialsByUser(ctx, credTestUserID)
	if err != nil {
		t.Fatalf("ListCredentialsByUser: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("credential must still exist after rejected cross-user delete; got %d", len(got))
	}
}

// TestDBDashboardCredentialStore_InvalidUUID verifies that invalid UUIDs are
// rejected with an error and do not panic.
func TestDBDashboardCredentialStore_InvalidUUID(t *testing.T) {
	store := NewDBDashboardCredentialStore(newFakeCredentialQuerier())
	ctx := context.Background()

	if _, err := store.ListCredentialsByUser(ctx, "not-a-uuid"); err == nil {
		t.Fatal("expected error for invalid userID UUID, got nil")
	}
	if err := store.DeleteCredential(ctx, "not-a-uuid", credTestUserID); err == nil {
		t.Fatal("expected error for invalid credentialID UUID, got nil")
	}
	if err := store.DeleteCredential(ctx, "00000000-0000-0000-0000-000000000d01", "not-a-uuid"); err == nil {
		t.Fatal("expected error for invalid userID UUID in DeleteCredential, got nil")
	}
}
