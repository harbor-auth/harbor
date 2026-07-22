package webauthn

import (
	"bytes"
	"context"
	"errors"
	"testing"

	gowebauthn "github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	db "github.com/harbor-auth/harbor/internal/gen/db"
)

// fakeStoreQuerier is an in-memory implementation of dbStoreQuerier for tests.
type fakeStoreQuerier struct {
	users            map[pgtype.UUID]db.User
	credentials      []db.Credential
	recoveryComplete map[pgtype.UUID]bool
}

func newFakeStoreQuerier() *fakeStoreQuerier {
	return &fakeStoreQuerier{
		users:            make(map[pgtype.UUID]db.User),
		recoveryComplete: make(map[pgtype.UUID]bool),
	}
}

func (f *fakeStoreQuerier) GetUser(_ context.Context, id pgtype.UUID) (db.User, error) {
	u, ok := f.users[id]
	if !ok {
		return db.User{}, errors.New("not found")
	}
	return u, nil
}

func (f *fakeStoreQuerier) ListCredentialsByUser(_ context.Context, userID pgtype.UUID) ([]db.Credential, error) {
	var out []db.Credential
	for _, c := range f.credentials {
		if c.UserID == userID {
			out = append(out, c)
		}
	}
	return out, nil
}

func (f *fakeStoreQuerier) CreateCredential(_ context.Context, arg db.CreateCredentialParams) (db.Credential, error) {
	c := db.Credential{
		ID:             arg.ID,
		Region:         arg.Region,
		UserID:         arg.UserID,
		Type:           arg.Type,
		WebauthnCredID: arg.WebauthnCredID,
		WebauthnPubkey: arg.WebauthnPubkey,
		WebauthnAaguid: arg.WebauthnAaguid,
		SignCount:      arg.SignCount,
	}
	f.credentials = append(f.credentials, c)
	return c, nil
}

func (f *fakeStoreQuerier) GetCredentialByWebAuthnCredID(_ context.Context, credID []byte) (db.Credential, error) {
	for _, c := range f.credentials {
		if bytes.Equal(c.WebauthnCredID, credID) {
			return c, nil
		}
	}
	return db.Credential{}, errors.New("not found")
}

func (f *fakeStoreQuerier) UpdateCredentialSignCount(_ context.Context, arg db.UpdateCredentialSignCountParams) error {
	for i, c := range f.credentials {
		if c.ID == arg.ID {
			f.credentials[i].SignCount = arg.SignCount
			return nil
		}
	}
	return errors.New("not found")
}

func (f *fakeStoreQuerier) SetRecoveryComplete(_ context.Context, id pgtype.UUID) error {
	if _, ok := f.users[id]; !ok {
		return errors.New("not found")
	}
	f.recoveryComplete[id] = true
	return nil
}

// pgUUID builds a pgtype.UUID from a google/uuid value.
func pgUUID(id uuid.UUID) pgtype.UUID {
	return pgtype.UUID{Bytes: id, Valid: true}
}

// --- helpers ----------------------------------------------------------------

func newFakeDBStore(t *testing.T) (*DBStore, *fakeStoreQuerier, pgtype.UUID) {
	t.Helper()
	q := newFakeStoreQuerier()
	id := uuid.New()
	uid := pgUUID(id)
	q.users[uid] = db.User{
		ID:     uid,
		Region: "EU",
		Status: "active",
	}
	return NewDBStore(q), q, uid
}

func uidBytes(uid pgtype.UUID) []byte {
	u := uuid.UUID(uid.Bytes)
	return []byte(u.String())
}

// --- tests ------------------------------------------------------------------

func TestDBStore_GetUser_NotFound(t *testing.T) {
	s := NewDBStore(newFakeStoreQuerier())
	// A valid UUID string that doesn't exist in the store.
	missing := []byte(uuid.New().String())
	if _, err := s.GetUser(context.Background(), missing); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("err = %v, want ErrUserNotFound", err)
	}
}

func TestDBStore_GetUser_InvalidHandle(t *testing.T) {
	s := NewDBStore(newFakeStoreQuerier())
	// A non-UUID byte slice must also return ErrUserNotFound (not an internal error).
	if _, err := s.GetUser(context.Background(), []byte("not-a-uuid")); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("err = %v, want ErrUserNotFound", err)
	}
}

func TestDBStore_GetUser_OK(t *testing.T) {
	s, _, uid := newFakeDBStore(t)
	u, err := s.GetUser(context.Background(), uidBytes(uid))
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if !bytes.Equal(u.WebAuthnID(), uidBytes(uid)) {
		t.Fatal("user ID mismatch")
	}
	if len(u.WebAuthnCredentials()) != 0 {
		t.Fatalf("want 0 credentials, got %d", len(u.WebAuthnCredentials()))
	}
}

func TestDBStore_AddCredential_OK(t *testing.T) {
	s, q, uid := newFakeDBStore(t)
	cred := gowebauthn.Credential{
		ID:        []byte("webauthn-cred-id-1"),
		PublicKey: []byte("cose-pubkey"),
	}
	cred.Authenticator.AAGUID = []byte("aaguid")
	cred.Authenticator.SignCount = 1

	if err := s.AddCredential(context.Background(), uidBytes(uid), cred); err != nil {
		t.Fatalf("AddCredential: %v", err)
	}
	if len(q.credentials) != 1 {
		t.Fatalf("want 1 credential in store, got %d", len(q.credentials))
	}
	got := q.credentials[0]
	if !bytes.Equal(got.WebauthnCredID, cred.ID) {
		t.Fatal("webauthn_cred_id mismatch")
	}
	if got.SignCount != 1 {
		t.Fatalf("sign_count = %d, want 1", got.SignCount)
	}
}

func TestDBStore_AddCredential_UnknownUser(t *testing.T) {
	s := NewDBStore(newFakeStoreQuerier())
	err := s.AddCredential(context.Background(), []byte(uuid.New().String()), gowebauthn.Credential{ID: []byte("c")})
	if !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("err = %v, want ErrUserNotFound", err)
	}
}

func TestDBStore_UpdateCredential_OK(t *testing.T) {
	s, _, uid := newFakeDBStore(t)
	cred := gowebauthn.Credential{
		ID:        []byte("webauthn-cred-id-2"),
		PublicKey: []byte("pk"),
	}
	cred.Authenticator.SignCount = 1
	if err := s.AddCredential(context.Background(), uidBytes(uid), cred); err != nil {
		t.Fatalf("AddCredential: %v", err)
	}

	cred.Authenticator.SignCount = 5
	if err := s.UpdateCredential(context.Background(), uidBytes(uid), cred); err != nil {
		t.Fatalf("UpdateCredential: %v", err)
	}

	u, err := s.GetUser(context.Background(), uidBytes(uid))
	if err != nil {
		t.Fatalf("GetUser after update: %v", err)
	}
	if got := u.WebAuthnCredentials()[0].Authenticator.SignCount; got != 5 {
		t.Fatalf("sign_count = %d, want 5", got)
	}
}

func TestDBStore_UpdateCredential_CrossUserBlocked(t *testing.T) {
	q := newFakeStoreQuerier()

	// Two users.
	id1, id2 := uuid.New(), uuid.New()
	uid1, uid2 := pgUUID(id1), pgUUID(id2)
	q.users[uid1] = db.User{ID: uid1, Region: "EU", Status: "active"}
	q.users[uid2] = db.User{ID: uid2, Region: "EU", Status: "active"}

	s := NewDBStore(q)
	cred := gowebauthn.Credential{ID: []byte("shared-cred"), PublicKey: []byte("pk")}
	cred.Authenticator.SignCount = 1

	// Enroll cred under user1.
	if err := s.AddCredential(context.Background(), []byte(id1.String()), cred); err != nil {
		t.Fatalf("AddCredential: %v", err)
	}

	// User2 tries to update user1's credential.
	cred.Authenticator.SignCount = 2
	err := s.UpdateCredential(context.Background(), []byte(id2.String()), cred)
	if !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("cross-user update: err = %v, want ErrUserNotFound", err)
	}
}

func TestDBStore_SetRecoveryComplete_OK(t *testing.T) {
	s, q, uid := newFakeDBStore(t)
	if err := s.SetRecoveryComplete(context.Background(), uidBytes(uid)); err != nil {
		t.Fatalf("SetRecoveryComplete: %v", err)
	}
	if !q.recoveryComplete[uid] {
		t.Fatal("expected recovery_required to be cleared for the user")
	}
}

func TestDBStore_SetRecoveryComplete_UnknownUser(t *testing.T) {
	s := NewDBStore(newFakeStoreQuerier())
	err := s.SetRecoveryComplete(context.Background(), []byte(uuid.New().String()))
	if !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("err = %v, want ErrUserNotFound", err)
	}
}

func TestDBStore_SetRecoveryComplete_InvalidHandle(t *testing.T) {
	s := NewDBStore(newFakeStoreQuerier())
	if err := s.SetRecoveryComplete(context.Background(), []byte("not-a-uuid")); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("err = %v, want ErrUserNotFound", err)
	}
}

func TestDBStore_UpdateCredential_SignCountRegression(t *testing.T) {
	s, _, uid := newFakeDBStore(t)
	cred := gowebauthn.Credential{ID: []byte("cred-regress"), PublicKey: []byte("pk")}
	cred.Authenticator.SignCount = 10
	if err := s.AddCredential(context.Background(), uidBytes(uid), cred); err != nil {
		t.Fatalf("AddCredential: %v", err)
	}
	// Attempt to move counter backward.
	cred.Authenticator.SignCount = 5
	if err := s.UpdateCredential(context.Background(), uidBytes(uid), cred); !errors.Is(err, ErrSignCountRegression) {
		t.Fatalf("err = %v, want ErrSignCountRegression", err)
	}
}
