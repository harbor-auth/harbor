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
	users               map[pgtype.UUID]db.User
	credentials         []db.Credential
	recoveryComplete    map[pgtype.UUID]bool
	beforeCounterUpdate func()
	counterUpdateCalls  int
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

func (f *fakeStoreQuerier) UpdateCredentialSignCount(_ context.Context, arg db.UpdateCredentialSignCountParams) (int64, error) {
	f.counterUpdateCalls++
	if f.beforeCounterUpdate != nil {
		hook := f.beforeCounterUpdate
		f.beforeCounterUpdate = nil
		hook()
	}
	for i, c := range f.credentials {
		if c.ID == arg.ID {
			// Mirror the guarded SQL update: a stale writer affects zero rows and
			// the :execrows sqlc method exposes that result to the store.
			if c.SignCount < arg.SignCount {
				f.credentials[i].SignCount = arg.SignCount
				return 1, nil
			}
			return 0, nil
		}
	}
	return 0, errors.New("not found")
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

// uidBytes returns the raw 16-byte WebAuthn user handle for uid — the format
// mgmtapi.parseUUIDToBytes and cmd/harbor-mgmt's recoveryUserHandle actually
// produce and save into the enrollment session store (parseWebAuthnUserID
// parses this with uuid.FromBytes, not the 36-char canonical string form).
func uidBytes(uid pgtype.UUID) []byte {
	return uid.Bytes[:]
}

// --- tests ------------------------------------------------------------------

func TestDBStore_GetUser_NotFound(t *testing.T) {
	s := NewDBStore(newFakeStoreQuerier())
	// A validly-formatted handle that doesn't exist in the store.
	missing := uidBytes(pgUUID(uuid.New()))
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

// TestDBStore_GetUser_ProductionHandleFormat reproduces the handle-format
// mismatch flagged for this task: mgmtapi.parseUUIDToBytes (POST /enroll) and
// cmd/harbor-mgmt's recoveryUserHandle (POST /recovery/complete) both save the
// WebAuthn user handle as the RAW 16-byte UUID (uuid.Parse(s); id[:]) — see
// cmd/harbor-mgmt/caller_test.go's TestRecoverySessionIssuerBindsBFFAndEnrollmentRecords,
// which pins exactly that format. Every real (DB-backed) WebAuthn ceremony
// therefore calls Store.GetUser with those raw bytes, never with the
// 36-character canonical string form the rest of this file's fixtures
// (uidBytes) use.
func TestDBStore_GetUser_ProductionHandleFormat(t *testing.T) {
	s, _, uid := newFakeDBStore(t)
	rawHandle := uid.Bytes[:] // exactly what parseUUIDToBytes/recoveryUserHandle produce in production.
	if _, err := s.GetUser(context.Background(), rawHandle); err != nil {
		t.Fatalf("GetUser(raw 16-byte handle) = %v, want success — this is the handle format enrollment/recovery actually produce", err)
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
	err := s.AddCredential(context.Background(), uidBytes(pgUUID(uuid.New())), gowebauthn.Credential{ID: []byte("c")})
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
	if err := s.AddCredential(context.Background(), id1[:], cred); err != nil {
		t.Fatalf("AddCredential: %v", err)
	}

	// User2 tries to update user1's credential.
	cred.Authenticator.SignCount = 2
	err := s.UpdateCredential(context.Background(), id2[:], cred)
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
	err := s.SetRecoveryComplete(context.Background(), uidBytes(pgUUID(uuid.New())))
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

// TestDBStore_SetRecoveryComplete_CanonicalTextForm reproduces the
// recoveryRequirementClearer path: cmd/harbor-mgmt/caller.go's
// ClearRecoveryRequired (POST /recovery/acknowledge) calls SetRecoveryComplete
// with the CANONICAL 36-CHARACTER UUID TEXT form (see caller.go's doc comment
// on recoveryRequirementClearer: "the mgmtapi-side userID is always the
// canonical UUID text form"), never the raw 16-byte WebAuthn handle that
// FinishRecoveryRegistration passes for the SAME store method. Both encodings
// must resolve to the same user.
func TestDBStore_SetRecoveryComplete_CanonicalTextForm(t *testing.T) {
	s, q, uid := newFakeDBStore(t)
	textHandle := []byte(uuid.UUID(uid.Bytes).String())
	if err := s.SetRecoveryComplete(context.Background(), textHandle); err != nil {
		t.Fatalf("SetRecoveryComplete(canonical text handle) = %v, want success — this is the encoding recoveryRequirementClearer.ClearRecoveryRequired actually sends", err)
	}
	if !q.recoveryComplete[uid] {
		t.Fatal("expected recovery_required to be cleared for the user")
	}
}

// TestDBStore_SetRecoveryComplete_BothEncodingsResolveSameUser locks in that
// the raw 16-byte WebAuthn handle (ceremony path, e.g.
// FinishRecoveryRegistration) and the canonical UUID text form (mgmtapi
// recoveryRequirementClearer path) are two encodings of the SAME identifier,
// not two different ones — parseWebAuthnUserID must dispatch between them by
// length rather than picking one and breaking the other caller.
func TestDBStore_SetRecoveryComplete_BothEncodingsResolveSameUser(t *testing.T) {
	s, q, uid := newFakeDBStore(t)
	rawHandle := uid.Bytes[:]
	textHandle := []byte(uuid.UUID(uid.Bytes).String())

	if err := s.SetRecoveryComplete(context.Background(), rawHandle); err != nil {
		t.Fatalf("SetRecoveryComplete(raw handle): %v", err)
	}
	if !q.recoveryComplete[uid] {
		t.Fatal("raw-handle call did not clear recovery_required")
	}

	delete(q.recoveryComplete, uid)

	if err := s.SetRecoveryComplete(context.Background(), textHandle); err != nil {
		t.Fatalf("SetRecoveryComplete(text handle): %v", err)
	}
	if !q.recoveryComplete[uid] {
		t.Fatal("text-handle call did not clear recovery_required for the same user")
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

// A preflight read cannot protect the counter: another replica can advance it
// before this replica executes its guarded UPDATE. The zero-row result is a
// clone/replay signal and must not be reported as a successful login.
func TestDBStore_UpdateCredential_ConcurrentNoOpIsRegression(t *testing.T) {
	s, q, uid := newFakeDBStore(t)
	cred := gowebauthn.Credential{ID: []byte("cred-concurrent"), PublicKey: []byte("pk")}
	cred.Authenticator.SignCount = 7
	if err := s.AddCredential(context.Background(), uidBytes(uid), cred); err != nil {
		t.Fatalf("AddCredential: %v", err)
	}

	q.beforeCounterUpdate = func() {
		// A concurrent assertion using the same observed counter wins first.
		q.credentials[0].SignCount = 8
	}
	cred.Authenticator.SignCount = 8
	if err := s.UpdateCredential(context.Background(), uidBytes(uid), cred); !errors.Is(err, ErrSignCountRegression) {
		t.Fatalf("concurrent guarded no-op: err = %v, want ErrSignCountRegression", err)
	}
	if got := q.credentials[0].SignCount; got != 8 {
		t.Fatalf("sign_count = %d, want concurrent winner's 8", got)
	}
}

// WebAuthn authenticators that do not implement a signature counter always
// return zero. Zero-to-zero is valid and should not execute a guarded SQL
// update whose zero-row result is otherwise treated as a clone signal.
func TestDBStore_UpdateCredential_ZeroCounterSkipsUpdate(t *testing.T) {
	s, q, uid := newFakeDBStore(t)
	cred := gowebauthn.Credential{ID: []byte("cred-zero-counter"), PublicKey: []byte("pk")}
	if err := s.AddCredential(context.Background(), uidBytes(uid), cred); err != nil {
		t.Fatalf("AddCredential: %v", err)
	}

	if err := s.UpdateCredential(context.Background(), uidBytes(uid), cred); err != nil {
		t.Fatalf("zero-counter authenticator: %v", err)
	}
	if q.counterUpdateCalls != 0 {
		t.Fatalf("guarded update calls = %d, want 0 for unsupported counter", q.counterUpdateCalls)
	}
}
