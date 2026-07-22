package webauthn

import (
	"context"
	"errors"
	"testing"

	gowebauthn "github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	db "github.com/harbor/harbor/internal/gen/db"
)

// activateFakeQuerier implements dbStoreQuerier plus SetUserStatus, so it also
// satisfies activationQuerier and exercises the atomic activation path via the
// no-pool fallback (no real DB or fake transaction needed).
type activateFakeQuerier struct {
	user         db.User
	getUserErr   error
	createErr    error
	setStatusErr error

	createdCred *db.CreateCredentialParams
	statusSet   *db.SetUserStatusParams
}

func (f *activateFakeQuerier) GetUser(_ context.Context, _ pgtype.UUID) (db.User, error) {
	if f.getUserErr != nil {
		return db.User{}, f.getUserErr
	}
	return f.user, nil
}

func (f *activateFakeQuerier) ListCredentialsByUser(_ context.Context, _ pgtype.UUID) ([]db.Credential, error) {
	return nil, nil
}

func (f *activateFakeQuerier) CreateCredential(_ context.Context, arg db.CreateCredentialParams) (db.Credential, error) {
	if f.createErr != nil {
		return db.Credential{}, f.createErr
	}
	a := arg
	f.createdCred = &a
	return db.Credential{ID: arg.ID}, nil
}

func (f *activateFakeQuerier) GetCredentialByWebAuthnCredID(_ context.Context, _ []byte) (db.Credential, error) {
	return db.Credential{}, nil
}

func (f *activateFakeQuerier) UpdateCredentialSignCount(_ context.Context, _ db.UpdateCredentialSignCountParams) error {
	return nil
}

func (f *activateFakeQuerier) SetUserStatus(_ context.Context, arg db.SetUserStatusParams) error {
	if f.setStatusErr != nil {
		return f.setStatusErr
	}
	a := arg
	f.statusSet = &a
	return nil
}

func (f *activateFakeQuerier) SetRecoveryComplete(_ context.Context, _ pgtype.UUID) error {
	return nil
}

// handleBytes returns a UUID's canonical string form as bytes — Harbor's
// WebAuthn user handle format (parseWebAuthnUserID uses uuid.ParseBytes).
func handleBytes(u uuid.UUID) []byte { return []byte(u.String()) }

func TestDBStore_AddCredentialAndActivateUser_CreatesAndActivates(t *testing.T) {
	u := uuid.New()
	fake := &activateFakeQuerier{
		user: db.User{
			ID:     pgtype.UUID{Bytes: u, Valid: true},
			Region: "eu",
			Status: "pending",
		},
	}
	store := NewDBStore(fake) // no pool → fallback path (activationQuerier assertion succeeds)

	cred := gowebauthn.Credential{ID: []byte("cred-raw-id"), PublicKey: []byte("pk")}
	if err := store.AddCredentialAndActivateUser(context.Background(), handleBytes(u), cred); err != nil {
		t.Fatalf("AddCredentialAndActivateUser: %v", err)
	}
	if fake.createdCred == nil {
		t.Fatal("expected credential to be created")
	}
	if fake.createdCred.Region != "eu" {
		t.Errorf("credential region = %q, want eu", fake.createdCred.Region)
	}
	if fake.statusSet == nil {
		t.Fatal("expected user status to be set")
	}
	if fake.statusSet.Status != "active" {
		t.Fatalf("status = %q, want active", fake.statusSet.Status)
	}
}

// TestDBStore_AddCredentialAndActivateUser_CreateFails verifies that a failed
// credential insert prevents activation — the user must NOT be flipped active
// when its passkey never persisted (atomicity, design decision 3).
func TestDBStore_AddCredentialAndActivateUser_CreateFails(t *testing.T) {
	u := uuid.New()
	fake := &activateFakeQuerier{
		user:      db.User{ID: pgtype.UUID{Bytes: u, Valid: true}, Region: "eu"},
		createErr: errors.New("insert failed"),
	}
	store := NewDBStore(fake)

	err := store.AddCredentialAndActivateUser(context.Background(), handleBytes(u), gowebauthn.Credential{ID: []byte("x")})
	if err == nil {
		t.Fatal("expected error when credential creation fails")
	}
	if fake.statusSet != nil {
		t.Fatal("user must not be activated when credential creation fails")
	}
}

func TestDBStore_AddCredentialAndActivateUser_UnknownUser(t *testing.T) {
	fake := &activateFakeQuerier{getUserErr: errors.New("no rows")}
	store := NewDBStore(fake)

	u := uuid.New()
	err := store.AddCredentialAndActivateUser(context.Background(), handleBytes(u), gowebauthn.Credential{ID: []byte("x")})
	if !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("err = %v, want ErrUserNotFound", err)
	}
	if fake.createdCred != nil {
		t.Fatal("no credential should be created for an unknown user")
	}
}

// TestInMemoryStore_AddCredentialAndActivateUser verifies the in-memory store's
// activation delegates to the credential add (no status column to flip).
func TestInMemoryStore_AddCredentialAndActivateUser(t *testing.T) {
	store := NewInMemoryStore()
	store.PutUser(NewUser([]byte("u"), "n", "d", nil))

	cred := gowebauthn.Credential{ID: []byte("c"), PublicKey: []byte("pk")}
	if err := store.AddCredentialAndActivateUser(context.Background(), []byte("u"), cred); err != nil {
		t.Fatalf("AddCredentialAndActivateUser: %v", err)
	}
	user, err := store.GetUser(context.Background(), []byte("u"))
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if len(user.WebAuthnCredentials()) != 1 {
		t.Fatalf("credentials = %d, want 1", len(user.WebAuthnCredentials()))
	}
}

// TestInMemoryStore_AddCredentialAndActivateUser_UnknownUser confirms the
// in-memory activation surfaces ErrUserNotFound for an unknown handle.
func TestInMemoryStore_AddCredentialAndActivateUser_UnknownUser(t *testing.T) {
	store := NewInMemoryStore()
	err := store.AddCredentialAndActivateUser(context.Background(), []byte("nobody"), gowebauthn.Credential{ID: []byte("c")})
	if !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("err = %v, want ErrUserNotFound", err)
	}
}
