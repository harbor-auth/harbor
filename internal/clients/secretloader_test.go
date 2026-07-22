package clients

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/harbor-auth/harbor/internal/crypto"
	"github.com/harbor-auth/harbor/internal/gen/db"
	"github.com/harbor-auth/harbor/internal/identity"
	"github.com/harbor-auth/harbor/internal/oidc"
)

const (
	testKMSSecret      = "test-kms-secret-for-secretloader"
	secretLoaderUserID = "00000000-0000-0000-0000-000000000001"
	testRegion         = "us"
)

// fakeSecretQuerier is an in-memory secretLoaderQuerier for tests.
type fakeSecretQuerier struct {
	users map[pgtype.UUID]db.User
}

func (f *fakeSecretQuerier) GetUser(_ context.Context, id pgtype.UUID) (db.User, error) {
	u, ok := f.users[id]
	if !ok {
		return db.User{}, pgx.ErrNoRows
	}
	return u, nil
}

// buildEncryptedUser produces a db.User with a real wrapped DEK and a real
// encrypted pairwise secret, using the given KMS secret and region. It returns
// the row and the raw plaintext secret so tests can assert round-tripping.
func buildEncryptedUser(t *testing.T, kmsSecret, region, userID string) (db.User, []byte) {
	t.Helper()
	kp, err := crypto.NewLocalKeyProvider(kmsSecret)
	if err != nil {
		t.Fatalf("NewLocalKeyProvider: %v", err)
	}
	cipher := crypto.NewCipher()

	dek, err := crypto.GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK: %v", err)
	}
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i + 7)
	}

	wrapped, err := kp.WrapDEK(context.Background(), region, dek)
	if err != nil {
		t.Fatalf("WrapDEK: %v", err)
	}
	enc, err := cipher.Encrypt(dek, raw, identity.PairwiseSecretAAD(userID))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	var id pgtype.UUID
	if err := id.Scan(userID); err != nil {
		t.Fatalf("scan uuid: %v", err)
	}
	return db.User{
		ID:             id,
		Region:         region,
		Status:         "active",
		DekWrapped:     wrapped,
		PairwiseSecret: enc,
	}, raw
}

func newLoader(t *testing.T, kmsSecret string, users ...db.User) *DBSecretLoader {
	t.Helper()
	kp, err := crypto.NewLocalKeyProvider(kmsSecret)
	if err != nil {
		t.Fatalf("NewLocalKeyProvider: %v", err)
	}
	q := &fakeSecretQuerier{users: make(map[pgtype.UUID]db.User)}
	for _, u := range users {
		q.users[u.ID] = u
	}
	return NewDBSecretLoader(q, kp, crypto.NewCipher())
}

func TestDBSecretLoaderHappyPath(t *testing.T) {
	user, raw := buildEncryptedUser(t, testKMSSecret, testRegion, secretLoaderUserID)
	loader := newLoader(t, testKMSSecret, user)

	us, err := loader.LoadUserSecret(context.Background(), secretLoaderUserID)
	if err != nil {
		t.Fatalf("LoadUserSecret: %v", err)
	}
	if us.Region != testRegion {
		t.Fatalf("region = %q, want %q", us.Region, testRegion)
	}
	if len(us.Secret) != len(raw) {
		t.Fatalf("secret len = %d, want %d", len(us.Secret), len(raw))
	}
	for i := range raw {
		if us.Secret[i] != raw[i] {
			t.Fatalf("secret mismatch at byte %d", i)
		}
	}
}

func TestDBSecretLoaderUnknownUser(t *testing.T) {
	loader := newLoader(t, testKMSSecret) // no users

	_, err := loader.LoadUserSecret(context.Background(), secretLoaderUserID)
	if !errors.Is(err, oidc.ErrUserSecretNotFound) {
		t.Fatalf("expected ErrUserSecretNotFound, got %v", err)
	}
}

func TestDBSecretLoaderDEKFailure(t *testing.T) {
	// Encrypt under one KMS secret, but load with a different one so the DEK
	// unwrap fails GCM authentication.
	user, _ := buildEncryptedUser(t, testKMSSecret, testRegion, secretLoaderUserID)
	loader := newLoader(t, "a-completely-different-kms-secret", user)

	_, err := loader.LoadUserSecret(context.Background(), secretLoaderUserID)
	if err == nil {
		t.Fatal("expected error on DEK unwrap failure")
	}
	if errors.Is(err, oidc.ErrUserSecretNotFound) {
		t.Fatalf("DEK failure must not be reported as not-found: %v", err)
	}
}

func TestDBSecretLoaderDecryptFailure(t *testing.T) {
	user, _ := buildEncryptedUser(t, testKMSSecret, testRegion, secretLoaderUserID)
	// Tamper with the ciphertext so GCM authentication fails.
	if len(user.PairwiseSecret) == 0 {
		t.Fatal("empty pairwise secret")
	}
	user.PairwiseSecret[len(user.PairwiseSecret)-1] ^= 0xFF
	loader := newLoader(t, testKMSSecret, user)

	_, err := loader.LoadUserSecret(context.Background(), secretLoaderUserID)
	if err == nil {
		t.Fatal("expected error on decrypt failure")
	}
}
