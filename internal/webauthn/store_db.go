package webauthn

import (
	"context"
	"fmt"

	gowebauthn "github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	db "github.com/harbor/harbor/internal/gen/db"
)

// dbStoreQuerier is a narrow interface over the sqlc Querier covering only the
// methods DBStore uses. Accepting an interface (not *db.Queries) lets tests
// inject a fake without a real Postgres connection.
type dbStoreQuerier interface {
	GetUser(ctx context.Context, id pgtype.UUID) (db.User, error)
	ListCredentialsByUser(ctx context.Context, userID pgtype.UUID) ([]db.Credential, error)
	CreateCredential(ctx context.Context, arg db.CreateCredentialParams) (db.Credential, error)
	GetCredentialByWebAuthnCredID(ctx context.Context, webauthnCredID []byte) (db.Credential, error)
	UpdateCredentialSignCount(ctx context.Context, arg db.UpdateCredentialSignCountParams) error
}

// DBStore implements Store backed by the sqlc queries over Postgres. It is
// safe for concurrent use (all state is in the database).
type DBStore struct {
	q dbStoreQuerier
}

// NewDBStore returns a DBStore backed by the given querier.
func NewDBStore(q dbStoreQuerier) *DBStore {
	return &DBStore{q: q}
}

// GetUser implements Store: fetches the user row and all their passkeys, then
// assembles a webauthn.User ready for ceremony functions.
func (s *DBStore) GetUser(ctx context.Context, userID []byte) (User, error) {
	uid, err := parseWebAuthnUserID(userID)
	if err != nil {
		return User{}, ErrUserNotFound
	}
	if _, err = s.q.GetUser(ctx, uid); err != nil {
		return User{}, ErrUserNotFound
	}
	creds, err := s.q.ListCredentialsByUser(ctx, uid)
	if err != nil {
		return User{}, fmt.Errorf("webauthn/store_db: list credentials: %w", err)
	}
	goCreds := make([]gowebauthn.Credential, 0, len(creds))
	for _, c := range creds {
		goCreds = append(goCreds, rowToGoCredential(c))
	}
	// name and displayName are display-only; Harbor stores no profile PII in the
	// users table, so the opaque user ID string serves as both.
	uidStr := string(userID)
	return NewUser(userID, uidStr, uidStr, goCreds), nil
}

// AddCredential implements Store: persists a newly-registered passkey.
// The region is read from the user's own row to keep it consistent.
func (s *DBStore) AddCredential(ctx context.Context, userID []byte, cred gowebauthn.Credential) error {
	uid, err := parseWebAuthnUserID(userID)
	if err != nil {
		return ErrUserNotFound
	}
	row, err := s.q.GetUser(ctx, uid)
	if err != nil {
		return ErrUserNotFound
	}
	credID := uuid.New()
	_, err = s.q.CreateCredential(ctx, db.CreateCredentialParams{
		ID:             pgtype.UUID{Bytes: credID, Valid: true},
		Region:         row.Region,
		UserID:         uid,
		Type:           "passkey",
		WebauthnCredID: cred.ID,
		WebauthnPubkey: cred.PublicKey,
		WebauthnAaguid: cred.Authenticator.AAGUID,
		SignCount:      int64(cred.Authenticator.SignCount),
	})
	return err
}

// UpdateCredential implements Store: advances the signature counter for an
// existing passkey. Monotonicity is enforced: a non-increasing counter (except
// from 0) is a clone signal and is refused (docs/DESIGN.md §3.1).
func (s *DBStore) UpdateCredential(ctx context.Context, userID []byte, cred gowebauthn.Credential) error {
	uid, err := parseWebAuthnUserID(userID)
	if err != nil {
		return ErrUserNotFound
	}
	row, err := s.q.GetCredentialByWebAuthnCredID(ctx, cred.ID)
	if err != nil {
		return ErrUserNotFound
	}
	// Cross-user guard: the credential must belong to the asserted user.
	if row.UserID.Bytes != uid.Bytes {
		return ErrUserNotFound
	}
	old := uint32(row.SignCount)
	newCount := cred.Authenticator.SignCount
	if old != 0 && newCount <= old {
		return ErrSignCountRegression
	}
	return s.q.UpdateCredentialSignCount(ctx, db.UpdateCredentialSignCountParams{
		ID:        row.ID,
		SignCount: int64(newCount),
	})
}

// rowToGoCredential maps a sqlc Credential row to a go-webauthn Credential.
func rowToGoCredential(row db.Credential) gowebauthn.Credential {
	c := gowebauthn.Credential{
		ID:        row.WebauthnCredID,
		PublicKey: row.WebauthnPubkey,
	}
	c.Authenticator.AAGUID = row.WebauthnAaguid
	c.Authenticator.SignCount = uint32(row.SignCount)
	return c
}

// parseWebAuthnUserID parses a WebAuthn user handle (UUID string in bytes) into
// a pgtype.UUID. Harbor's WebAuthn user handles are UUID strings
// (e.g. "550e8400-e29b-41d4-a716-446655440000").
func parseWebAuthnUserID(userID []byte) (pgtype.UUID, error) {
	id, err := uuid.ParseBytes(userID)
	if err != nil {
		return pgtype.UUID{}, fmt.Errorf("webauthn/store_db: invalid user handle: %w", err)
	}
	return pgtype.UUID{Bytes: id, Valid: true}, nil
}

// Compile-time assertion: DBStore implements Store.
var _ Store = (*DBStore)(nil)
