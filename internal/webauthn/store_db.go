package webauthn

import (
	"context"
	"fmt"

	gowebauthn "github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
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

// txBeginner is satisfied by *pgxpool.Pool. It enables the atomic
// credential-create + user-activate path in AddCredentialAndActivateUser. A nil
// beginner disables the transaction (dev/test best-effort fallback).
type txBeginner interface {
	Begin(ctx context.Context) (pgx.Tx, error)
}

// activationQuerier is the sqlc surface the atomic activation path writes
// through. Both the production *db.Queries and a per-transaction db.New(tx)
// satisfy it, so the same logic runs inside or outside a transaction.
type activationQuerier interface {
	CreateCredential(ctx context.Context, arg db.CreateCredentialParams) (db.Credential, error)
	SetUserStatus(ctx context.Context, arg db.SetUserStatusParams) error
}

// DBStore implements Store backed by the sqlc queries over Postgres. It is
// safe for concurrent use (all state is in the database).
type DBStore struct {
	q  dbStoreQuerier
	tx txBeginner // nil → non-atomic best-effort fallback (dev/test without a pool)
}

// NewDBStore returns a DBStore backed by the given querier.
func NewDBStore(q dbStoreQuerier) *DBStore {
	return &DBStore{q: q}
}

// WithPool enables atomic first-passkey enrollment: AddCredentialAndActivateUser
// then runs the credential insert and the pending→active status flip inside a
// single transaction on the given pool (production wiring). Without a pool it
// falls back to a best-effort sequential path (dev/test). Returns s for chaining.
func (s *DBStore) WithPool(p txBeginner) *DBStore {
	s.tx = p
	return s
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
	_, err = s.q.CreateCredential(ctx, credentialParams(uid, row.Region, cred))
	return err
}

// AddCredentialAndActivateUser implements Store: it atomically persists the
// user's first passkey AND flips their status from "pending" to "active"
// (design decision 3, §11.1). When a pool is wired (WithPool) both writes run in
// a single transaction and roll back together on any failure, so enrollment can
// never leave a user "pending" with a credential, nor "active" with none.
func (s *DBStore) AddCredentialAndActivateUser(ctx context.Context, userID []byte, cred gowebauthn.Credential) error {
	uid, err := parseWebAuthnUserID(userID)
	if err != nil {
		return ErrUserNotFound
	}
	row, err := s.q.GetUser(ctx, uid)
	if err != nil {
		return ErrUserNotFound
	}

	// No pool: best-effort sequential fallback (dev/test). When the querier can
	// also set status we still activate; otherwise we only add the credential.
	if s.tx == nil {
		if act, ok := s.q.(activationQuerier); ok {
			return createCredentialAndActivate(ctx, act, uid, row.Region, cred)
		}
		_, err = s.q.CreateCredential(ctx, credentialParams(uid, row.Region, cred))
		return err
	}

	txn, err := s.tx.Begin(ctx)
	if err != nil {
		return fmt.Errorf("webauthn/store_db: begin activation tx: %w", err)
	}
	// Rollback is a no-op after Commit. WithoutCancel ensures the rollback still
	// runs if ctx was cancelled mid-flight, mirroring
	// clients.DBSessionStore.RotateSession.
	defer txn.Rollback(context.WithoutCancel(ctx)) //nolint:errcheck // best-effort rollback; no-op after commit.

	if err := createCredentialAndActivate(ctx, db.New(txn), uid, row.Region, cred); err != nil {
		return err
	}
	return txn.Commit(ctx)
}

// createCredentialAndActivate performs the two enrollment-completing writes
// against q: insert the passkey, then activate the user. Shared by the
// transactional and fallback paths so they cannot diverge.
func createCredentialAndActivate(ctx context.Context, q activationQuerier, uid pgtype.UUID, region string, cred gowebauthn.Credential) error {
	if _, err := q.CreateCredential(ctx, credentialParams(uid, region, cred)); err != nil {
		return fmt.Errorf("webauthn/store_db: create credential: %w", err)
	}
	if err := q.SetUserStatus(ctx, db.SetUserStatusParams{ID: uid, Status: "active"}); err != nil {
		return fmt.Errorf("webauthn/store_db: activate user: %w", err)
	}
	return nil
}

// credentialParams builds the sqlc params for inserting a passkey. The
// credential's own primary key is a fresh UUID; region is the user's own region.
func credentialParams(uid pgtype.UUID, region string, cred gowebauthn.Credential) db.CreateCredentialParams {
	return db.CreateCredentialParams{
		ID:             pgtype.UUID{Bytes: uuid.New(), Valid: true},
		Region:         region,
		UserID:         uid,
		Type:           "passkey",
		WebauthnCredID: cred.ID,
		WebauthnPubkey: cred.PublicKey,
		WebauthnAaguid: cred.Authenticator.AAGUID,
		SignCount:      int64(cred.Authenticator.SignCount),
	}
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
