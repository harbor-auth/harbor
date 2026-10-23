package clients

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/harbor-auth/harbor/internal/crypto"
	"github.com/harbor-auth/harbor/internal/gen/db"
	"github.com/harbor-auth/harbor/internal/identity"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

type DBIdentifierStore struct {
	pool   *pgxpool.Pool
	q      *db.Queries
	keys   crypto.KeyProvider
	cipher crypto.Decryptor
}

func NewDBIdentifierStore(pool *pgxpool.Pool, keys crypto.KeyProvider, cipher crypto.Decryptor) *DBIdentifierStore {
	return &DBIdentifierStore{pool, db.New(pool), keys, cipher}
}

func (s *DBIdentifierStore) PersistIdentifiedUser(ctx context.Context, user identity.UserRecord, identifier identity.IdentifierRecord) (resultErr error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() {
		if err := tx.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			resultErr = errors.Join(resultErr, err)
		}
	}()
	q := db.New(tx)
	// Lock existing accounts before considering cleanup. Credential activation
	// also updates the user row, serializing cleanup against first registration.
	old, err := q.FindAccountIdentifier(ctx, db.FindAccountIdentifierParams{Region: user.Region, Kind: identifier.Kind, LookupHash: identifier.LookupHash})
	if err == nil {
		n, err := q.DeleteExpiredPendingSignup(ctx, old.ID)
		if err != nil {
			return err
		}
		if n == 0 {
			return identity.ErrIdentifierExists
		}
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if err := NewDBUserPersister(q).PersistUser(ctx, user); err != nil {
		return err
	}
	id := uuid.MustParse(user.ID)
	err = q.CreateAccountIdentifier(ctx, db.CreateAccountIdentifierParams{
		UserID: pgtype.UUID{Bytes: id, Valid: true}, Region: user.Region, Kind: identifier.Kind,
		LookupHash: identifier.LookupHash, EncryptedValue: identifier.EncryptedValue,
	})
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return identity.ErrIdentifierExists
	}
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// AccountLabel decrypts the verified email only for Harbor's credential UI.
// Empty means a federated account with no email; errors fail closed.
func (s *DBIdentifierStore) AccountLabel(ctx context.Context, userID string) (string, error) {
	id, err := uuid.Parse(userID)
	if err != nil {
		return "", err
	}
	uid := pgtype.UUID{Bytes: id, Valid: true}
	entries, err := s.q.ListAccountIdentifiers(ctx, uid)
	if err != nil {
		return "", err
	}
	for _, entry := range entries {
		if entry.Kind != "email" {
			continue
		}
		user, err := s.q.GetUser(ctx, uid)
		if err != nil {
			return "", err
		}
		dek, err := s.keys.UnwrapDEK(ctx, user.Region, user.DekWrapped)
		if err != nil {
			return "", err
		}
		value, err := s.cipher.Decrypt(dek, entry.EncryptedValue, identity.IdentifierAAD(userID, entry.Kind))
		return string(value), err
	}
	return "", nil
}
