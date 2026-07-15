package clients

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	db "github.com/harbor/harbor/internal/gen/db"
)

// SigningKey represents a signing key in the key rotation lifecycle.
// Keys progress through states: pending → active → retired.
type SigningKey struct {
	ID                string    // UUID primary key
	Kid               string    // key identifier in JWKS
	State             string    // "pending" | "active" | "retired"
	PublicKeyBytes    []byte    // DER-encoded ECDSA P-256 public key
	PrivateKeyWrapped []byte    // envelope-encrypted private key
	Region            string    // data sovereignty jurisdiction
	CreatedAt         time.Time
	PromotedAt        *time.Time // when state changed to 'active'
	RetiredAt         *time.Time // when state changed to 'retired'
}

// NewSigningKey is the input for creating a new signing key.
type NewSigningKey struct {
	ID                string
	Kid               string
	PublicKeyBytes    []byte
	PrivateKeyWrapped []byte
	Region            string
}

// ErrSigningKeyNotFound is returned when a signing key lookup finds no rows.
var ErrSigningKeyNotFound = errors.New("signing key not found")

// SigningKeyStore persists and retrieves signing keys for JWKS kid rotation
// (DESIGN §7.3, §3.5.4). Implementations must be safe for concurrent use.
type SigningKeyStore interface {
	// Create inserts a new signing key in 'pending' state.
	Create(ctx context.Context, key NewSigningKey) (SigningKey, error)

	// GetByKid retrieves a signing key by its kid. Returns ErrSigningKeyNotFound
	// if no key exists with that kid.
	GetByKid(ctx context.Context, kid string) (SigningKey, error)

	// GetActive returns the single active signing key used for signing new
	// tokens. Returns ErrSigningKeyNotFound if no active key exists.
	GetActive(ctx context.Context) (SigningKey, error)

	// ListLive returns all keys that should appear in the JWKS endpoint:
	// pending (new keys awaiting promotion) and active (the current signer).
	ListLive(ctx context.Context) ([]SigningKey, error)

	// SetState updates a key's state and timestamps. The caller must provide
	// the appropriate timestamps for the target state (promoted_at for active,
	// retired_at for retired).
	SetState(ctx context.Context, id string, state string, promotedAt, retiredAt *time.Time) (SigningKey, error)

	// Retire marks a key as retired by kid. Used during scheduled rotation
	// (after overlap window) or emergency rotation (immediate).
	Retire(ctx context.Context, kid string) (SigningKey, error)
}

// signingKeyQuerier is the narrow sqlc surface DBSigningKeyStore needs.
type signingKeyQuerier interface {
	CreateSigningKey(ctx context.Context, arg db.CreateSigningKeyParams) (db.SigningKey, error)
	GetSigningKeyByKid(ctx context.Context, kid string) (db.SigningKey, error)
	GetActiveSigningKey(ctx context.Context) (db.SigningKey, error)
	ListLiveSigningKeys(ctx context.Context) ([]db.SigningKey, error)
	UpdateSigningKeyState(ctx context.Context, arg db.UpdateSigningKeyStateParams) (db.SigningKey, error)
	RetireSigningKey(ctx context.Context, kid string) (db.SigningKey, error)
}

// DBSigningKeyStore implements SigningKeyStore over the signing_keys table
// (docs/DESIGN.md §7.3). Each method converts domain types to/from sqlc types.
type DBSigningKeyStore struct {
	q signingKeyQuerier
}

// Compile-time proof that DBSigningKeyStore implements SigningKeyStore.
var _ SigningKeyStore = (*DBSigningKeyStore)(nil)

// NewDBSigningKeyStore wraps a sqlc Queries (or any signingKeyQuerier).
func NewDBSigningKeyStore(q signingKeyQuerier) *DBSigningKeyStore {
	return &DBSigningKeyStore{q: q}
}

// Create implements SigningKeyStore.
func (s *DBSigningKeyStore) Create(ctx context.Context, key NewSigningKey) (SigningKey, error) {
	var id pgtype.UUID
	if err := id.Scan(key.ID); err != nil {
		return SigningKey{}, fmt.Errorf("signingkeys: invalid ID %q: %w", key.ID, err)
	}
	row, err := s.q.CreateSigningKey(ctx, db.CreateSigningKeyParams{
		ID:                id,
		Kid:               key.Kid,
		PublicKeyBytes:    key.PublicKeyBytes,
		PrivateKeyWrapped: key.PrivateKeyWrapped,
		Region:            key.Region,
	})
	if err != nil {
		return SigningKey{}, fmt.Errorf("signingkeys: create: %w", err)
	}
	return rowToSigningKey(row), nil
}

// GetByKid implements SigningKeyStore.
func (s *DBSigningKeyStore) GetByKid(ctx context.Context, kid string) (SigningKey, error) {
	row, err := s.q.GetSigningKeyByKid(ctx, kid)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return SigningKey{}, ErrSigningKeyNotFound
		}
		return SigningKey{}, fmt.Errorf("signingkeys: get by kid %q: %w", kid, err)
	}
	return rowToSigningKey(row), nil
}

// GetActive implements SigningKeyStore.
func (s *DBSigningKeyStore) GetActive(ctx context.Context) (SigningKey, error) {
	row, err := s.q.GetActiveSigningKey(ctx)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return SigningKey{}, ErrSigningKeyNotFound
		}
		return SigningKey{}, fmt.Errorf("signingkeys: get active: %w", err)
	}
	return rowToSigningKey(row), nil
}

// ListLive implements SigningKeyStore.
func (s *DBSigningKeyStore) ListLive(ctx context.Context) ([]SigningKey, error) {
	rows, err := s.q.ListLiveSigningKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("signingkeys: list live: %w", err)
	}
	out := make([]SigningKey, len(rows))
	for i, r := range rows {
		out[i] = rowToSigningKey(r)
	}
	return out, nil
}

// SetState implements SigningKeyStore.
func (s *DBSigningKeyStore) SetState(ctx context.Context, id string, state string, promotedAt, retiredAt *time.Time) (SigningKey, error) {
	var uid pgtype.UUID
	if err := uid.Scan(id); err != nil {
		return SigningKey{}, fmt.Errorf("signingkeys: invalid ID %q: %w", id, err)
	}
	var promotedAtPg, retiredAtPg pgtype.Timestamptz
	if promotedAt != nil {
		promotedAtPg = pgtype.Timestamptz{Time: *promotedAt, Valid: true}
	}
	if retiredAt != nil {
		retiredAtPg = pgtype.Timestamptz{Time: *retiredAt, Valid: true}
	}
	row, err := s.q.UpdateSigningKeyState(ctx, db.UpdateSigningKeyStateParams{
		ID:         uid,
		State:      state,
		PromotedAt: promotedAtPg,
		RetiredAt:  retiredAtPg,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return SigningKey{}, ErrSigningKeyNotFound
		}
		return SigningKey{}, fmt.Errorf("signingkeys: set state: %w", err)
	}
	return rowToSigningKey(row), nil
}

// Retire implements SigningKeyStore.
func (s *DBSigningKeyStore) Retire(ctx context.Context, kid string) (SigningKey, error) {
	row, err := s.q.RetireSigningKey(ctx, kid)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return SigningKey{}, ErrSigningKeyNotFound
		}
		return SigningKey{}, fmt.Errorf("signingkeys: retire kid %q: %w", kid, err)
	}
	return rowToSigningKey(row), nil
}

// rowToSigningKey converts a sqlc SigningKey row to the domain type.
func rowToSigningKey(row db.SigningKey) SigningKey {
	return SigningKey{
		ID:                uuidToString(row.ID),
		Kid:               row.Kid,
		State:             row.State,
		PublicKeyBytes:    row.PublicKeyBytes,
		PrivateKeyWrapped: row.PrivateKeyWrapped,
		Region:            row.Region,
		CreatedAt:         row.CreatedAt.Time,
		PromotedAt:        timePtrFromPgtz(row.PromotedAt),
		RetiredAt:         timePtrFromPgtz(row.RetiredAt),
	}
}
