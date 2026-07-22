package relay

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/harbor-auth/harbor/internal/crypto"
	db "github.com/harbor-auth/harbor/internal/gen/db"
	"github.com/harbor-auth/harbor/internal/region"
)

// Store errors.
var (
	// ErrRelayAddressNotFound is returned when a relay address lookup fails.
	ErrRelayAddressNotFound = errors.New("relay: address not found")
	// ErrRelayAddressExists is returned when trying to create a duplicate relay address.
	ErrRelayAddressExists = errors.New("relay: address already exists for this user and client")
	// ErrDecryptionFailed is returned when the encrypted mapping cannot be decrypted.
	ErrDecryptionFailed = errors.New("relay: failed to decrypt mapping")
	// ErrEncryptionFailed is returned when the mapping cannot be encrypted.
	ErrEncryptionFailed = errors.New("relay: failed to encrypt mapping")
)

// relayQuerier is the narrow sqlc surface Store needs. Using a subset keeps
// this file testable with a fake and documents exactly which generated queries
// the relay store depends on.
type relayQuerier interface {
	CreateRelayAddress(ctx context.Context, arg db.CreateRelayAddressParams) (db.RelayAddress, error)
	GetRelayAddressByToken(ctx context.Context, relayToken string) (db.RelayAddress, error)
	GetActiveRelayAddressByToken(ctx context.Context, relayToken string) (db.RelayAddress, error)
	GetRelayAddressByUserClient(ctx context.Context, arg db.GetRelayAddressByUserClientParams) (db.RelayAddress, error)
	ListRelayAddressesByUser(ctx context.Context, userID pgtype.UUID) ([]db.RelayAddress, error)
	DeactivateRelayAddress(ctx context.Context, id pgtype.UUID) error
	DeactivateRelayAddressByUserClient(ctx context.Context, arg db.DeactivateRelayAddressByUserClientParams) error
	ReactivateRelayAddress(ctx context.Context, id pgtype.UUID) error
	SetRelayAddressBYODomain(ctx context.Context, id pgtype.UUID) error
}

// Store implements relay address operations with envelope encryption for the
// mapping (real email address). All operations are region-pinned: the encrypted
// mapping is stored in the user's home region and never cross-region replicated.
type Store struct {
	q      relayQuerier
	cipher *crypto.Cipher
}

// NewStore creates a new relay Store with the given sqlc queries and cipher for
// envelope encryption. The caller is responsible for obtaining the user's DEK
// (via KeyProvider.UnwrapDEK) before calling methods that require encryption.
func NewStore(q relayQuerier, cipher *crypto.Cipher) *Store {
	return &Store{
		q:      q,
		cipher: cipher,
	}
}

// encryptMapping encrypts the real email address using the user's DEK.
// The region is bound to the encryption as AAD, ensuring the encrypted blob
// cannot be decrypted in a different region.
func (s *Store) encryptMapping(realEmail string, reg region.Region, dek crypto.DEK) ([]byte, error) {
	// Use region as AAD to bind the ciphertext to the user's home region.
	aad := []byte("relay-mapping-v1:" + string(reg))
	encrypted, err := s.cipher.Encrypt(dek, []byte(realEmail), aad)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEncryptionFailed, err)
	}
	return encrypted, nil
}

// decryptMapping decrypts the encrypted mapping using the user's DEK.
// The region must match the region used during encryption.
func (s *Store) decryptMapping(encMapping []byte, reg region.Region, dek crypto.DEK) (string, error) {
	aad := []byte("relay-mapping-v1:" + string(reg))
	plaintext, err := s.cipher.Decrypt(dek, encMapping, aad)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}
	return string(plaintext), nil
}

// CreateParams holds the parameters for creating a new relay address.
type CreateParams struct {
	// Token is the opaque, unlinkable relay token.
	Token string
	// UserID is the user this relay address belongs to.
	UserID string
	// ClientID is the RP this relay address is scoped to.
	ClientID string
	// RealEmail is the user's actual email address (will be encrypted).
	RealEmail string
	// Region is the user's home region.
	Region region.Region
	// DEK is the user's data encryption key for envelope encryption.
	DEK crypto.DEK
}

// Create mints a new relay address with the given parameters. The real email
// is envelope-encrypted before storage. Returns ErrRelayAddressExists if a
// relay address already exists for this (user, client) pair.
func (s *Store) Create(ctx context.Context, params CreateParams) (*Address, error) {
	// Encrypt the real email mapping
	encMapping, err := s.encryptMapping(params.RealEmail, params.Region, params.DEK)
	if err != nil {
		return nil, err
	}

	var userID pgtype.UUID
	if err := userID.Scan(params.UserID); err != nil {
		return nil, fmt.Errorf("relay: parse user ID %q: %w", params.UserID, err)
	}

	row, err := s.q.CreateRelayAddress(ctx, db.CreateRelayAddressParams{
		RelayToken: params.Token,
		UserID:     userID,
		ClientID:   params.ClientID,
		State:      string(StateActive),
		EncMapping: encMapping,
		Region:     string(params.Region),
	})
	if err != nil {
		// Check for unique constraint violation (duplicate user+client)
		if isDuplicateKeyError(err) {
			return nil, ErrRelayAddressExists
		}
		return nil, fmt.Errorf("relay: create address: %w", err)
	}

	return rowToAddress(row), nil
}

// GetByToken retrieves a relay address by its token. Returns the address with
// the encrypted mapping (caller must decrypt with user's DEK).
// Returns ErrRelayAddressNotFound if the token doesn't exist.
func (s *Store) GetByToken(ctx context.Context, token string) (*Address, []byte, error) {
	row, err := s.q.GetRelayAddressByToken(ctx, token)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil, ErrRelayAddressNotFound
		}
		return nil, nil, fmt.Errorf("relay: get by token: %w", err)
	}
	return rowToAddress(row), row.EncMapping, nil
}

// GetActiveByToken retrieves an active relay address by its token. Used by
// the inbound MTA to reject mail to deactivated addresses (hard-bounce).
// Returns ErrRelayAddressNotFound if the token doesn't exist or is not active.
func (s *Store) GetActiveByToken(ctx context.Context, token string) (*Address, []byte, error) {
	row, err := s.q.GetActiveRelayAddressByToken(ctx, token)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil, ErrRelayAddressNotFound
		}
		return nil, nil, fmt.Errorf("relay: get active by token: %w", err)
	}
	return rowToAddress(row), row.EncMapping, nil
}

// GetByUserClient retrieves a relay address by user and client ID pair.
// Used to check if a relay address already exists before minting a new one.
// Returns ErrRelayAddressNotFound if no address exists for this pair.
func (s *Store) GetByUserClient(ctx context.Context, userID, clientID string) (*Address, []byte, error) {
	var uid pgtype.UUID
	if err := uid.Scan(userID); err != nil {
		return nil, nil, fmt.Errorf("relay: parse user ID %q: %w", userID, err)
	}

	row, err := s.q.GetRelayAddressByUserClient(ctx, db.GetRelayAddressByUserClientParams{
		UserID:   uid,
		ClientID: clientID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil, ErrRelayAddressNotFound
		}
		return nil, nil, fmt.Errorf("relay: get by user client: %w", err)
	}
	return rowToAddress(row), row.EncMapping, nil
}

// ListByUser returns all relay addresses for a user, ordered by most recent first.
// The encrypted mappings are included for the caller to decrypt as needed.
func (s *Store) ListByUser(ctx context.Context, userID string) ([]*Address, [][]byte, error) {
	var uid pgtype.UUID
	if err := uid.Scan(userID); err != nil {
		return nil, nil, fmt.Errorf("relay: parse user ID %q: %w", userID, err)
	}

	rows, err := s.q.ListRelayAddressesByUser(ctx, uid)
	if err != nil {
		return nil, nil, fmt.Errorf("relay: list by user: %w", err)
	}

	addresses := make([]*Address, len(rows))
	mappings := make([][]byte, len(rows))
	for i, row := range rows {
		addresses[i] = rowToAddress(row)
		mappings[i] = row.EncMapping
	}
	return addresses, mappings, nil
}

// Deactivate sets a relay address to the deactivated state (hard-bounce kill switch).
// Deactivation is independent of login grant revocation (§7.5.4).
func (s *Store) Deactivate(ctx context.Context, addressID string) error {
	var id pgtype.UUID
	if err := id.Scan(addressID); err != nil {
		return fmt.Errorf("relay: parse address ID %q: %w", addressID, err)
	}
	return s.q.DeactivateRelayAddress(ctx, id)
}

// DeactivateByUserClient deactivates a relay address by user and client ID.
// Convenience method when the caller has the user/client but not the address ID.
func (s *Store) DeactivateByUserClient(ctx context.Context, userID, clientID string) error {
	var uid pgtype.UUID
	if err := uid.Scan(userID); err != nil {
		return fmt.Errorf("relay: parse user ID %q: %w", userID, err)
	}
	return s.q.DeactivateRelayAddressByUserClient(ctx, db.DeactivateRelayAddressByUserClientParams{
		UserID:   uid,
		ClientID: clientID,
	})
}

// Reactivate restores a previously deactivated relay address to the active state.
func (s *Store) Reactivate(ctx context.Context, addressID string) error {
	var id pgtype.UUID
	if err := id.Scan(addressID); err != nil {
		return fmt.Errorf("relay: parse address ID %q: %w", addressID, err)
	}
	return s.q.ReactivateRelayAddress(ctx, id)
}

// SetBYODomain transitions a relay address to the BYO-domain state after the
// user has verified ownership of their custom domain.
func (s *Store) SetBYODomain(ctx context.Context, addressID string) error {
	var id pgtype.UUID
	if err := id.Scan(addressID); err != nil {
		return fmt.Errorf("relay: parse address ID %q: %w", addressID, err)
	}
	return s.q.SetRelayAddressBYODomain(ctx, id)
}

// DecryptMapping is a convenience method to decrypt an encrypted mapping using
// the user's DEK. The region must match the region used during encryption.
func (s *Store) DecryptMapping(encMapping []byte, reg region.Region, dek crypto.DEK) (string, error) {
	return s.decryptMapping(encMapping, reg, dek)
}

// rowToAddress converts a sqlc RelayAddress row to the domain Address type.
func rowToAddress(row db.RelayAddress) *Address {
	addr := &Address{
		Token:    row.RelayToken,
		UserID:   uuidFromPgtype(row.UserID),
		ClientID: row.ClientID,
		Region:   region.Region(row.Region),
	}

	// Parse the UUID ID
	if row.ID.Valid {
		addr.ID = uuidFromPgtype(row.ID)
	}

	// Parse state
	if state, err := ParseState(row.State); err == nil {
		addr.State = state
	} else {
		addr.State = StateActive // default fallback
	}

	// Parse timestamps
	if row.CreatedAt.Valid {
		addr.CreatedAt = row.CreatedAt.Time
	}
	if row.DeactivatedAt.Valid {
		t := row.DeactivatedAt.Time
		addr.DeactivatedAt = &t
	}

	return addr
}

// uuidFromPgtype converts a pgtype.UUID to a github.com/google/uuid.UUID.
func uuidFromPgtype(u pgtype.UUID) [16]byte {
	if !u.Valid {
		return [16]byte{}
	}
	return u.Bytes
}

// isDuplicateKeyError checks if an error is a PostgreSQL unique constraint violation.
func isDuplicateKeyError(err error) bool {
	if err == nil {
		return false
	}
	// pgx wraps PostgreSQL errors; check for unique_violation (23505)
	errStr := err.Error()
	return strings.Contains(errStr, "23505") ||
		strings.Contains(errStr, "unique constraint") ||
		strings.Contains(errStr, "duplicate key")
}
