package crypto

import (
	"context"
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// DBRotationStore implements RotationStore by delegating to a signing key store.
// It bridges the crypto domain types (NewKeyMaterial, JWK) to the persistence layer
// so the crypto package stays free of DB imports.
//
// The adapter:
//   - Converts NewKeyMaterial.PublicJWK to DER-encoded public key bytes
//   - Generates a UUID for new keys
//   - Delegates all persistence to the provided store functions
//
// DBRotationStore is safe for concurrent use if the underlying store is.
type DBRotationStore struct {
	// Store function implementations - these are injected by the caller
	// to avoid import cycles with internal/clients.
	createKey    func(ctx context.Context, id, kid, region string, publicKeyBytes, privateKeyWrapped []byte) error
	getActiveKid func(ctx context.Context) (string, error)
	promoteKey   func(ctx context.Context, kid string, promotedAt time.Time) error
	retireKey    func(ctx context.Context, kid string) error

	generateID func() string
}

// Compile-time proof that DBRotationStore implements RotationStore.
var _ RotationStore = (*DBRotationStore)(nil)

// DBRotationStoreConfig holds the store function implementations.
type DBRotationStoreConfig struct {
	// CreateKey persists a new signing key in pending state.
	// Parameters: id (UUID), kid (key identifier), region, publicKeyBytes (DER), privateKeyWrapped.
	CreateKey func(ctx context.Context, id, kid, region string, publicKeyBytes, privateKeyWrapped []byte) error

	// GetActiveKid returns the kid of the current active signing key, or "" if none.
	GetActiveKid func(ctx context.Context) (string, error)

	// PromoteKey transitions the key with the given kid to active state.
	PromoteKey func(ctx context.Context, kid string, promotedAt time.Time) error

	// RetireKey transitions the key with the given kid to retired state.
	RetireKey func(ctx context.Context, kid string) error
}

// NewDBRotationStore constructs a DBRotationStore with the given store functions.
// This functional injection pattern avoids import cycles: internal/clients creates
// the config by wrapping its SigningKeyStore methods.
func NewDBRotationStore(cfg DBRotationStoreConfig) *DBRotationStore {
	return &DBRotationStore{
		createKey:    cfg.CreateKey,
		getActiveKid: cfg.GetActiveKid,
		promoteKey:   cfg.PromoteKey,
		retireKey:    cfg.RetireKey,
		generateID:   func() string { return uuid.New().String() },
	}
}

// WithIDGenerator sets a custom ID generator (for deterministic tests).
func (s *DBRotationStore) WithIDGenerator(gen func() string) *DBRotationStore {
	s.generateID = gen
	return s
}

// Create implements RotationStore. It converts the NewKeyMaterial to store
// parameters and delegates to the underlying store.
func (s *DBRotationStore) Create(ctx context.Context, key NewKeyMaterial) error {
	// Convert JWK to DER-encoded public key bytes.
	pubKeyBytes, err := jwkToPublicKeyDER(key.PublicJWK)
	if err != nil {
		return fmt.Errorf("crypto: DBRotationStore.Create: %w", err)
	}

	// Create the signing key in the store (pending state).
	id := s.generateID()
	if err := s.createKey(ctx, id, key.Kid, key.Region, pubKeyBytes, nil); err != nil {
		return fmt.Errorf("crypto: DBRotationStore.Create: %w", err)
	}

	return nil
}

// CreateWithWrappedKey creates a signing key with the pre-wrapped private key bytes.
// This is the preferred method when using KMSBackedSigner, which provides the
// wrapped private key at creation time.
func (s *DBRotationStore) CreateWithWrappedKey(ctx context.Context, key NewKeyMaterial, wrappedPrivateKey []byte) error {
	// Convert JWK to DER-encoded public key bytes.
	pubKeyBytes, err := jwkToPublicKeyDER(key.PublicJWK)
	if err != nil {
		return fmt.Errorf("crypto: DBRotationStore.CreateWithWrappedKey: %w", err)
	}

	// Create the signing key in the store (pending state).
	id := s.generateID()
	if err := s.createKey(ctx, id, key.Kid, key.Region, pubKeyBytes, wrappedPrivateKey); err != nil {
		return fmt.Errorf("crypto: DBRotationStore.CreateWithWrappedKey: %w", err)
	}

	return nil
}

// ActiveKid implements RotationStore. It returns the kid of the current active
// key, or "" if there is no active key.
func (s *DBRotationStore) ActiveKid(ctx context.Context) (string, error) {
	kid, err := s.getActiveKid(ctx)
	if err != nil {
		// Check if no active key exists (not an error, just empty result).
		if isNotFoundError(err) {
			return "", nil
		}
		return "", fmt.Errorf("crypto: DBRotationStore.ActiveKid: %w", err)
	}
	return kid, nil
}

// Promote implements RotationStore. It transitions the pending key with the
// given kid to active state.
func (s *DBRotationStore) Promote(ctx context.Context, kid string, promotedAt time.Time) error {
	if err := s.promoteKey(ctx, kid, promotedAt); err != nil {
		return fmt.Errorf("crypto: DBRotationStore.Promote: %w", err)
	}
	return nil
}

// Retire implements RotationStore. It transitions the key with the given kid
// to retired state.
func (s *DBRotationStore) Retire(ctx context.Context, kid string) error {
	if err := s.retireKey(ctx, kid); err != nil {
		return fmt.Errorf("crypto: DBRotationStore.Retire: %w", err)
	}
	return nil
}

// --- Helper functions ---

// jwkToPublicKeyDER converts a JWK to DER-encoded public key bytes.
func jwkToPublicKeyDER(jwk JWK) ([]byte, error) {
	pub, err := jwk.ToPublicKey()
	if err != nil {
		return nil, fmt.Errorf("convert JWK to public key: %w", err)
	}

	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("marshal public key to DER: %w", err)
	}

	return der, nil
}

// isNotFoundError checks if the error indicates a not-found condition.
// This checks for common patterns from database drivers and the clients package.
func isNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "not found") || strings.Contains(msg, "no rows")
}
