package clients

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/harbor-auth/harbor/internal/crypto"
)

// DBRotationStore adapts a SigningKeyStore to the crypto.RotationStore interface
// consumed by crypto.KeyRotator (docs/DESIGN.md §7.3, §3.5.4). The KeyRotator
// speaks crypto domain types (NewKeyMaterial / kid); this adapter translates
// them onto the signing_keys table, persisting both the public JWK (as PKIX
// DER) and the wrapped private key bytes produced by the KeyRotator's private-
// key wrapper.
type DBRotationStore struct {
	keyStore SigningKeyStore
	region   string
}

// Compile-time proof that DBRotationStore implements crypto.RotationStore.
var _ crypto.RotationStore = (*DBRotationStore)(nil)

// NewDBRotationStore wraps keyStore as a crypto.RotationStore, stamping region
// on every created key.
func NewDBRotationStore(keyStore SigningKeyStore, region string) *DBRotationStore {
	return &DBRotationStore{keyStore: keyStore, region: region}
}

// Create implements crypto.RotationStore: it persists a new key in pending
// state. The public JWK is re-encoded as PKIX DER for storage; the wrapped
// private key bytes (nil for HSM-backed signers) are stored as-is.
func (s *DBRotationStore) Create(ctx context.Context, key crypto.NewKeyMaterial) error {
	pub, err := key.PublicJWK.ToPublicKey()
	if err != nil {
		return fmt.Errorf("rotationstore: parse public JWK for kid %q: %w", key.Kid, err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return fmt.Errorf("rotationstore: marshal public key for kid %q: %w", key.Kid, err)
	}

	region := key.Region
	if region == "" {
		region = s.region
	}

	if _, err := s.keyStore.Create(ctx, NewSigningKey{
		ID:                uuid.NewString(),
		Kid:               key.Kid,
		PublicKeyBytes:    pubDER,
		PrivateKeyWrapped: key.WrappedPrivateKey,
		Region:            region,
	}); err != nil {
		return fmt.Errorf("rotationstore: create key %q: %w", key.Kid, err)
	}
	return nil
}

// ActiveKid implements crypto.RotationStore: it returns the kid of the current
// active key, or "" when there is no active key (e.g. the first rotation).
func (s *DBRotationStore) ActiveKid(ctx context.Context) (string, error) {
	key, err := s.keyStore.GetActive(ctx)
	if err != nil {
		if errors.Is(err, ErrSigningKeyNotFound) {
			return "", nil
		}
		return "", fmt.Errorf("rotationstore: get active kid: %w", err)
	}
	return key.Kid, nil
}

// Promote implements crypto.RotationStore: it transitions the pending key with
// the given kid to active, stamping promotedAt. It first resolves the kid to the
// row's UUID (SetState is keyed by ID).
func (s *DBRotationStore) Promote(ctx context.Context, kid string, promotedAt time.Time) error {
	key, err := s.keyStore.GetByKid(ctx, kid)
	if err != nil {
		return fmt.Errorf("rotationstore: get key by kid %q: %w", kid, err)
	}
	if _, err := s.keyStore.SetState(ctx, key.ID, string(crypto.KeyStateActive), &promotedAt, nil); err != nil {
		return fmt.Errorf("rotationstore: promote key %q: %w", kid, err)
	}
	return nil
}

// Retire implements crypto.RotationStore: it transitions the key with the given
// kid to retired (removed from JWKS).
func (s *DBRotationStore) Retire(ctx context.Context, kid string) error {
	if _, err := s.keyStore.Retire(ctx, kid); err != nil {
		return fmt.Errorf("rotationstore: retire key %q: %w", kid, err)
	}
	return nil
}
