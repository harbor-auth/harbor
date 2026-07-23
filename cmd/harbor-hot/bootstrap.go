package main

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/harbor-auth/harbor/internal/clients"
	"github.com/harbor-auth/harbor/internal/crypto"
)

// BootstrapConfig holds configuration for the signing key bootstrap process.
type BootstrapConfig struct {
	// DatabaseURL is the connection string for the signing key store.
	// If empty, dev mode (LocalSigner) is used.
	DatabaseURL string

	// Region is the data sovereignty jurisdiction for new keys.
	Region string

	// KMSKeyProvider is the KeyProvider for wrapping/unwrapping signing keys.
	// Required when DatabaseURL is set; ignored in dev mode.
	KeyProvider crypto.KeyProvider

	// SigningKeyStore is the store for signing key persistence.
	// Required when DatabaseURL is set; ignored in dev mode.
	SigningKeyStore clients.SigningKeyStore

	// Logger for bootstrap messages.
	Logger *slog.Logger
}

// BootstrapResult contains the initialized crypto components.
type BootstrapResult struct {
	// Provider is the MultiKeyProvider with loaded signers.
	Provider *crypto.MultiKeyProvider

	// Rotator is the KeyRotator for managing key rotation.
	Rotator *crypto.KeyRotator

	// ActiveKid is the kid of the active signing key, or "" if none.
	ActiveKid string

	// DevMode indicates whether dev-only LocalSigner is being used.
	DevMode bool
}

// BootstrapSigningKeys initializes the signing key infrastructure on startup.
//
// If DATABASE_URL is set:
//  1. Queries SigningKeyStore.ListLive to load existing keys
//  2. For each key, calls LoadKMSBackedSigner to reconstruct the Signer
//  3. If no active key exists, generates a new one via KeyRotator.Rotate
//  4. Returns MultiKeyProvider with loaded signers
//
// If DATABASE_URL is unset (dev mode):
//  1. Creates a LocalSigner (dev-only, logs warning)
//  2. Returns MultiKeyProvider with the dev signer
func BootstrapSigningKeys(ctx context.Context, cfg BootstrapConfig) (*BootstrapResult, error) {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	// Dev mode: no DATABASE_URL means use LocalSigner.
	if cfg.DatabaseURL == "" {
		return bootstrapDevMode(ctx, logger)
	}

	// Production mode: load from database.
	return bootstrapProductionMode(ctx, cfg, logger)
}

// bootstrapDevMode creates a dev-only LocalSigner.
func bootstrapDevMode(ctx context.Context, logger *slog.Logger) (*BootstrapResult, error) {
	logger.Warn("DEV MODE: using in-memory LocalSigner — NOT FOR PRODUCTION",
		"hint", "set DATABASE_URL to enable KMS-backed signing keys")

	// Create dev signer.
	signer, err := crypto.NewLocalSigner()
	if err != nil {
		return nil, fmt.Errorf("bootstrap: create dev signer: %w", err)
	}

	// Create provider with dev signer as active.
	provider, err := crypto.NewMultiKeyProvider(signer)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: create provider: %w", err)
	}

	// Create a no-op rotation store for dev mode.
	devStore := &devRotationStore{}
	rotator := crypto.NewKeyRotator(
		crypto.NewRotationManager(crypto.DefaultRotationConfig()),
		provider,
		devStore,
	)

	logger.Info("dev signing key ready",
		"kid", signer.KeyID(),
		"mode", "local")

	return &BootstrapResult{
		Provider:  provider,
		Rotator:   rotator,
		ActiveKid: signer.KeyID(),
		DevMode:   true,
	}, nil
}

// bootstrapProductionMode loads signing keys from the database.
func bootstrapProductionMode(ctx context.Context, cfg BootstrapConfig, logger *slog.Logger) (*BootstrapResult, error) {
	if cfg.KeyProvider == nil {
		return nil, fmt.Errorf("bootstrap: KeyProvider required when DATABASE_URL is set")
	}
	if cfg.SigningKeyStore == nil {
		return nil, fmt.Errorf("bootstrap: SigningKeyStore required when DATABASE_URL is set")
	}
	if cfg.Region == "" {
		return nil, fmt.Errorf("bootstrap: Region required when DATABASE_URL is set")
	}

	// Load existing live keys from the database.
	liveKeys, err := cfg.SigningKeyStore.ListLive(ctx)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: list live keys: %w", err)
	}

	// Collect signers from the database.
	var signers []crypto.Signer
	var activeSigner crypto.Signer
	var activeKid string

	for _, key := range liveKeys {
		// Skip keys without wrapped private key (shouldn't happen in production).
		if len(key.PrivateKeyWrapped) == 0 {
			logger.Warn("skipping key without wrapped private key",
				"kid", key.Kid,
				"state", key.State)
			continue
		}

		// Load the signer from wrapped bytes.
		signer, err := crypto.LoadKMSBackedSigner(ctx, cfg.KeyProvider, cfg.Region, key.PrivateKeyWrapped)
		if err != nil {
			logger.Error("failed to load signing key",
				"kid", key.Kid,
				"error", err)
			continue
		}

		signers = append(signers, signer)

		// Track the active key.
		if key.State == "active" {
			activeSigner = signer
			activeKid = key.Kid
		}

		logger.Info("loaded signing key",
			"kid", key.Kid,
			"state", key.State)
	}

	// If no keys exist or no active key, generate a new one.
	var provider *crypto.MultiKeyProvider
	var rotationStore *rotationStoreAdapter

	if activeSigner == nil {
		logger.Info("no active signing key found, generating new key",
			"region", cfg.Region)

		// Generate a fresh KMS-backed signer.
		newSigner, wrapped, err := crypto.NewKMSBackedSigner(ctx, cfg.KeyProvider, cfg.Region)
		if err != nil {
			return nil, fmt.Errorf("bootstrap: generate initial key: %w", err)
		}

		// Persist the new key as active (emergency rotation = immediate promotion).
		pubKey, err := newSigner.PublicJWK().ToPublicKey()
		if err != nil {
			return nil, fmt.Errorf("bootstrap: convert public key: %w", err)
		}
		pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
		if err != nil {
			return nil, fmt.Errorf("bootstrap: marshal public key: %w", err)
		}

		keyID := uuid.New().String()
		now := time.Now()
		_, err = cfg.SigningKeyStore.Create(ctx, clients.NewSigningKey{
			ID:                keyID,
			Kid:               newSigner.KeyID(),
			PublicKeyBytes:    pubKeyBytes,
			PrivateKeyWrapped: wrapped,
			Region:            cfg.Region,
		})
		if err != nil {
			return nil, fmt.Errorf("bootstrap: persist initial key: %w", err)
		}

		// Promote to active immediately.
		_, err = cfg.SigningKeyStore.SetState(ctx, keyID, "active", &now, nil)
		if err != nil {
			return nil, fmt.Errorf("bootstrap: promote initial key: %w", err)
		}

		activeSigner = newSigner
		activeKid = newSigner.KeyID()
		signers = append(signers, newSigner)

		logger.Info("generated initial signing key",
			"kid", activeKid,
			"region", cfg.Region)
	}

	// Create the MultiKeyProvider with the active signer first.
	var pendingSigners []crypto.Signer
	for _, s := range signers {
		if s.KeyID() != activeKid {
			pendingSigners = append(pendingSigners, s)
		}
	}

	provider, err = crypto.NewMultiKeyProvider(activeSigner, pendingSigners...)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: create provider: %w", err)
	}

	// Create rotation store adapter.
	rotationStore = newRotationStoreAdapter(cfg.SigningKeyStore, cfg.KeyProvider, cfg.Region)

	// Create rotator with KMS-backed signer generator.
	rotator := crypto.NewKeyRotator(
		crypto.NewRotationManager(crypto.DefaultRotationConfig()),
		provider,
		rotationStore,
	).WithGenerator(func() (crypto.Signer, error) {
		signer, wrapped, err := crypto.NewKMSBackedSigner(ctx, cfg.KeyProvider, cfg.Region)
		if err != nil {
			return nil, err
		}
		// Store the wrapped key in the rotation store for persistence.
		rotationStore.setWrappedKey(signer.KeyID(), wrapped)
		return signer, nil
	})

	logger.Info("signing key bootstrap complete",
		"activeKid", activeKid,
		"totalKeys", len(signers),
		"mode", "production")

	return &BootstrapResult{
		Provider:  provider,
		Rotator:   rotator,
		ActiveKid: activeKid,
		DevMode:   false,
	}, nil
}

// --- Rotation store adapter ---

// rotationStoreAdapter adapts clients.SigningKeyStore to crypto.RotationStore.
type rotationStoreAdapter struct {
	store       clients.SigningKeyStore
	keyProvider crypto.KeyProvider
	region      string
	wrappedKeys map[string][]byte // kid -> wrapped private key
}

func newRotationStoreAdapter(store clients.SigningKeyStore, kp crypto.KeyProvider, region string) *rotationStoreAdapter {
	return &rotationStoreAdapter{
		store:       store,
		keyProvider: kp,
		region:      region,
		wrappedKeys: make(map[string][]byte),
	}
}

func (a *rotationStoreAdapter) setWrappedKey(kid string, wrapped []byte) {
	a.wrappedKeys[kid] = wrapped
}

func (a *rotationStoreAdapter) Create(ctx context.Context, key crypto.NewKeyMaterial) error {
	// Get the wrapped private key that was set by the generator.
	wrapped := a.wrappedKeys[key.Kid]
	delete(a.wrappedKeys, key.Kid) // Clean up after use

	// Convert JWK to DER-encoded public key bytes.
	pubKey, err := key.PublicJWK.ToPublicKey()
	if err != nil {
		return fmt.Errorf("convert JWK to public key: %w", err)
	}
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return fmt.Errorf("marshal public key: %w", err)
	}

	_, err = a.store.Create(ctx, clients.NewSigningKey{
		ID:                uuid.New().String(),
		Kid:               key.Kid,
		PublicKeyBytes:    pubKeyBytes,
		PrivateKeyWrapped: wrapped,
		Region:            key.Region,
	})
	return err
}

func (a *rotationStoreAdapter) ActiveKid(ctx context.Context) (string, error) {
	key, err := a.store.GetActive(ctx)
	if err != nil {
		if errors.Is(err, clients.ErrSigningKeyNotFound) {
			return "", nil
		}
		return "", err
	}
	return key.Kid, nil
}

func (a *rotationStoreAdapter) Promote(ctx context.Context, kid string, promotedAt time.Time) error {
	key, err := a.store.GetByKid(ctx, kid)
	if err != nil {
		return err
	}
	_, err = a.store.SetState(ctx, key.ID, "active", &promotedAt, nil)
	return err
}

func (a *rotationStoreAdapter) Retire(ctx context.Context, kid string) error {
	_, err := a.store.Retire(ctx, kid)
	return err
}

// --- Dev mode rotation store (no-op) ---

type devRotationStore struct{}

func (s *devRotationStore) Create(ctx context.Context, key crypto.NewKeyMaterial) error {
	return nil
}

func (s *devRotationStore) ActiveKid(ctx context.Context) (string, error) {
	return "", nil
}

func (s *devRotationStore) Promote(ctx context.Context, kid string, promotedAt time.Time) error {
	return nil
}

func (s *devRotationStore) Retire(ctx context.Context, kid string) error {
	return nil
}

// BootstrapFromEnv creates a BootstrapConfig from environment variables.
func BootstrapFromEnv() BootstrapConfig {
	return BootstrapConfig{
		DatabaseURL: os.Getenv("DATABASE_URL"),
		Region:      os.Getenv("HARBOR_REGION"),
	}
}
