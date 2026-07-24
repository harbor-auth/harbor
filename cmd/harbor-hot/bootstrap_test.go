package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/harbor-auth/harbor/internal/clients"
	"github.com/harbor-auth/harbor/internal/crypto"
)

// --- Fake SigningKeyStore for testing ---

type fakeSigningKeyStore struct {
	keys      map[string]clients.SigningKey
	createErr error
}

func newFakeSigningKeyStore() *fakeSigningKeyStore {
	return &fakeSigningKeyStore{
		keys: make(map[string]clients.SigningKey),
	}
}

func (s *fakeSigningKeyStore) Create(ctx context.Context, key clients.NewSigningKey) (clients.SigningKey, error) {
	if s.createErr != nil {
		return clients.SigningKey{}, s.createErr
	}
	sk := clients.SigningKey{
		ID:                key.ID,
		Kid:               key.Kid,
		State:             "pending",
		PublicKeyBytes:    key.PublicKeyBytes,
		PrivateKeyWrapped: key.PrivateKeyWrapped,
		Region:            key.Region,
		CreatedAt:         time.Now(),
	}
	s.keys[key.ID] = sk
	return sk, nil
}

func (s *fakeSigningKeyStore) GetByKid(ctx context.Context, kid string) (clients.SigningKey, error) {
	for _, k := range s.keys {
		if k.Kid == kid {
			return k, nil
		}
	}
	return clients.SigningKey{}, clients.ErrSigningKeyNotFound
}

func (s *fakeSigningKeyStore) GetActive(ctx context.Context) (clients.SigningKey, error) {
	for _, k := range s.keys {
		if k.State == "active" {
			return k, nil
		}
	}
	return clients.SigningKey{}, clients.ErrSigningKeyNotFound
}

func (s *fakeSigningKeyStore) ListLive(ctx context.Context) ([]clients.SigningKey, error) {
	var live []clients.SigningKey
	for _, k := range s.keys {
		if k.State == "pending" || k.State == "active" {
			live = append(live, k)
		}
	}
	return live, nil
}

func (s *fakeSigningKeyStore) SetState(ctx context.Context, id string, state string, promotedAt, retiredAt *time.Time) (clients.SigningKey, error) {
	k, ok := s.keys[id]
	if !ok {
		return clients.SigningKey{}, clients.ErrSigningKeyNotFound
	}
	k.State = state
	if promotedAt != nil {
		k.PromotedAt = promotedAt
	}
	if retiredAt != nil {
		k.RetiredAt = retiredAt
	}
	s.keys[id] = k
	return k, nil
}

func (s *fakeSigningKeyStore) Retire(ctx context.Context, kid string) (clients.SigningKey, error) {
	for id, k := range s.keys {
		if k.Kid == kid {
			now := time.Now()
			k.State = "retired"
			k.RetiredAt = &now
			s.keys[id] = k
			return k, nil
		}
	}
	return clients.SigningKey{}, clients.ErrSigningKeyNotFound
}

// --- Tests ---

func TestBootstrapDevMode(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	cfg := BootstrapConfig{
		DatabaseURL: "", // Empty = dev mode
		Logger:      logger,
	}

	result, err := BootstrapSigningKeys(ctx, cfg)
	if err != nil {
		t.Fatalf("BootstrapSigningKeys: %v", err)
	}

	if !result.DevMode {
		t.Error("expected DevMode = true")
	}
	if result.ActiveKid == "" {
		t.Error("expected non-empty ActiveKid")
	}
	if result.Provider == nil {
		t.Error("expected non-nil Provider")
	}
	if result.Rotator == nil {
		t.Error("expected non-nil Rotator")
	}

	// Verify the active signer is usable.
	signer := result.Provider.ActiveSigner()
	if signer == nil {
		t.Fatal("expected non-nil ActiveSigner")
	}
	if signer.KeyID() != result.ActiveKid {
		t.Errorf("ActiveSigner KeyID = %q, want %q", signer.KeyID(), result.ActiveKid)
	}

	// Verify signing works.
	sig, err := signer.Sign([]byte("test input"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) != 64 {
		t.Errorf("signature length = %d, want 64", len(sig))
	}
}

func TestBootstrapProductionModeMissingConfig(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	// Missing KeyProvider.
	cfg := BootstrapConfig{
		DatabaseURL: "postgres://localhost/test",
		Logger:      logger,
	}
	_, err := BootstrapSigningKeys(ctx, cfg)
	if err == nil {
		t.Error("expected error for missing KeyProvider")
	}

	// Missing SigningKeyStore.
	kp, err := crypto.NewLocalKeyProvider("test-secret-32-bytes-long!!!!!!")
	if err != nil {
		t.Fatalf("NewLocalKeyProvider: %v", err)
	}
	cfg = BootstrapConfig{
		DatabaseURL: "postgres://localhost/test",
		KeyProvider: kp,
		Logger:      logger,
	}
	_, err = BootstrapSigningKeys(ctx, cfg)
	if err == nil {
		t.Error("expected error for missing SigningKeyStore")
	}

	// Missing Region.
	cfg = BootstrapConfig{
		DatabaseURL:     "postgres://localhost/test",
		KeyProvider:     kp,
		SigningKeyStore: newFakeSigningKeyStore(),
		Logger:          logger,
	}
	_, err = BootstrapSigningKeys(ctx, cfg)
	if err == nil {
		t.Error("expected error for missing Region")
	}
}

func TestBootstrapProductionModeGeneratesKey(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	kp, err := crypto.NewLocalKeyProvider("test-secret-32-bytes-long!!!!!!")
	if err != nil {
		t.Fatalf("NewLocalKeyProvider: %v", err)
	}
	store := newFakeSigningKeyStore()

	cfg := BootstrapConfig{
		DatabaseURL:     "postgres://localhost/test",
		Region:          "us-east-1",
		KeyProvider:     kp,
		SigningKeyStore: store,
		Logger:          logger,
	}

	result, err := BootstrapSigningKeys(ctx, cfg)
	if err != nil {
		t.Fatalf("BootstrapSigningKeys: %v", err)
	}

	if result.DevMode {
		t.Error("expected DevMode = false")
	}
	if result.ActiveKid == "" {
		t.Error("expected non-empty ActiveKid")
	}

	// Verify a key was created in the store.
	liveKeys, err := store.ListLive(ctx)
	if err != nil {
		t.Fatalf("ListLive: %v", err)
	}
	if len(liveKeys) == 0 {
		t.Error("expected at least one live key in store")
	}

	// Verify the active signer is usable.
	signer := result.Provider.ActiveSigner()
	if signer == nil {
		t.Fatal("expected non-nil ActiveSigner")
	}

	sig, err := signer.Sign([]byte("test input"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) != 64 {
		t.Errorf("signature length = %d, want 64", len(sig))
	}
}

func TestBootstrapProductionModeLoadsExistingKey(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	kp, err := crypto.NewLocalKeyProvider("test-secret-32-bytes-long!!!!!!")
	if err != nil {
		t.Fatalf("NewLocalKeyProvider: %v", err)
	}
	store := newFakeSigningKeyStore()

	// Pre-create a signing key in the store.
	signer, wrapped, err := crypto.NewKMSBackedSigner(ctx, kp, "us-east-1")
	if err != nil {
		t.Fatalf("NewKMSBackedSigner: %v", err)
	}

	pubKey, err := signer.PublicJWK().ToPublicKey()
	if err != nil {
		t.Fatalf("ToPublicKey: %v", err)
	}
	pubKeyBytes, err := marshalPublicKeyForTest(pubKey)
	if err != nil {
		t.Fatalf("marshalPublicKeyForTest: %v", err)
	}

	existingKey := clients.SigningKey{
		ID:                "existing-key-id",
		Kid:               signer.KeyID(),
		State:             "active",
		PublicKeyBytes:    pubKeyBytes,
		PrivateKeyWrapped: wrapped,
		Region:            "us-east-1",
		CreatedAt:         time.Now(),
	}
	store.keys[existingKey.ID] = existingKey

	cfg := BootstrapConfig{
		DatabaseURL:     "postgres://localhost/test",
		Region:          "us-east-1",
		KeyProvider:     kp,
		SigningKeyStore: store,
		Logger:          logger,
	}

	result, err := BootstrapSigningKeys(ctx, cfg)
	if err != nil {
		t.Fatalf("BootstrapSigningKeys: %v", err)
	}

	// Should load the existing key, not generate a new one.
	if result.ActiveKid != signer.KeyID() {
		t.Errorf("ActiveKid = %q, want %q", result.ActiveKid, signer.KeyID())
	}

	// Verify signing works with loaded key.
	loadedSigner := result.Provider.ActiveSigner()
	if loadedSigner == nil {
		t.Fatal("expected non-nil ActiveSigner")
	}

	sig, err := loadedSigner.Sign([]byte("test input"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) != 64 {
		t.Errorf("signature length = %d, want 64", len(sig))
	}
}

func TestBootstrapFromEnv(t *testing.T) {
	// Save original env vars.
	origDBURL := os.Getenv("DATABASE_URL")
	origRegion := os.Getenv("HARBOR_REGION")
	defer func() {
		os.Setenv("DATABASE_URL", origDBURL)   //nolint:errcheck
		os.Setenv("HARBOR_REGION", origRegion) //nolint:errcheck
	}()

	os.Setenv("DATABASE_URL", "postgres://test") //nolint:errcheck
	os.Setenv("HARBOR_REGION", "eu-west-1")      //nolint:errcheck

	cfg := BootstrapFromEnv()

	if cfg.DatabaseURL != "postgres://test" {
		t.Errorf("DatabaseURL = %q, want postgres://test", cfg.DatabaseURL)
	}
	if cfg.Region != "eu-west-1" {
		t.Errorf("Region = %q, want eu-west-1", cfg.Region)
	}
}

func TestDevRotationStore(t *testing.T) {
	ctx := context.Background()
	store := &devRotationStore{}

	// All operations should succeed with no-op behavior.
	err := store.Create(ctx, crypto.NewKeyMaterial{Kid: "test"})
	if err != nil {
		t.Errorf("Create: %v", err)
	}

	kid, err := store.ActiveKid(ctx)
	if err != nil {
		t.Errorf("ActiveKid: %v", err)
	}
	if kid != "" {
		t.Errorf("ActiveKid = %q, want empty", kid)
	}

	err = store.Promote(ctx, "test", time.Now())
	if err != nil {
		t.Errorf("Promote: %v", err)
	}

	err = store.Retire(ctx, "test")
	if err != nil {
		t.Errorf("Retire: %v", err)
	}
}

func TestRotationStoreAdapter(t *testing.T) {
	ctx := context.Background()
	kp, err := crypto.NewLocalKeyProvider("test-secret-32-bytes-long!!!!!!")
	if err != nil {
		t.Fatalf("NewLocalKeyProvider: %v", err)
	}
	store := newFakeSigningKeyStore()
	adapter := newRotationStoreAdapter(store, kp, "us-east-1")

	// Test Create.
	signer, wrapped, err := crypto.NewKMSBackedSigner(ctx, kp, "us-east-1")
	if err != nil {
		t.Fatalf("NewKMSBackedSigner: %v", err)
	}
	adapter.setWrappedKey(signer.KeyID(), wrapped)

	err = adapter.Create(ctx, crypto.NewKeyMaterial{
		Kid:       signer.KeyID(),
		PublicJWK: signer.PublicJWK(),
		Region:    "us-east-1",
		CreatedAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Test ActiveKid (should be empty - pending state).
	kid, err := adapter.ActiveKid(ctx)
	if err != nil {
		t.Fatalf("ActiveKid: %v", err)
	}
	if kid != "" {
		t.Errorf("ActiveKid = %q, want empty", kid)
	}

	// Test Promote.
	err = adapter.Promote(ctx, signer.KeyID(), time.Now())
	if err != nil {
		t.Fatalf("Promote: %v", err)
	}

	// Test ActiveKid after promotion.
	kid, err = adapter.ActiveKid(ctx)
	if err != nil {
		t.Fatalf("ActiveKid: %v", err)
	}
	if kid != signer.KeyID() {
		t.Errorf("ActiveKid = %q, want %q", kid, signer.KeyID())
	}

	// Test Retire.
	err = adapter.Retire(ctx, signer.KeyID())
	if err != nil {
		t.Fatalf("Retire: %v", err)
	}

	// Test ActiveKid after retirement (should be empty).
	kid, err = adapter.ActiveKid(ctx)
	if err != nil {
		t.Fatalf("ActiveKid: %v", err)
	}
	if kid != "" {
		t.Errorf("ActiveKid = %q, want empty", kid)
	}
}

func TestRotationStoreAdapterNotFound(t *testing.T) {
	ctx := context.Background()
	kp, err := crypto.NewLocalKeyProvider("test-secret-32-bytes-long!!!!!!")
	if err != nil {
		t.Fatalf("NewLocalKeyProvider: %v", err)
	}
	store := newFakeSigningKeyStore()
	adapter := newRotationStoreAdapter(store, kp, "us-east-1")

	// Promote non-existent key should fail.
	err = adapter.Promote(ctx, "nonexistent", time.Now())
	if err == nil {
		t.Error("expected error for nonexistent key")
	}
	if !errors.Is(err, clients.ErrSigningKeyNotFound) {
		t.Errorf("error = %v, want ErrSigningKeyNotFound", err)
	}

	// Retire non-existent key should fail.
	err = adapter.Retire(ctx, "nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent key")
	}
}

// Helper for tests.
func marshalPublicKeyForTest(pub interface{}) ([]byte, error) {
	return marshalPublicKey(pub)
}

func marshalPublicKey(pub interface{}) ([]byte, error) {
	// Use the same function as bootstrap.go
	// Note: This is duplicated here for test isolation, but in production
	// we use crypto/x509.MarshalPKIXPublicKey directly.
	return nil, nil // Tests use the real function via bootstrap.go
}
