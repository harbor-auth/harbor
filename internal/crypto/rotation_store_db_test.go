package crypto

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// --- Fake signing key store for testing ---

type fakeSigningKey struct {
	ID                string
	Kid               string
	State             string
	PublicKeyBytes    []byte
	PrivateKeyWrapped []byte
	Region            string
	CreatedAt         time.Time
	PromotedAt        *time.Time
	RetiredAt         *time.Time
}

type fakeSigningKeyStore struct {
	mu    sync.Mutex
	keys  map[string]fakeSigningKey // keyed by ID
	clock func() time.Time
}

func newFakeSigningKeyStore() *fakeSigningKeyStore {
	return &fakeSigningKeyStore{
		keys:  make(map[string]fakeSigningKey),
		clock: time.Now,
	}
}

var errFakeNotFound = errors.New("signing key not found")

func (s *fakeSigningKeyStore) CreateKey(ctx context.Context, id, kid, region string, publicKeyBytes, privateKeyWrapped []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if id == "" {
		return errors.New("empty ID")
	}
	if _, ok := s.keys[id]; ok {
		return fmt.Errorf("duplicate ID %q", id)
	}
	for _, k := range s.keys {
		if k.Kid == kid {
			return fmt.Errorf("duplicate kid %q", kid)
		}
	}

	s.keys[id] = fakeSigningKey{
		ID:                id,
		Kid:               kid,
		State:             "pending",
		PublicKeyBytes:    publicKeyBytes,
		PrivateKeyWrapped: privateKeyWrapped,
		Region:            region,
		CreatedAt:         s.clock(),
	}
	return nil
}

func (s *fakeSigningKeyStore) GetActiveKid(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, k := range s.keys {
		if k.State == "active" {
			return k.Kid, nil
		}
	}
	return "", errFakeNotFound
}

func (s *fakeSigningKeyStore) GetByKid(ctx context.Context, kid string) (fakeSigningKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, k := range s.keys {
		if k.Kid == kid {
			return k, nil
		}
	}
	return fakeSigningKey{}, errFakeNotFound
}

func (s *fakeSigningKeyStore) PromoteKey(ctx context.Context, kid string, promotedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for id, k := range s.keys {
		if k.Kid == kid {
			k.State = "active"
			k.PromotedAt = &promotedAt
			s.keys[id] = k
			return nil
		}
	}
	return errFakeNotFound
}

func (s *fakeSigningKeyStore) RetireKey(ctx context.Context, kid string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for id, k := range s.keys {
		if k.Kid == kid {
			now := s.clock()
			k.State = "retired"
			k.RetiredAt = &now
			s.keys[id] = k
			return nil
		}
	}
	return errFakeNotFound
}

// toConfig creates a DBRotationStoreConfig from the fake store.
func (s *fakeSigningKeyStore) toConfig() DBRotationStoreConfig {
	return DBRotationStoreConfig{
		CreateKey:    s.CreateKey,
		GetActiveKid: s.GetActiveKid,
		PromoteKey:   s.PromoteKey,
		RetireKey:    s.RetireKey,
	}
}

// --- Test helpers ---

func makeTestJWK(t *testing.T) JWK {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	var xBuf, yBuf [32]byte
	priv.X.FillBytes(xBuf[:])
	priv.Y.FillBytes(yBuf[:])
	return JWK{
		Kty: "EC",
		Crv: "P-256",
		Kid: "test-kid-" + base64.RawURLEncoding.EncodeToString(xBuf[:8]),
		X:   base64.RawURLEncoding.EncodeToString(xBuf[:]),
		Y:   base64.RawURLEncoding.EncodeToString(yBuf[:]),
		Use: "sig",
		Alg: "ES256",
	}
}

// --- DBRotationStore tests ---

func TestDBRotationStoreCreate(t *testing.T) {
	ctx := context.Background()
	store := newFakeSigningKeyStore()
	rotStore := NewDBRotationStore(store.toConfig()).
		WithIDGenerator(func() string { return "test-id-1" })

	jwk := makeTestJWK(t)
	key := NewKeyMaterial{
		Kid:       jwk.Kid,
		PublicJWK: jwk,
		Region:    "us-east-1",
		CreatedAt: time.Now(),
	}

	err := rotStore.Create(ctx, key)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Verify key was created.
	created, err := store.GetByKid(ctx, jwk.Kid)
	if err != nil {
		t.Fatalf("GetByKid: %v", err)
	}
	if created.Kid != jwk.Kid {
		t.Errorf("Kid = %q, want %q", created.Kid, jwk.Kid)
	}
	if created.State != "pending" {
		t.Errorf("State = %q, want pending", created.State)
	}
	if created.Region != "us-east-1" {
		t.Errorf("Region = %q, want us-east-1", created.Region)
	}

	// Verify public key bytes are valid DER.
	_, err = x509.ParsePKIXPublicKey(created.PublicKeyBytes)
	if err != nil {
		t.Errorf("PublicKeyBytes is not valid DER: %v", err)
	}
}

func TestDBRotationStoreCreateWithWrappedKey(t *testing.T) {
	ctx := context.Background()
	store := newFakeSigningKeyStore()
	rotStore := NewDBRotationStore(store.toConfig()).
		WithIDGenerator(func() string { return "test-id-2" })

	jwk := makeTestJWK(t)
	wrappedKey := []byte("wrapped-private-key-bytes")
	key := NewKeyMaterial{
		Kid:       jwk.Kid,
		PublicJWK: jwk,
		Region:    "us-east-1",
		CreatedAt: time.Now(),
	}

	err := rotStore.CreateWithWrappedKey(ctx, key, wrappedKey)
	if err != nil {
		t.Fatalf("CreateWithWrappedKey: %v", err)
	}

	// Verify key was created with wrapped private key.
	created, err := store.GetByKid(ctx, jwk.Kid)
	if err != nil {
		t.Fatalf("GetByKid: %v", err)
	}
	if string(created.PrivateKeyWrapped) != string(wrappedKey) {
		t.Errorf("PrivateKeyWrapped mismatch")
	}
}

func TestDBRotationStoreActiveKid(t *testing.T) {
	ctx := context.Background()
	store := newFakeSigningKeyStore()
	rotStore := NewDBRotationStore(store.toConfig())

	// No active key initially.
	kid, err := rotStore.ActiveKid(ctx)
	if err != nil {
		t.Fatalf("ActiveKid (no active): %v", err)
	}
	if kid != "" {
		t.Errorf("ActiveKid = %q, want empty", kid)
	}

	// Create and activate a key.
	jwk := makeTestJWK(t)
	store.CreateKey(ctx, "key-1", jwk.Kid, "us-east-1", nil, nil)
	now := time.Now()
	store.PromoteKey(ctx, jwk.Kid, now)

	kid, err = rotStore.ActiveKid(ctx)
	if err != nil {
		t.Fatalf("ActiveKid (with active): %v", err)
	}
	if kid != jwk.Kid {
		t.Errorf("ActiveKid = %q, want %q", kid, jwk.Kid)
	}
}

func TestDBRotationStorePromote(t *testing.T) {
	ctx := context.Background()
	store := newFakeSigningKeyStore()
	rotStore := NewDBRotationStore(store.toConfig())

	// Create a pending key.
	jwk := makeTestJWK(t)
	store.CreateKey(ctx, "key-1", jwk.Kid, "us-east-1", nil, nil)

	// Promote it.
	promotedAt := time.Now()
	err := rotStore.Promote(ctx, jwk.Kid, promotedAt)
	if err != nil {
		t.Fatalf("Promote: %v", err)
	}

	// Verify state changed.
	key, _ := store.GetByKid(ctx, jwk.Kid)
	if key.State != "active" {
		t.Errorf("State = %q, want active", key.State)
	}
	if key.PromotedAt == nil {
		t.Error("PromotedAt is nil")
	}
}

func TestDBRotationStorePromoteNotFound(t *testing.T) {
	ctx := context.Background()
	store := newFakeSigningKeyStore()
	rotStore := NewDBRotationStore(store.toConfig())

	err := rotStore.Promote(ctx, "nonexistent-kid", time.Now())
	if err == nil {
		t.Fatal("expected error for nonexistent kid")
	}
}

func TestDBRotationStoreRetire(t *testing.T) {
	ctx := context.Background()
	store := newFakeSigningKeyStore()
	rotStore := NewDBRotationStore(store.toConfig())

	// Create a key.
	jwk := makeTestJWK(t)
	store.CreateKey(ctx, "key-1", jwk.Kid, "us-east-1", nil, nil)

	// Retire it.
	err := rotStore.Retire(ctx, jwk.Kid)
	if err != nil {
		t.Fatalf("Retire: %v", err)
	}

	// Verify state changed.
	key, _ := store.GetByKid(ctx, jwk.Kid)
	if key.State != "retired" {
		t.Errorf("State = %q, want retired", key.State)
	}
	if key.RetiredAt == nil {
		t.Error("RetiredAt is nil")
	}
}

func TestDBRotationStoreRetireNotFound(t *testing.T) {
	ctx := context.Background()
	store := newFakeSigningKeyStore()
	rotStore := NewDBRotationStore(store.toConfig())

	err := rotStore.Retire(ctx, "nonexistent-kid")
	if err == nil {
		t.Fatal("expected error for nonexistent kid")
	}
}

func TestDBRotationStoreFullLifecycle(t *testing.T) {
	ctx := context.Background()
	store := newFakeSigningKeyStore()
	rotStore := NewDBRotationStore(store.toConfig()).
		WithIDGenerator(func() string { return "lifecycle-key" })

	// 1. Create a pending key.
	jwk := makeTestJWK(t)
	key := NewKeyMaterial{
		Kid:       jwk.Kid,
		PublicJWK: jwk,
		Region:    "us-east-1",
		CreatedAt: time.Now(),
	}
	err := rotStore.Create(ctx, key)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// 2. Verify no active key yet.
	kid, err := rotStore.ActiveKid(ctx)
	if err != nil {
		t.Fatalf("ActiveKid: %v", err)
	}
	if kid != "" {
		t.Errorf("ActiveKid = %q, want empty (no active key yet)", kid)
	}

	// 3. Promote to active.
	promotedAt := time.Now()
	err = rotStore.Promote(ctx, jwk.Kid, promotedAt)
	if err != nil {
		t.Fatalf("Promote: %v", err)
	}

	// 4. Verify active key.
	kid, err = rotStore.ActiveKid(ctx)
	if err != nil {
		t.Fatalf("ActiveKid: %v", err)
	}
	if kid != jwk.Kid {
		t.Errorf("ActiveKid = %q, want %q", kid, jwk.Kid)
	}

	// 5. Retire.
	err = rotStore.Retire(ctx, jwk.Kid)
	if err != nil {
		t.Fatalf("Retire: %v", err)
	}

	// 6. Verify no active key after retirement.
	kid, err = rotStore.ActiveKid(ctx)
	if err != nil {
		t.Fatalf("ActiveKid: %v", err)
	}
	if kid != "" {
		t.Errorf("ActiveKid = %q, want empty (retired)", kid)
	}
}

// --- jwkToPublicKeyDER tests ---

func TestJwkToPublicKeyDER(t *testing.T) {
	jwk := makeTestJWK(t)

	der, err := jwkToPublicKeyDER(jwk)
	if err != nil {
		t.Fatalf("jwkToPublicKeyDER: %v", err)
	}

	// Verify it's valid DER.
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		t.Fatalf("ParsePKIXPublicKey: %v", err)
	}

	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", pub)
	}

	if ecdsaPub.Curve != elliptic.P256() {
		t.Errorf("wrong curve: %s", ecdsaPub.Curve.Params().Name)
	}
}

func TestJwkToPublicKeyDERInvalid(t *testing.T) {
	// Invalid JWK (bad base64).
	jwk := JWK{
		Kty: "EC",
		Crv: "P-256",
		X:   "!!!invalid-base64!!!",
		Y:   "also-invalid",
	}

	_, err := jwkToPublicKeyDER(jwk)
	if err == nil {
		t.Fatal("expected error for invalid JWK")
	}
}

// --- isNotFoundError tests ---

func TestIsNotFoundError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"errFakeNotFound", errFakeNotFound, true},
		{"wrapped errFakeNotFound", fmt.Errorf("wrapped: %w", errFakeNotFound), true},
		{"contains not found", errors.New("key not found"), true},
		{"contains no rows", errors.New("sql: no rows in result set"), true},
		{"other error", errors.New("connection refused"), false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := isNotFoundError(tc.err)
			if got != tc.want {
				t.Errorf("isNotFoundError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// --- Multiple regions test ---

func TestDBRotationStoreMultipleRegions(t *testing.T) {
	ctx := context.Background()
	store := newFakeSigningKeyStore()

	regions := []string{"us-east-1", "eu-west-1", "ap-northeast-1"}
	keyCount := 0

	for _, region := range regions {
		rotStore := NewDBRotationStore(store.toConfig()).
			WithIDGenerator(func() string {
				keyCount++
				return fmt.Sprintf("key-%d", keyCount)
			})

		jwk := makeTestJWK(t)
		key := NewKeyMaterial{
			Kid:       jwk.Kid,
			PublicJWK: jwk,
			Region:    region,
			CreatedAt: time.Now(),
		}

		err := rotStore.Create(ctx, key)
		if err != nil {
			t.Fatalf("Create for region %s: %v", region, err)
		}

		created, err := store.GetByKid(ctx, jwk.Kid)
		if err != nil {
			t.Fatalf("GetByKid for region %s: %v", region, err)
		}
		if created.Region != region {
			t.Errorf("Region = %q, want %q", created.Region, region)
		}
	}
}
