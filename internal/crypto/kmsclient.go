package crypto

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"sync"
)

// KMSClient is the narrow seam for envelope encryption operations against a
// regional KMS or HSM (docs/DESIGN.md §7.3). Implementations wrap/unwrap data
// encryption keys (DEKs) under a key-encryption-key (KEK) identified by keyID.
//
// The interface is intentionally minimal: Encrypt wraps plaintext under keyID;
// Decrypt unwraps ciphertext previously encrypted under keyID. The KEK itself
// never leaves the KMS/HSM boundary.
//
// Production implementations will call AWS KMS, GCP Cloud KMS, or a hardware
// HSM; tests use [FakeKMSClient] for hermetic, in-memory operation.
type KMSClient interface {
	// Encrypt wraps plaintext under the KEK identified by keyID. The returned
	// ciphertext is opaque and can only be decrypted by calling Decrypt with
	// the same keyID on a compatible KMSClient.
	Encrypt(ctx context.Context, keyID string, plaintext []byte) ([]byte, error)

	// Decrypt unwraps ciphertext that was previously encrypted under keyID.
	// Returns ErrKMSDecryptFailed if the ciphertext is invalid, tampered, or
	// was encrypted under a different keyID.
	Decrypt(ctx context.Context, keyID string, ciphertext []byte) ([]byte, error)
}

// KMS client errors.
var (
	// ErrKMSDecryptFailed is returned when decryption fails due to invalid
	// ciphertext, wrong keyID, or tampering. A single generic error prevents
	// callers from distinguishing failure modes (decryption-oracle defense).
	ErrKMSDecryptFailed = errors.New("crypto: KMS decryption failed")

	// ErrKMSKeyNotFound is returned when the requested keyID does not exist.
	ErrKMSKeyNotFound = errors.New("crypto: KMS key not found")
)

// FakeKMSClient is an in-memory KMSClient for hermetic tests. It generates a
// random 256-bit AES key per keyID on first use and stores wrapped blobs in
// memory. NOT FOR PRODUCTION — keys are held in process memory.
//
// FakeKMSClient is safe for concurrent use.
type FakeKMSClient struct {
	mu   sync.RWMutex
	keys map[string][]byte // keyID → 32-byte AES key
}

// Compile-time proof that FakeKMSClient implements KMSClient.
var _ KMSClient = (*FakeKMSClient)(nil)

// NewFakeKMSClient constructs an empty FakeKMSClient. Keys are generated lazily
// on first Encrypt call for each keyID.
func NewFakeKMSClient() *FakeKMSClient {
	return &FakeKMSClient{
		keys: make(map[string][]byte),
	}
}

// NewFakeKMSClientWithKeys constructs a FakeKMSClient pre-seeded with the given
// keys. Each key must be exactly 32 bytes (AES-256). This is useful for tests
// that need deterministic encryption output.
func NewFakeKMSClientWithKeys(keys map[string][]byte) (*FakeKMSClient, error) {
	f := &FakeKMSClient{
		keys: make(map[string][]byte, len(keys)),
	}
	for keyID, key := range keys {
		if len(key) != 32 {
			return nil, fmt.Errorf("crypto: FakeKMSClient: key %q must be 32 bytes, got %d", keyID, len(key))
		}
		keyCopy := make([]byte, 32)
		copy(keyCopy, key)
		f.keys[keyID] = keyCopy
	}
	return f, nil
}

// Encrypt implements KMSClient. It encrypts plaintext using AES-256-GCM under
// the key for keyID. If no key exists for keyID, a new random key is generated.
//
// Output layout: nonce (12 bytes) ‖ ciphertext ‖ GCM tag (16 bytes).
func (f *FakeKMSClient) Encrypt(_ context.Context, keyID string, plaintext []byte) ([]byte, error) {
	key, err := f.getOrCreateKey(keyID)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: FakeKMSClient: AES setup: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: FakeKMSClient: GCM setup: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("crypto: FakeKMSClient: nonce generation: %w", err)
	}

	// Seal appends ciphertext+tag after nonce, giving nonce ‖ ciphertext ‖ tag.
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt implements KMSClient. It decrypts ciphertext that was encrypted under
// keyID. Returns ErrKMSKeyNotFound if no key exists for keyID, or
// ErrKMSDecryptFailed if decryption fails.
func (f *FakeKMSClient) Decrypt(_ context.Context, keyID string, ciphertext []byte) ([]byte, error) {
	f.mu.RLock()
	key, ok := f.keys[keyID]
	f.mu.RUnlock()

	if !ok {
		return nil, ErrKMSKeyNotFound
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrKMSDecryptFailed
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrKMSDecryptFailed
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize+gcm.Overhead() {
		return nil, ErrKMSDecryptFailed
	}

	nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, ErrKMSDecryptFailed
	}
	return plaintext, nil
}

// getOrCreateKey returns the key for keyID, creating a new random key if none
// exists. Thread-safe via double-checked locking.
func (f *FakeKMSClient) getOrCreateKey(keyID string) ([]byte, error) {
	// Fast path: key already exists.
	f.mu.RLock()
	key, ok := f.keys[keyID]
	f.mu.RUnlock()
	if ok {
		return key, nil
	}

	// Slow path: generate new key under write lock.
	f.mu.Lock()
	defer f.mu.Unlock()

	// Double-check after acquiring write lock.
	if key, ok := f.keys[keyID]; ok {
		return key, nil
	}

	newKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, newKey); err != nil {
		return nil, fmt.Errorf("crypto: FakeKMSClient: key generation: %w", err)
	}
	f.keys[keyID] = newKey
	return newKey, nil
}

// HasKey reports whether a key exists for the given keyID. Useful in tests to
// verify lazy key creation behavior.
func (f *FakeKMSClient) HasKey(keyID string) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	_, ok := f.keys[keyID]
	return ok
}

// KeyCount returns the number of keys currently held. Useful in tests.
func (f *FakeKMSClient) KeyCount() int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return len(f.keys)
}
