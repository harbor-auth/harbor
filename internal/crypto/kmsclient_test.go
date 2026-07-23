package crypto

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
)

var kmsTestCtx = context.Background()

// --- FakeKMSClient tests ---

func TestFakeKMSClientEncryptDecryptRoundTrip(t *testing.T) {
	client := NewFakeKMSClient()
	keyID := "test-key-1"
	plaintext := []byte("secret data for encryption")

	ciphertext, err := client.Encrypt(kmsTestCtx, keyID, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Ciphertext must not contain plaintext in the clear.
	if bytes.Contains(ciphertext, plaintext) {
		t.Fatal("ciphertext contains plaintext in the clear")
	}

	// Ciphertext must be longer than plaintext (nonce + tag overhead).
	if len(ciphertext) <= len(plaintext) {
		t.Fatalf("ciphertext len %d <= plaintext len %d", len(ciphertext), len(plaintext))
	}

	decrypted, err := client.Decrypt(kmsTestCtx, keyID, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("round-trip mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestFakeKMSClientEmptyPlaintext(t *testing.T) {
	client := NewFakeKMSClient()
	keyID := "test-key-empty"
	plaintext := []byte{}

	ciphertext, err := client.Encrypt(kmsTestCtx, keyID, plaintext)
	if err != nil {
		t.Fatalf("Encrypt empty: %v", err)
	}

	decrypted, err := client.Decrypt(kmsTestCtx, keyID, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt empty: %v", err)
	}

	if len(decrypted) != 0 {
		t.Fatalf("expected empty plaintext, got %d bytes", len(decrypted))
	}
}

func TestFakeKMSClientKeyIsolation(t *testing.T) {
	client := NewFakeKMSClient()
	keyID1 := "key-alpha"
	keyID2 := "key-beta"
	plaintext := []byte("isolated data")

	ct1, err := client.Encrypt(kmsTestCtx, keyID1, plaintext)
	if err != nil {
		t.Fatalf("Encrypt key1: %v", err)
	}

	// Decrypting with a different keyID must fail.
	_, err = client.Decrypt(kmsTestCtx, keyID2, ct1)
	if !errors.Is(err, ErrKMSKeyNotFound) {
		t.Fatalf("cross-key decrypt: error = %v, want ErrKMSKeyNotFound", err)
	}
}

func TestFakeKMSClientTamperedCiphertext(t *testing.T) {
	client := NewFakeKMSClient()
	keyID := "test-key-tamper"
	plaintext := []byte("tamper test data")

	ciphertext, err := client.Encrypt(kmsTestCtx, keyID, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Tamper with the last byte (GCM tag).
	tampered := append([]byte(nil), ciphertext...)
	tampered[len(tampered)-1] ^= 0xff

	_, err = client.Decrypt(kmsTestCtx, keyID, tampered)
	if !errors.Is(err, ErrKMSDecryptFailed) {
		t.Fatalf("tampered decrypt: error = %v, want ErrKMSDecryptFailed", err)
	}
}

func TestFakeKMSClientShortCiphertext(t *testing.T) {
	client := NewFakeKMSClient()
	keyID := "test-key-short"

	// First encrypt something to create the key.
	_, err := client.Encrypt(kmsTestCtx, keyID, []byte("x"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Try to decrypt a too-short ciphertext (less than nonce + tag).
	shortCT := []byte("short")
	_, err = client.Decrypt(kmsTestCtx, keyID, shortCT)
	if !errors.Is(err, ErrKMSDecryptFailed) {
		t.Fatalf("short ciphertext: error = %v, want ErrKMSDecryptFailed", err)
	}
}

func TestFakeKMSClientDecryptUnknownKey(t *testing.T) {
	client := NewFakeKMSClient()

	// Decrypt with a keyID that was never used for encryption.
	_, err := client.Decrypt(kmsTestCtx, "unknown-key", []byte("some-ciphertext"))
	if !errors.Is(err, ErrKMSKeyNotFound) {
		t.Fatalf("unknown key decrypt: error = %v, want ErrKMSKeyNotFound", err)
	}
}

func TestFakeKMSClientLazyKeyCreation(t *testing.T) {
	client := NewFakeKMSClient()
	keyID := "lazy-key"

	// Key should not exist before first encrypt.
	if client.HasKey(keyID) {
		t.Fatal("key exists before first encrypt")
	}
	if client.KeyCount() != 0 {
		t.Fatalf("KeyCount = %d, want 0", client.KeyCount())
	}

	// Encrypt creates the key lazily.
	_, err := client.Encrypt(kmsTestCtx, keyID, []byte("data"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if !client.HasKey(keyID) {
		t.Fatal("key does not exist after encrypt")
	}
	if client.KeyCount() != 1 {
		t.Fatalf("KeyCount = %d, want 1", client.KeyCount())
	}
}

func TestFakeKMSClientWithPreseededKeys(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	keys := map[string][]byte{"preset-key": key}

	client, err := NewFakeKMSClientWithKeys(keys)
	if err != nil {
		t.Fatalf("NewFakeKMSClientWithKeys: %v", err)
	}

	if !client.HasKey("preset-key") {
		t.Fatal("preset key not found")
	}

	plaintext := []byte("preset test")
	ct, err := client.Encrypt(kmsTestCtx, "preset-key", plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	pt, err := client.Decrypt(kmsTestCtx, "preset-key", ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("round-trip mismatch: got %q, want %q", pt, plaintext)
	}
}

func TestFakeKMSClientWithKeysInvalidLength(t *testing.T) {
	keys := map[string][]byte{"bad-key": make([]byte, 16)} // 16 bytes, not 32
	_, err := NewFakeKMSClientWithKeys(keys)
	if err == nil {
		t.Fatal("expected error for invalid key length, got nil")
	}
}

func TestFakeKMSClientConcurrentAccess(t *testing.T) {
	client := NewFakeKMSClient()
	const goroutines = 10
	const opsPerGoroutine = 50

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := range goroutines {
		go func(id int) {
			defer wg.Done()
			keyID := "concurrent-key"
			for j := range opsPerGoroutine {
				plaintext := []byte{byte(id), byte(j)}
				ct, err := client.Encrypt(kmsTestCtx, keyID, plaintext)
				if err != nil {
					t.Errorf("goroutine %d op %d Encrypt: %v", id, j, err)
					return
				}
				pt, err := client.Decrypt(kmsTestCtx, keyID, ct)
				if err != nil {
					t.Errorf("goroutine %d op %d Decrypt: %v", id, j, err)
					return
				}
				if !bytes.Equal(pt, plaintext) {
					t.Errorf("goroutine %d op %d mismatch", id, j)
					return
				}
			}
		}(i)
	}

	wg.Wait()
}

func TestFakeKMSClientMultipleKeys(t *testing.T) {
	client := NewFakeKMSClient()
	keys := []string{"key-a", "key-b", "key-c"}
	ciphertexts := make(map[string][]byte)
	plaintext := []byte("multi-key test")

	// Encrypt under each key.
	for _, keyID := range keys {
		ct, err := client.Encrypt(kmsTestCtx, keyID, plaintext)
		if err != nil {
			t.Fatalf("Encrypt %s: %v", keyID, err)
		}
		ciphertexts[keyID] = ct
	}

	if client.KeyCount() != 3 {
		t.Fatalf("KeyCount = %d, want 3", client.KeyCount())
	}

	// Decrypt each with its own key.
	for _, keyID := range keys {
		pt, err := client.Decrypt(kmsTestCtx, keyID, ciphertexts[keyID])
		if err != nil {
			t.Fatalf("Decrypt %s: %v", keyID, err)
		}
		if !bytes.Equal(pt, plaintext) {
			t.Fatalf("Decrypt %s mismatch", keyID)
		}
	}

	// Cross-key decryption must fail.
	_, err := client.Decrypt(kmsTestCtx, "key-a", ciphertexts["key-b"])
	if !errors.Is(err, ErrKMSDecryptFailed) {
		t.Fatalf("cross-key decrypt: error = %v, want ErrKMSDecryptFailed", err)
	}
}
