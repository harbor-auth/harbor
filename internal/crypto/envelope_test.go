package crypto

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
)

// --- GenerateDEK tests ---

//harbor:invariant INV-DEK-CSPRNG
func TestGenerateDEKNeverZero(t *testing.T) {
	for i := 0; i < 100; i++ {
		dek, err := GenerateDEK()
		if err != nil {
			t.Fatalf("GenerateDEK() error = %v", err)
		}
		if dek == (DEK{}) {
			t.Fatal("GenerateDEK returned all-zero DEK")
		}
	}
}

// TestEncryptUniqueNonces verifies that two encryptions of identical plaintext
// differ (unique CSPRNG nonces per call).
//
//harbor:invariant INV-DEK-CSPRNG
func TestEncryptUniqueNonces(t *testing.T) {
	dek, err := GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK: %v", err)
	}
	c := NewCipher()
	plaintext := []byte("harbor test plaintext")
	aad := []byte("test-aad")
	ct1, err := c.Encrypt(dek, plaintext, aad)
	if err != nil {
		t.Fatalf("Encrypt#1: %v", err)
	}
	ct2, err := c.Encrypt(dek, plaintext, aad)
	if err != nil {
		t.Fatalf("Encrypt#2: %v", err)
	}
	if bytes.Equal(ct1, ct2) {
		t.Fatal("two Encrypt calls with the same plaintext produced identical output (nonce reuse!)")
	}
}

// TestEncryptRNGFailure verifies Encrypt fails closed with ErrRandFailure when
// the nonce source is unavailable, rather than emitting a zero/degenerate nonce.
func TestEncryptRNGFailure(t *testing.T) {
	dek, err := GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK: %v", err)
	}
	c := FailingCipher(errors.New("simulated RNG failure"))
	_, err = c.Encrypt(dek, []byte("data"), nil)
	if !errors.Is(err, ErrRandFailure) {
		t.Fatalf("Encrypt with failing RNG: got %v, want ErrRandFailure", err)
	}
}

// --- Round-trip tests ---

func TestEncryptDecryptRoundTrip(t *testing.T) {
	dek, err := GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK: %v", err)
	}
	c := NewCipher()
	cases := []struct {
		name      string
		plaintext []byte
		aad       []byte
	}{
		{"empty plaintext", []byte{}, []byte("aad")},
		{"short plaintext", []byte("hello"), nil},
		{"binary data", []byte{0x00, 0xff, 0x01, 0xfe}, []byte("binary-aad")},
		{"1KB plaintext", make([]byte, 1024), []byte("big")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ct, err := c.Encrypt(dek, tc.plaintext, tc.aad)
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}
			if len(ct) < minCipherLen {
				t.Fatalf("ciphertext too short: got %d, want >= %d", len(ct), minCipherLen)
			}
			pt, err := c.Decrypt(dek, ct, tc.aad)
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}
			if !bytes.Equal(pt, tc.plaintext) {
				t.Fatalf("round-trip mismatch: got %x, want %x", pt, tc.plaintext)
			}
		})
	}
}

func TestEncryptOutputLayoutNoncePrepended(t *testing.T) {
	dek, err := GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK: %v", err)
	}
	c := NewCipher()
	pt := []byte("layout-test")
	ct, err := c.Encrypt(dek, pt, nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	// Layout must be nonce (12) + ciphertext (len pt) + GCM tag (16).
	if len(ct) != gcmNonceSize+len(pt)+16 {
		t.Fatalf("ciphertext length = %d, want %d (nonce+plaintext+tag)",
			len(ct), gcmNonceSize+len(pt)+16)
	}
}

// --- Fail-closed tests ---

//harbor:invariant INV-DEK-FAIL-CLOSED
func TestDecryptFailClosed(t *testing.T) {
	dek, err := GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK: %v", err)
	}
	c := NewCipher()
	plaintext := []byte("sensitive")
	aad := []byte("ctx")
	ct, err := c.Encrypt(dek, plaintext, aad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// assertFail asserts ErrDecryptFailed with nil plaintext (no partial output).
	assertFail := func(t *testing.T, name string, got []byte, err error) {
		t.Helper()
		if !errors.Is(err, ErrDecryptFailed) {
			t.Errorf("%s: error = %v, want ErrDecryptFailed", name, err)
		}
		if got != nil {
			t.Errorf("%s: plaintext must be nil on failure, got %x", name, got)
		}
	}

	t.Run("tampered ciphertext byte", func(t *testing.T) {
		tampered := append([]byte(nil), ct...)
		tampered[len(tampered)-1] ^= 0xff
		got, err := c.Decrypt(dek, tampered, aad)
		assertFail(t, "tampered", got, err)
	})

	t.Run("tampered nonce byte", func(t *testing.T) {
		tampered := append([]byte(nil), ct...)
		tampered[0] ^= 0xff
		got, err := c.Decrypt(dek, tampered, aad)
		assertFail(t, "tampered nonce", got, err)
	})

	t.Run("wrong AAD", func(t *testing.T) {
		got, err := c.Decrypt(dek, ct, []byte("wrong-aad"))
		assertFail(t, "wrong AAD", got, err)
	})

	t.Run("nil AAD when AAD was set", func(t *testing.T) {
		got, err := c.Decrypt(dek, ct, nil)
		assertFail(t, "nil AAD", got, err)
	})

	t.Run("wrong DEK", func(t *testing.T) {
		wrongDEK, err := GenerateDEK()
		if err != nil {
			t.Fatalf("GenerateDEK (wrongDEK): %v", err)
		}
		got, err := c.Decrypt(wrongDEK, ct, aad)
		assertFail(t, "wrong DEK", got, err)
	})

	t.Run("short ciphertext below minCipherLen", func(t *testing.T) {
		got, err := c.Decrypt(dek, ct[:minCipherLen-1], aad)
		assertFail(t, "short ct", got, err)
	})

	t.Run("empty ciphertext", func(t *testing.T) {
		got, err := c.Decrypt(dek, []byte{}, aad)
		assertFail(t, "empty ct", got, err)
	})

	t.Run("nil ciphertext", func(t *testing.T) {
		got, err := c.Decrypt(dek, nil, aad)
		assertFail(t, "nil ct", got, err)
	})
}

// --- Corrupted ciphertext tests ---

// TestDecryptCorruptedGCMTag verifies that corrupting ANY byte of the GCM tag
// returns ErrDecryptFailed with nil plaintext (no partial output).
//
//harbor:invariant INV-DEK-FAIL-CLOSED
func TestDecryptCorruptedGCMTag(t *testing.T) {
	dek, err := GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK: %v", err)
	}
	c := NewCipher()
	plaintext := []byte("sensitive data that must not leak")
	aad := []byte("context")
	ct, err := c.Encrypt(dek, plaintext, aad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// GCM tag is the last 16 bytes of the ciphertext.
	tagStart := len(ct) - 16

	// Corrupt each byte of the GCM tag and verify decryption fails with nil plaintext.
	for i := 0; i < 16; i++ {
		t.Run(fmt.Sprintf("tag byte %d", i), func(t *testing.T) {
			corrupted := append([]byte(nil), ct...)
			corrupted[tagStart+i] ^= 0xff
			got, err := c.Decrypt(dek, corrupted, aad)
			if !errors.Is(err, ErrDecryptFailed) {
				t.Errorf("corrupted tag byte %d: error = %v, want ErrDecryptFailed", i, err)
			}
			if got != nil {
				t.Errorf("corrupted tag byte %d: plaintext must be nil, got %x", i, got)
			}
		})
	}
}

// TestDecryptCorruptedCiphertextBody verifies that corrupting the ciphertext body
// (between nonce and tag) returns ErrDecryptFailed with nil plaintext.
//
//harbor:invariant INV-DEK-FAIL-CLOSED
func TestDecryptCorruptedCiphertextBody(t *testing.T) {
	dek, err := GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK: %v", err)
	}
	c := NewCipher()
	plaintext := []byte("this is longer plaintext to have a body to corrupt")
	aad := []byte("aad")
	ct, err := c.Encrypt(dek, plaintext, aad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Body is between nonce (first 12 bytes) and tag (last 16 bytes).
	bodyStart := gcmNonceSize
	bodyEnd := len(ct) - 16

	// Corrupt a few bytes in the body.
	for _, offset := range []int{0, (bodyEnd - bodyStart) / 2, bodyEnd - bodyStart - 1} {
		t.Run(fmt.Sprintf("body offset %d", offset), func(t *testing.T) {
			corrupted := append([]byte(nil), ct...)
			corrupted[bodyStart+offset] ^= 0xff
			got, err := c.Decrypt(dek, corrupted, aad)
			if !errors.Is(err, ErrDecryptFailed) {
				t.Errorf("corrupted body offset %d: error = %v, want ErrDecryptFailed", offset, err)
			}
			if got != nil {
				t.Errorf("corrupted body offset %d: plaintext must be nil, got %x", offset, got)
			}
		})
	}
}

// TestDecryptTruncatedCiphertext verifies that truncating the ciphertext at various
// points returns ErrDecryptFailed with nil plaintext.
//
//harbor:invariant INV-DEK-FAIL-CLOSED
func TestDecryptTruncatedCiphertext(t *testing.T) {
	dek, err := GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK: %v", err)
	}
	c := NewCipher()
	plaintext := []byte("truncation test data")
	aad := []byte("aad")
	ct, err := c.Encrypt(dek, plaintext, aad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Try various truncation lengths.
	truncations := []int{0, 1, gcmNonceSize - 1, gcmNonceSize, minCipherLen - 1, len(ct) - 1}
	for _, truncLen := range truncations {
		if truncLen < 0 || truncLen >= len(ct) {
			continue
		}
		t.Run(fmt.Sprintf("truncate to %d bytes", truncLen), func(t *testing.T) {
			truncated := ct[:truncLen]
			got, err := c.Decrypt(dek, truncated, aad)
			if !errors.Is(err, ErrDecryptFailed) {
				t.Errorf("truncated to %d: error = %v, want ErrDecryptFailed", truncLen, err)
			}
			if got != nil {
				t.Errorf("truncated to %d: plaintext must be nil, got %x", truncLen, got)
			}
		})
	}
}

// TestDecryptExtendedCiphertext verifies that appending garbage bytes to valid
// ciphertext returns ErrDecryptFailed with nil plaintext (tag verification fails
// because the extra bytes alter the authenticated data).
//
//harbor:invariant INV-DEK-FAIL-CLOSED
func TestDecryptExtendedCiphertext(t *testing.T) {
	dek, err := GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK: %v", err)
	}
	c := NewCipher()
	plaintext := []byte("extend test")
	aad := []byte("aad")
	ct, err := c.Encrypt(dek, plaintext, aad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Append garbage bytes.
	extended := append(ct, 0x00, 0x01, 0x02, 0x03)
	got, err := c.Decrypt(dek, extended, aad)
	if !errors.Is(err, ErrDecryptFailed) {
		t.Errorf("extended ciphertext: error = %v, want ErrDecryptFailed", err)
	}
	if got != nil {
		t.Errorf("extended ciphertext: plaintext must be nil, got %x", got)
	}
}

// TestDecryptAllZeroCiphertext verifies that an all-zero ciphertext (of valid length)
// returns ErrDecryptFailed with nil plaintext.
//
//harbor:invariant INV-DEK-FAIL-CLOSED
func TestDecryptAllZeroCiphertext(t *testing.T) {
	dek, err := GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK: %v", err)
	}
	c := NewCipher()

	// Create a ciphertext of valid length but all zeros.
	allZeros := make([]byte, minCipherLen+10)
	got, err := c.Decrypt(dek, allZeros, nil)
	if !errors.Is(err, ErrDecryptFailed) {
		t.Errorf("all-zero ciphertext: error = %v, want ErrDecryptFailed", err)
	}
	if got != nil {
		t.Errorf("all-zero ciphertext: plaintext must be nil, got %x", got)
	}
}

// TestDecryptGoldenVector verifies round-trip correctness with a deterministic
// injected nonce. Unlike TestCryptoGoldenVectors (which freezes the exact ciphertext
// bytes via testdata/gcm_vectors.json), this test only checks that Decrypt
// recovers the original plaintext — it does NOT pin ciphertext bytes to a frozen
// hex value. Use it to catch AES key setup or output layout regressions.
func TestDecryptGoldenVector(t *testing.T) {
	var dek DEK
	for i := range dek {
		dek[i] = 0x01
	}
	fixedNonce := bytes.Repeat([]byte{0x02}, gcmNonceSize)
	plaintext := []byte("hello, harbor")
	aad := []byte("test-aad")

	c := testCipher(fixedNonce)
	ct, err := c.Encrypt(dek, plaintext, aad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if !bytes.Equal(ct[:gcmNonceSize], fixedNonce) {
		t.Fatalf("nonce prefix = %x, want %x", ct[:gcmNonceSize], fixedNonce)
	}
	got, err := c.Decrypt(dek, ct, aad)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("golden round-trip mismatch: got %q, want %q", got, plaintext)
	}
}
