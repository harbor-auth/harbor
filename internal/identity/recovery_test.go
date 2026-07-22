package identity

import (
	"bytes"
	"crypto/sha256"
	"io"
	"strings"
	"testing"
)

func TestGenerateCodesCount(t *testing.T) {
	m := NewRecoveryManager()
	codes, err := m.GenerateCodes(10)
	if err != nil {
		t.Fatalf("GenerateCodes: %v", err)
	}
	if len(codes) != 10 {
		t.Fatalf("got %d codes, want 10", len(codes))
	}
}

func TestGenerateCodesZeroOrNegative(t *testing.T) {
	m := NewRecoveryManager()
	if _, err := m.GenerateCodes(0); err == nil {
		t.Fatal("expected error for 0 codes")
	}
	if _, err := m.GenerateCodes(-1); err == nil {
		t.Fatal("expected error for negative codes")
	}
}

// TestGenerateCodesEntropy verifies that each code has sufficient entropy:
// 20 random bytes = 160 bits, base32-encoded = 32 characters.
//
//harbor:invariant INV-RECOVERY-CODE-ENTROPY
func TestGenerateCodesEntropy(t *testing.T) {
	m := NewRecoveryManager()
	codes, err := m.GenerateCodes(5)
	if err != nil {
		t.Fatalf("GenerateCodes: %v", err)
	}
	for i, code := range codes {
		// Remove hyphens to count actual characters.
		plain := strings.ReplaceAll(code.Plaintext, "-", "")
		// 20 bytes base32-encoded = 32 characters.
		if len(plain) != 32 {
			t.Errorf("code %d: got %d chars (without hyphens), want 32", i, len(plain))
		}
	}
}

// TestGenerateCodesUnique verifies that generated codes are unique (no collisions).
//
//harbor:invariant INV-RECOVERY-CODE-UNIQUE
func TestGenerateCodesUnique(t *testing.T) {
	m := NewRecoveryManager()
	codes, err := m.GenerateCodes(100)
	if err != nil {
		t.Fatalf("GenerateCodes: %v", err)
	}
	seen := make(map[string]bool)
	for i, code := range codes {
		if seen[code.Plaintext] {
			t.Fatalf("code %d is a duplicate", i)
		}
		seen[code.Plaintext] = true
	}
}

// TestGenerateCodesSaltUnique verifies that each code has a unique salt.
//
//harbor:invariant INV-RECOVERY-SALT-UNIQUE
func TestGenerateCodesSaltUnique(t *testing.T) {
	m := NewRecoveryManager()
	codes, err := m.GenerateCodes(100)
	if err != nil {
		t.Fatalf("GenerateCodes: %v", err)
	}
	seen := make(map[string]bool)
	for i, code := range codes {
		key := string(code.Salt)
		if seen[key] {
			t.Fatalf("code %d has duplicate salt", i)
		}
		seen[key] = true
	}
}

// TestGenerateCodesHashLength verifies that hashes are SHA-256 (32 bytes).
func TestGenerateCodesHashLength(t *testing.T) {
	m := NewRecoveryManager()
	codes, err := m.GenerateCodes(5)
	if err != nil {
		t.Fatalf("GenerateCodes: %v", err)
	}
	for i, code := range codes {
		if len(code.Hash) != sha256.Size {
			t.Errorf("code %d: hash is %d bytes, want %d", i, len(code.Hash), sha256.Size)
		}
	}
}

// TestGenerateCodesSaltLength verifies that salts are 16 bytes.
func TestGenerateCodesSaltLength(t *testing.T) {
	m := NewRecoveryManager()
	codes, err := m.GenerateCodes(5)
	if err != nil {
		t.Fatalf("GenerateCodes: %v", err)
	}
	for i, code := range codes {
		if len(code.Salt) != saltBytes {
			t.Errorf("code %d: salt is %d bytes, want %d", i, len(code.Salt), saltBytes)
		}
	}
}

// TestGenerateCodesFormat verifies that codes are formatted with hyphens.
func TestGenerateCodesFormat(t *testing.T) {
	m := NewRecoveryManager()
	codes, err := m.GenerateCodes(5)
	if err != nil {
		t.Fatalf("GenerateCodes: %v", err)
	}
	for i, code := range codes {
		// Should contain hyphens.
		if !strings.Contains(code.Plaintext, "-") {
			t.Errorf("code %d: expected hyphens in %q", i, code.Plaintext)
		}
		// Should be uppercase.
		if code.Plaintext != strings.ToUpper(code.Plaintext) {
			t.Errorf("code %d: expected uppercase, got %q", i, code.Plaintext)
		}
	}
}

// TestSaltedHashDeterministic verifies that the same input produces the same hash.
func TestSaltedHashDeterministic(t *testing.T) {
	salt := []byte("fixed-salt-1234!")
	plaintext := "ABCD-1234-EFGH-5678"

	h1 := saltedHash(plaintext, salt)
	h2 := saltedHash(plaintext, salt)

	if !bytes.Equal(h1, h2) {
		t.Fatal("saltedHash is not deterministic")
	}
}

// TestSaltedHashDifferentSalts verifies that different salts produce different hashes.
func TestSaltedHashDifferentSalts(t *testing.T) {
	salt1 := []byte("salt-one-1234567")
	salt2 := []byte("salt-two-1234567")
	plaintext := "ABCD-1234-EFGH-5678"

	h1 := saltedHash(plaintext, salt1)
	h2 := saltedHash(plaintext, salt2)

	if bytes.Equal(h1, h2) {
		t.Fatal("different salts should produce different hashes")
	}
}

// TestVerifyCodeSuccess verifies that a correct code is accepted.
func TestVerifyCodeSuccess(t *testing.T) {
	m := NewRecoveryManager()
	codes, err := m.GenerateCodes(1)
	if err != nil {
		t.Fatalf("GenerateCodes: %v", err)
	}
	code := codes[0]

	if !VerifyCode(code.Plaintext, code.Hash, code.Salt) {
		t.Fatal("VerifyCode should accept the correct code")
	}
}

// TestVerifyCodeWrongCode verifies that an incorrect code is rejected.
func TestVerifyCodeWrongCode(t *testing.T) {
	m := NewRecoveryManager()
	codes, err := m.GenerateCodes(1)
	if err != nil {
		t.Fatalf("GenerateCodes: %v", err)
	}
	code := codes[0]

	if VerifyCode("WRONG-CODE-1234-5678", code.Hash, code.Salt) {
		t.Fatal("VerifyCode should reject an incorrect code")
	}
}

// TestVerifyCodeWrongSalt verifies that the wrong salt causes rejection.
func TestVerifyCodeWrongSalt(t *testing.T) {
	m := NewRecoveryManager()
	codes, err := m.GenerateCodes(1)
	if err != nil {
		t.Fatalf("GenerateCodes: %v", err)
	}
	code := codes[0]

	wrongSalt := []byte("wrong-salt-12345")
	if VerifyCode(code.Plaintext, code.Hash, wrongSalt) {
		t.Fatal("VerifyCode should reject with wrong salt")
	}
}

// TestVerifyCodeNormalization verifies that codes are normalized before verification.
func TestVerifyCodeNormalization(t *testing.T) {
	m := NewRecoveryManager()
	codes, err := m.GenerateCodes(1)
	if err != nil {
		t.Fatalf("GenerateCodes: %v", err)
	}
	code := codes[0]

	// Test lowercase input.
	if !VerifyCode(strings.ToLower(code.Plaintext), code.Hash, code.Salt) {
		t.Fatal("VerifyCode should accept lowercase input")
	}

	// Test without hyphens.
	noHyphens := strings.ReplaceAll(code.Plaintext, "-", "")
	if !VerifyCode(noHyphens, code.Hash, code.Salt) {
		t.Fatal("VerifyCode should accept input without hyphens")
	}

	// Test with spaces instead of hyphens.
	withSpaces := strings.ReplaceAll(code.Plaintext, "-", " ")
	if !VerifyCode(withSpaces, code.Hash, code.Salt) {
		t.Fatal("VerifyCode should accept input with spaces instead of hyphens")
	}
}

// TestFormatCode verifies the hyphen formatting.
func TestFormatCode(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"ABCDEFGH", "ABCD-EFGH"},
		{"ABCDEFGHIJKLMNOP", "ABCD-EFGH-IJKL-MNOP"},
		{"ABC", "ABC"},
		{"ABCD", "ABCD"},
		{"ABCDE", "ABCD-E"},
	}
	for _, tt := range tests {
		got := formatCode(tt.input)
		if got != tt.want {
			t.Errorf("formatCode(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// TestNormalizeCode verifies code normalization.
func TestNormalizeCode(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"abcd-efgh", "ABCDEFGH"},
		{"ABCD-EFGH", "ABCDEFGH"},
		{"abcd efgh", "ABCDEFGH"},
		{"ABCD EFGH", "ABCDEFGH"},
		{"a-b c-d", "ABCD"},
	}
	for _, tt := range tests {
		got := normalizeCode(tt.input)
		if got != tt.want {
			t.Errorf("normalizeCode(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// TestGenerateCodesRandError verifies that RNG failure is handled.
func TestGenerateCodesRandError(t *testing.T) {
	m := newRecoveryManagerWithRand(&failingReader{})
	_, err := m.GenerateCodes(1)
	if err == nil {
		t.Fatal("expected error when RNG fails")
	}
}

// failingReader is an io.Reader that always returns an error.
type failingReader struct{}

func (f *failingReader) Read(p []byte) (n int, err error) {
	return 0, io.ErrUnexpectedEOF
}

// TestGenerateCodesDeterministic verifies that with a fixed random source,
// codes are deterministic (for testing purposes).
func TestGenerateCodesDeterministic(t *testing.T) {
	// Use a deterministic reader.
	r1 := &deterministicReader{seed: 42}
	r2 := &deterministicReader{seed: 42}

	m1 := newRecoveryManagerWithRand(r1)
	m2 := newRecoveryManagerWithRand(r2)

	codes1, err := m1.GenerateCodes(3)
	if err != nil {
		t.Fatalf("GenerateCodes: %v", err)
	}
	codes2, err := m2.GenerateCodes(3)
	if err != nil {
		t.Fatalf("GenerateCodes: %v", err)
	}

	for i := range codes1 {
		if codes1[i].Plaintext != codes2[i].Plaintext {
			t.Errorf("code %d: plaintexts differ", i)
		}
		if !bytes.Equal(codes1[i].Hash, codes2[i].Hash) {
			t.Errorf("code %d: hashes differ", i)
		}
		if !bytes.Equal(codes1[i].Salt, codes2[i].Salt) {
			t.Errorf("code %d: salts differ", i)
		}
	}
}

// deterministicReader is a simple deterministic pseudo-random reader for testing.
type deterministicReader struct {
	seed byte
}

func (d *deterministicReader) Read(p []byte) (n int, err error) {
	for i := range p {
		d.seed = d.seed*31 + 17
		p[i] = d.seed
	}
	return len(p), nil
}
