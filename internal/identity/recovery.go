package identity

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"io"
	"strings"
)

const (
	// DefaultCodeCount is the number of recovery codes generated per user.
	DefaultCodeCount = 10
	// codeEntropyBytes is the number of random bytes per code (≥128 bits).
	codeEntropyBytes = 20
	// saltBytes is the number of random bytes for per-code salt.
	saltBytes = 16
)

// RecoveryCode represents a single recovery code with its hash and salt.
// The plaintext is only available at generation time and is never persisted.
type RecoveryCode struct {
	// Plaintext is the human-readable code shown once to the user.
	// This field is only populated at generation time; it is never stored.
	Plaintext string
	// Hash is the salted SHA-256 hash of the plaintext code.
	Hash []byte
	// Salt is the per-code salt used in the hash.
	Salt []byte
}

// RecoveryCodeGenerator generates recovery codes with cryptographic randomness.
type RecoveryCodeGenerator interface {
	// GenerateCodes generates n single-use recovery codes.
	// Each code has ≥128 bits entropy, is base32-encoded for human readability,
	// and is returned with its salted hash. The plaintext is shown once to the
	// user and never persisted.
	GenerateCodes(n int) ([]RecoveryCode, error)
}

// RecoveryManager implements RecoveryCodeGenerator and provides recovery code
// operations. It generates high-entropy codes, salts each one, and stores only
// the salted SHA-256 hash — never the plaintext (docs/DESIGN.md §10).
type RecoveryManager struct {
	rand io.Reader
}

// NewRecoveryManager creates a new RecoveryManager backed by crypto/rand.
func NewRecoveryManager() *RecoveryManager {
	return &RecoveryManager{rand: rand.Reader}
}

// newRecoveryManagerWithRand creates a RecoveryManager with a custom random
// source. This is only used for testing with deterministic randomness.
func newRecoveryManagerWithRand(r io.Reader) *RecoveryManager {
	return &RecoveryManager{rand: r}
}

// GenerateCodes generates n single-use recovery codes. Each code:
//   - Has ≥128 bits entropy (20 random bytes = 160 bits)
//   - Is base32-encoded without padding for human readability
//   - Is formatted with hyphens every 4 characters for easier transcription
//   - Is salted with 16 random bytes
//   - Is stored as a salted SHA-256 hash (never plaintext)
//
// The plaintext is returned in RecoveryCode.Plaintext for one-time display to
// the user; callers must never persist it.
func (m *RecoveryManager) GenerateCodes(n int) ([]RecoveryCode, error) {
	if n <= 0 {
		return nil, fmt.Errorf("identity: code count must be positive, got %d", n)
	}

	codes := make([]RecoveryCode, 0, n)
	for i := 0; i < n; i++ {
		code, err := m.generateSingleCode()
		if err != nil {
			return nil, fmt.Errorf("identity: generate code %d: %w", i, err)
		}
		codes = append(codes, code)
	}
	return codes, nil
}

// generateSingleCode generates one recovery code with its salt and hash.
func (m *RecoveryManager) generateSingleCode() (RecoveryCode, error) {
	// Generate random bytes for the code (160 bits of entropy).
	codeBytes := make([]byte, codeEntropyBytes)
	if _, err := io.ReadFull(m.rand, codeBytes); err != nil {
		return RecoveryCode{}, fmt.Errorf("read random for code: %w", err)
	}

	// Generate salt (128 bits).
	salt := make([]byte, saltBytes)
	if _, err := io.ReadFull(m.rand, salt); err != nil {
		return RecoveryCode{}, fmt.Errorf("read random for salt: %w", err)
	}

	// Encode as base32 (no padding). This is the canonical form used for hashing.
	canonical := strings.ToUpper(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(codeBytes))

	// Format with hyphens for human readability (display only).
	plaintext := formatCode(canonical)

	// Compute salted hash of the canonical (no-hyphen) form so verification
	// works regardless of how the user enters the code.
	hash := saltedHash(canonical, salt)

	return RecoveryCode{
		Plaintext: plaintext,
		Hash:      hash,
		Salt:      salt,
	}, nil
}

// formatCode formats a base32 string with hyphens every 4 characters for
// human readability. Example: "ABCD1234EFGH5678" -> "ABCD-1234-EFGH-5678"
func formatCode(s string) string {
	s = strings.ToUpper(s)
	var builder strings.Builder
	for i, c := range s {
		if i > 0 && i%4 == 0 {
			builder.WriteByte('-')
		}
		builder.WriteRune(c)
	}
	return builder.String()
}

// saltedHash computes SHA-256(salt || plaintext). This is the hash stored in
// the database; the plaintext is never persisted.
func saltedHash(plaintext string, salt []byte) []byte {
	h := sha256.New()
	h.Write(salt)
	h.Write([]byte(plaintext))
	return h.Sum(nil)
}

// VerifyCode checks if a submitted code matches a stored hash and salt.
// Returns true if the code is valid, false otherwise.
func VerifyCode(submittedCode string, storedHash, salt []byte) bool {
	// Normalize the submitted code (uppercase, remove spaces/hyphens for flexibility).
	normalized := normalizeCode(submittedCode)
	computedHash := saltedHash(normalized, salt)

	// Constant-time comparison to prevent timing attacks.
	if len(computedHash) != len(storedHash) {
		return false
	}
	var diff byte
	for i := range computedHash {
		diff |= computedHash[i] ^ storedHash[i]
	}
	return diff == 0
}

// normalizeCode normalizes a user-submitted code by uppercasing and removing
// common separators (hyphens, spaces) that users might add or omit.
func normalizeCode(code string) string {
	code = strings.ToUpper(code)
	code = strings.ReplaceAll(code, "-", "")
	code = strings.ReplaceAll(code, " ", "")
	return code
}
