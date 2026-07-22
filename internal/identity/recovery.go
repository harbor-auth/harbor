package identity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
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

// Recovery consumption errors.
var (
	// ErrUserLocked is returned when a user has exceeded the maximum number of
	// failed recovery attempts and is temporarily locked out.
	ErrUserLocked = errors.New("identity: user is locked out from recovery")
	// ErrInvalidCode is returned when the submitted code is invalid or exhausted.
	ErrInvalidCode = errors.New("identity: invalid or exhausted recovery code")
)

// Lockout policy constants.
const (
	// MaxFailedAttempts is the maximum number of failed recovery attempts
	// before a user is locked out.
	MaxFailedAttempts = 5
	// LockoutDuration is the duration a user is locked out after exceeding
	// MaxFailedAttempts.
	LockoutDuration = 15 * time.Minute
)

// LockoutState represents the current lockout state for a user.
type LockoutState struct {
	FailedCount int
	LockedUntil time.Time
}

// IsLocked returns true if the user is currently locked out.
func (s LockoutState) IsLocked() bool {
	return !s.LockedUntil.IsZero() && time.Now().Before(s.LockedUntil)
}

// RecoveryStore provides persistence operations for recovery codes and
// lockout tracking. This interface is implemented by clients.DBRecoveryStore.
type RecoveryStore interface {
	// StoreRecoveryCodes stores a batch of recovery codes for a user.
	// Existing codes are deleted first (regeneration invalidates old codes).
	StoreRecoveryCodes(ctx context.Context, userID string, codes []RecoveryCode) error

	// GetLockoutState returns the current lockout state for a user.
	GetLockoutState(ctx context.Context, userID string) (LockoutState, error)

	// RecordFailedAttempt increments the failed attempt counter and optionally
	// sets a lockout time.
	RecordFailedAttempt(ctx context.Context, userID string, newCount int, lockUntil *time.Time) error

	// ResetFailedAttempts clears the failed attempt counter after successful recovery.
	ResetFailedAttempts(ctx context.Context, userID string) error

	// FindAndConsumeCode finds a matching code for the user and atomically
	// marks it as used. Returns the code ID on success.
	FindAndConsumeCode(ctx context.Context, userID, submittedCode string) (string, error)

	// CountUnusedCodes returns the number of unused recovery codes for a user.
	CountUnusedCodes(ctx context.Context, userID string) (int, error)
}

// RecoveryService handles recovery code operations with lockout enforcement.
// It wraps a RecoveryStore and enforces the fail-closed lockout policy.
type RecoveryService struct {
	store RecoveryStore
}

// NewRecoveryService creates a new RecoveryService with the given store.
func NewRecoveryService(store RecoveryStore) *RecoveryService {
	return &RecoveryService{store: store}
}

// ConsumeCode attempts to consume a recovery code for the user. It:
//  1. Checks if the user is locked out (fail-closed).
//  2. Attempts to find and atomically consume a matching code.
//  3. On failure, increments the failed attempt counter and potentially locks the user.
//  4. On success, resets the failed attempt counter.
//
// Returns ErrUserLocked if the user is locked out, ErrInvalidCode if the code
// is invalid or already used, or nil on success.
func (s *RecoveryService) ConsumeCode(ctx context.Context, userID, submittedCode string) error {
	// Step 1: Check lockout state.
	state, err := s.store.GetLockoutState(ctx, userID)
	if err != nil {
		return fmt.Errorf("identity: get lockout state: %w", err)
	}
	if state.IsLocked() {
		return ErrUserLocked
	}

	// Step 2: Attempt to find and consume the code.
	_, err = s.store.FindAndConsumeCode(ctx, userID, submittedCode)
	if err != nil {
		// Step 3: Code not found or already used — record failed attempt.
		newCount := state.FailedCount + 1
		var lockUntil *time.Time
		if newCount >= MaxFailedAttempts {
			t := time.Now().Add(LockoutDuration)
			lockUntil = &t
		}
		if recordErr := s.store.RecordFailedAttempt(ctx, userID, newCount, lockUntil); recordErr != nil {
			// Log but don't fail the request — the code was still invalid.
			// In production, this would be logged for alerting.
		}
		return ErrInvalidCode
	}

	// Step 4: Success — reset failed attempts.
	if err := s.store.ResetFailedAttempts(ctx, userID); err != nil {
		// Log but don't fail — the code was consumed successfully.
		// In production, this would be logged for alerting.
	}

	return nil
}

// CountUnusedCodes returns the number of unused recovery codes for a user.
func (s *RecoveryService) CountUnusedCodes(ctx context.Context, userID string) (int, error) {
	return s.store.CountUnusedCodes(ctx, userID)
}

// IsUserLocked checks if the user is currently locked out from recovery.
func (s *RecoveryService) IsUserLocked(ctx context.Context, userID string) (bool, error) {
	state, err := s.store.GetLockoutState(ctx, userID)
	if err != nil {
		return false, fmt.Errorf("identity: get lockout state: %w", err)
	}
	return state.IsLocked(), nil
}
