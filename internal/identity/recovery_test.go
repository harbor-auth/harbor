package identity

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"
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

// --- security invariant tests: RecoveryService ---

// storedRecoveryCode mirrors a persisted recovery code: only the salted hash,
// its salt, and a used flag — never the plaintext, matching the DB's hash-only
// storage (docs/DESIGN.md §10).
type storedRecoveryCode struct {
	hash []byte
	salt []byte
	used bool
}

// fakeRecoveryStore is an in-memory identity.RecoveryStore used to exercise the
// RecoveryService security invariants (single-use, cross-user isolation,
// fail-closed lockout) without a real database. Codes are keyed by user id, so
// one user's codes can never satisfy another user's ceremony.
type fakeRecoveryStore struct {
	codes         map[string][]*storedRecoveryCode
	lockouts      map[string]LockoutState
	getLockoutErr error
	// consumeCalls counts how many times FindAndConsumeCode was reached; it must
	// stay 0 whenever the service fails closed before checking a code.
	consumeCalls int
}

func newFakeRecoveryStore() *fakeRecoveryStore {
	return &fakeRecoveryStore{
		codes:    make(map[string][]*storedRecoveryCode),
		lockouts: make(map[string]LockoutState),
	}
}

func (f *fakeRecoveryStore) StoreRecoveryCodes(_ context.Context, userID string, codes []RecoveryCode) error {
	stored := make([]*storedRecoveryCode, 0, len(codes))
	for _, c := range codes {
		stored = append(stored, &storedRecoveryCode{hash: c.Hash, salt: c.Salt})
	}
	f.codes[userID] = stored
	return nil
}

func (f *fakeRecoveryStore) GetLockoutState(_ context.Context, userID string) (LockoutState, error) {
	if f.getLockoutErr != nil {
		return LockoutState{}, f.getLockoutErr
	}
	return f.lockouts[userID], nil
}

func (f *fakeRecoveryStore) RecordFailedAttempt(_ context.Context, userID string, newCount int, lockUntil *time.Time) error {
	st := LockoutState{FailedCount: newCount}
	if lockUntil != nil {
		st.LockedUntil = *lockUntil
	}
	f.lockouts[userID] = st
	return nil
}

func (f *fakeRecoveryStore) ResetFailedAttempts(_ context.Context, userID string) error {
	delete(f.lockouts, userID)
	return nil
}

func (f *fakeRecoveryStore) FindAndConsumeCode(_ context.Context, userID, submittedCode string) (string, error) {
	f.consumeCalls++
	// Only THIS user's codes are ever considered — cross-user isolation.
	for i, c := range f.codes[userID] {
		if c.used {
			continue
		}
		if VerifyCode(submittedCode, c.hash, c.salt) {
			c.used = true
			return fmt.Sprintf("%s-%d", userID, i), nil
		}
	}
	return "", errors.New("code not found")
}

func (f *fakeRecoveryStore) CountUnusedCodes(_ context.Context, userID string) (int, error) {
	var n int
	for _, c := range f.codes[userID] {
		if !c.used {
			n++
		}
	}
	return n, nil
}

// TestConsumeCode_SingleUse proves a recovery code is single-use: the first use
// succeeds and an immediate replay of the SAME code fails closed.
//
//harbor:invariant INV-RECOVERY-CODE-SINGLE-USE
func TestConsumeCode_SingleUse(t *testing.T) {
	mgr := NewRecoveryManager()
	codes, err := mgr.GenerateCodes(3)
	if err != nil {
		t.Fatalf("GenerateCodes: %v", err)
	}

	store := newFakeRecoveryStore()
	if err := store.StoreRecoveryCodes(context.Background(), "user-A", codes); err != nil {
		t.Fatalf("StoreRecoveryCodes: %v", err)
	}
	svc := NewRecoveryService(store)

	if err := svc.ConsumeCode(context.Background(), "user-A", codes[0].Plaintext); err != nil {
		t.Fatalf("first ConsumeCode: %v", err)
	}
	// Replay of the same code must fail closed.
	if err := svc.ConsumeCode(context.Background(), "user-A", codes[0].Plaintext); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("replay ConsumeCode = %v, want ErrInvalidCode", err)
	}
	// A different, still-unused code must still work.
	if err := svc.ConsumeCode(context.Background(), "user-A", codes[1].Plaintext); err != nil {
		t.Fatalf("second distinct code: %v", err)
	}
}

// TestConsumeCode_CrossUserRejected proves one user's recovery code cannot be
// used to recover a different account, and that the failed cross-user attempt
// does not consume the real owner's code.
//
//harbor:invariant INV-RECOVERY-CROSS-USER-REJECT
func TestConsumeCode_CrossUserRejected(t *testing.T) {
	mgr := NewRecoveryManager()
	aCodes, err := mgr.GenerateCodes(3)
	if err != nil {
		t.Fatalf("GenerateCodes(A): %v", err)
	}
	bCodes, err := mgr.GenerateCodes(3)
	if err != nil {
		t.Fatalf("GenerateCodes(B): %v", err)
	}

	store := newFakeRecoveryStore()
	if err := store.StoreRecoveryCodes(context.Background(), "user-A", aCodes); err != nil {
		t.Fatalf("StoreRecoveryCodes(A): %v", err)
	}
	if err := store.StoreRecoveryCodes(context.Background(), "user-B", bCodes); err != nil {
		t.Fatalf("StoreRecoveryCodes(B): %v", err)
	}
	svc := NewRecoveryService(store)

	// user-B submits user-A's code → rejected.
	if err := svc.ConsumeCode(context.Background(), "user-B", aCodes[0].Plaintext); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("cross-user ConsumeCode = %v, want ErrInvalidCode", err)
	}
	// user-A's own code is untouched and still valid.
	if err := svc.ConsumeCode(context.Background(), "user-A", aCodes[0].Plaintext); err != nil {
		t.Fatalf("user-A own code after cross-user attempt: %v", err)
	}
}

// TestConsumeCode_LockoutEnforcedFromStore proves the fail-closed lockout is
// enforced from the store's persisted state: a locked user is rejected with
// ErrUserLocked BEFORE any code is checked (the consume path is never reached).
//
//harbor:invariant INV-RECOVERY-LOCKOUT-ENFORCED
func TestConsumeCode_LockoutEnforcedFromStore(t *testing.T) {
	store := newFakeRecoveryStore()
	store.lockouts["user-A"] = LockoutState{
		FailedCount: MaxFailedAttempts,
		LockedUntil: time.Now().Add(LockoutDuration),
	}
	svc := NewRecoveryService(store)

	if err := svc.ConsumeCode(context.Background(), "user-A", "ANY-CODE"); !errors.Is(err, ErrUserLocked) {
		t.Fatalf("ConsumeCode while locked = %v, want ErrUserLocked", err)
	}
	if store.consumeCalls != 0 {
		t.Errorf("consume path reached %d times while locked; want 0 (fail-closed)", store.consumeCalls)
	}
}

// TestConsumeCode_ExpiredLockoutAllowsRetry proves a lockout whose window has
// elapsed no longer blocks recovery — the state is time-bounded, not permanent.
func TestConsumeCode_ExpiredLockoutAllowsRetry(t *testing.T) {
	mgr := NewRecoveryManager()
	codes, err := mgr.GenerateCodes(1)
	if err != nil {
		t.Fatalf("GenerateCodes: %v", err)
	}
	store := newFakeRecoveryStore()
	if err := store.StoreRecoveryCodes(context.Background(), "user-A", codes); err != nil {
		t.Fatalf("StoreRecoveryCodes: %v", err)
	}
	// Lockout already expired.
	store.lockouts["user-A"] = LockoutState{
		FailedCount: MaxFailedAttempts,
		LockedUntil: time.Now().Add(-time.Minute),
	}
	svc := NewRecoveryService(store)

	if err := svc.ConsumeCode(context.Background(), "user-A", codes[0].Plaintext); err != nil {
		t.Fatalf("ConsumeCode after lockout expiry = %v, want success", err)
	}
}

// TestConsumeCode_FailClosedLocksAfterMaxAttempts proves invalid codes fail
// closed: after MaxFailedAttempts consecutive failures the account is locked,
// and even a subsequent CORRECT code is rejected while the lockout holds.
//
//harbor:invariant INV-RECOVERY-FAIL-CLOSED
func TestConsumeCode_FailClosedLocksAfterMaxAttempts(t *testing.T) {
	mgr := NewRecoveryManager()
	codes, err := mgr.GenerateCodes(1)
	if err != nil {
		t.Fatalf("GenerateCodes: %v", err)
	}
	store := newFakeRecoveryStore()
	if err := store.StoreRecoveryCodes(context.Background(), "user-A", codes); err != nil {
		t.Fatalf("StoreRecoveryCodes: %v", err)
	}
	svc := NewRecoveryService(store)

	for i := 0; i < MaxFailedAttempts; i++ {
		if err := svc.ConsumeCode(context.Background(), "user-A", "WRONG-CODE-0000-0000"); !errors.Is(err, ErrInvalidCode) {
			t.Fatalf("attempt %d = %v, want ErrInvalidCode", i, err)
		}
	}

	locked, err := svc.IsUserLocked(context.Background(), "user-A")
	if err != nil {
		t.Fatalf("IsUserLocked: %v", err)
	}
	if !locked {
		t.Fatal("account should be locked after MaxFailedAttempts failures (fail-closed)")
	}
	// The correct code is now rejected with the lockout error, not accepted.
	if err := svc.ConsumeCode(context.Background(), "user-A", codes[0].Plaintext); !errors.Is(err, ErrUserLocked) {
		t.Fatalf("ConsumeCode after lockout = %v, want ErrUserLocked", err)
	}
}

// TestConsumeCode_GetLockoutStoreError proves a store read failure fails closed:
// if lockout state cannot be read, recovery does NOT proceed to check a code.
func TestConsumeCode_GetLockoutStoreError(t *testing.T) {
	store := newFakeRecoveryStore()
	store.getLockoutErr = errors.New("db down")
	svc := NewRecoveryService(store)

	if err := svc.ConsumeCode(context.Background(), "user-A", "ANY"); err == nil {
		t.Fatal("expected error when lockout state cannot be read (fail-closed)")
	}
	if store.consumeCalls != 0 {
		t.Errorf("consume path reached %d times on lockout-read failure; want 0", store.consumeCalls)
	}
}

// TestGenerateCodes_HashOnly_NoPlaintextInStorage proves the persisted form of
// a code is its salted hash: the plaintext is not derivable from the stored
// fields, so an operator with DB read access cannot recover a usable code.
//
//harbor:invariant INV-RECOVERY-HASH-ONLY
func TestGenerateCodes_HashOnly_NoPlaintextInStorage(t *testing.T) {
	mgr := NewRecoveryManager()
	codes, err := mgr.GenerateCodes(5)
	if err != nil {
		t.Fatalf("GenerateCodes: %v", err)
	}
	for i, c := range codes {
		normalized := normalizeCode(c.Plaintext)
		// The stored hash/salt must not embed the plaintext (raw or normalized).
		if bytes.Contains(c.Hash, []byte(c.Plaintext)) || bytes.Contains(c.Hash, []byte(normalized)) {
			t.Errorf("code %d: stored hash embeds plaintext", i)
		}
		if bytes.Contains(c.Salt, []byte(normalized)) {
			t.Errorf("code %d: salt embeds plaintext", i)
		}
		// Presenting the STORED hash (as if it were the code) must not verify — an
		// operator holding only the persisted secret cannot authenticate.
		if VerifyCode(string(c.Hash), c.Hash, c.Salt) {
			t.Errorf("code %d: stored hash verified as a code (operator-readable secret)", i)
		}
	}
}

// TestGenerateCodes_EntropyAtLeast128Bits proves each code carries at least 128
// bits of RNG entropy, and that a large batch shows no collisions (a collision
// would signal catastrophically low entropy).
//
//harbor:invariant INV-RECOVERY-CODE-ENTROPY
func TestGenerateCodes_EntropyAtLeast128Bits(t *testing.T) {
	if codeEntropyBytes*8 < 128 {
		t.Fatalf("code entropy is %d bits, want >= 128", codeEntropyBytes*8)
	}
	mgr := NewRecoveryManager()
	codes, err := mgr.GenerateCodes(1000)
	if err != nil {
		t.Fatalf("GenerateCodes: %v", err)
	}
	seen := make(map[string]struct{}, len(codes))
	for i, c := range codes {
		key := normalizeCode(c.Plaintext)
		if _, dup := seen[key]; dup {
			t.Fatalf("code %d collided across 1000 codes — entropy too low", i)
		}
		seen[key] = struct{}{}
	}
}
