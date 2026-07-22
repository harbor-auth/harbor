package identity

import (
	"context"
	"errors"
	"testing"

	"github.com/harbor-auth/harbor/internal/crypto"
)

// errKeyProvider returns a fixed error from WrapDEK.
type errKeyProvider struct {
	wrapErr   error
	unwrapErr error
}

func (e errKeyProvider) WrapDEK(_ context.Context, _ string, _ crypto.DEK) ([]byte, error) {
	return nil, e.wrapErr
}

func (e errKeyProvider) UnwrapDEK(_ context.Context, _ string, _ []byte) (crypto.DEK, error) {
	return crypto.DEK{}, e.unwrapErr
}

// errCipher returns a fixed error from Encrypt.
type errCipher struct {
	encryptErr error
}

func (e errCipher) Encrypt(_ crypto.DEK, _, _ []byte) ([]byte, error) {
	return nil, e.encryptErr
}

// fakePersister captures what was passed to PersistUser for assertions.
type fakePersister struct {
	records []UserRecord
	err     error
}

func (f *fakePersister) PersistUser(_ context.Context, r UserRecord) error {
	if f.err != nil {
		return f.err
	}
	f.records = append(f.records, r)
	return nil
}

func newTestEnroller(t *testing.T, p UserPersister) *Enroller {
	t.Helper()
	kp, err := crypto.NewLocalKeyProvider("test-secret-32-bytes-for-testing!")
	if err != nil {
		t.Fatalf("NewLocalKeyProvider: %v", err)
	}
	return NewEnroller(kp, crypto.NewCipher(), p)
}

func TestEnrollSuccess(t *testing.T) {
	p := &fakePersister{}
	e := newTestEnroller(t, p)
	res, err := e.Enroll(context.Background(), "EU")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if res.Region != "EU" {
		t.Fatalf("region = %q, want EU", res.Region)
	}
	if res.UserID == "" {
		t.Fatal("user_id is empty")
	}
	if len(p.records) != 1 {
		t.Fatalf("persister got %d records, want 1", len(p.records))
	}
	r := p.records[0]
	if r.ID != res.UserID {
		t.Fatalf("record.ID %q != result.UserID %q", r.ID, res.UserID)
	}
	if len(r.DekWrapped) == 0 {
		t.Fatal("DekWrapped must not be empty")
	}
	if len(r.PairwiseSecret) == 0 {
		t.Fatal("PairwiseSecret must not be empty")
	}
	if !r.RecoveryRequired {
		t.Fatal("RecoveryRequired must be true for a freshly enrolled user (REQ-005)")
	}
}

// TestEnrollRecordsRecoveryRequired verifies that every enrollment records
// recovery_required=true, so a newly created user is forced through account
// recovery setup before normal use (REQ-005).
func TestEnrollRecordsRecoveryRequired(t *testing.T) {
	p := &fakePersister{}
	e := newTestEnroller(t, p)
	if _, err := e.Enroll(context.Background(), "US"); err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if len(p.records) != 1 {
		t.Fatalf("persister got %d records, want 1", len(p.records))
	}
	if !p.records[0].RecoveryRequired {
		t.Fatal("enrollment must record RecoveryRequired=true")
	}
}

func TestEnrollInvalidRegion(t *testing.T) {
	p := &fakePersister{}
	e := newTestEnroller(t, p)
	if _, err := e.Enroll(context.Background(), "ATLANTIS"); err == nil {
		t.Fatal("expected error for unknown region")
	}
	if len(p.records) != 0 {
		t.Fatal("no DB write should occur for invalid region")
	}
}

func TestEnrollPersisterError(t *testing.T) {
	want := errors.New("db down")
	p := &fakePersister{err: want}
	e := newTestEnroller(t, p)
	_, err := e.Enroll(context.Background(), "US")
	if !errors.Is(err, want) {
		t.Fatalf("err = %v, want wrapping %v", err, want)
	}
}

// TestEnrollDifferentUsers verifies that two enrollments produce distinct UUIDs,
// distinct wrapped DEKs, and distinct encrypted pairwise secrets (fresh randomness
// per user; a DEK collision would mean two users share a decryption key).
//
//harbor:invariant INV-ENROLL-DEK-FRESH
func TestEnrollDifferentUsers(t *testing.T) {
	p := &fakePersister{}
	e := newTestEnroller(t, p)
	if _, err := e.Enroll(context.Background(), "EU"); err != nil {
		t.Fatalf("first Enroll: %v", err)
	}
	if _, err := e.Enroll(context.Background(), "EU"); err != nil {
		t.Fatalf("second Enroll: %v", err)
	}
	if len(p.records) != 2 {
		t.Fatalf("want 2 records, got %d", len(p.records))
	}
	a, b := p.records[0], p.records[1]
	if a.ID == b.ID {
		t.Fatal("user IDs must differ across enrollments")
	}
	if string(a.DekWrapped) == string(b.DekWrapped) {
		t.Fatal("DekWrapped must differ across enrollments (each user gets a fresh DEK)")
	}
	if string(a.PairwiseSecret) == string(b.PairwiseSecret) {
		t.Fatal("PairwiseSecret ciphertext must differ across enrollments")
	}
}

// TestEnrollPairwiseSecretEncrypted verifies that the stored pairwise secret is
// NOT the raw 32-byte secret — it must be envelope-encrypted and therefore longer:
// 12-byte nonce + 32-byte ciphertext + 16-byte GCM tag = 60 bytes.
//
//harbor:invariant INV-ENROLL-PAIRWISE-SECRET-ENCRYPTED
func TestEnrollPairwiseSecretEncrypted(t *testing.T) {
	p := &fakePersister{}
	e := newTestEnroller(t, p)
	if _, err := e.Enroll(context.Background(), "EU"); err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	r := p.records[0]
	// Raw 32-byte secret → GCM output is 60 bytes (nonce+ciphertext+tag).
	// A 32-byte stored value means plaintext was written — a storage leak.
	if len(r.PairwiseSecret) <= 32 {
		t.Fatalf("PairwiseSecret is %d bytes — looks like raw plaintext, expected ≥60 (encrypted)",
			len(r.PairwiseSecret))
	}
}

// TestEnrollRegionBound verifies that the wrapped DEK is region-isolated:
// unwrapping with a different region must fail, and the correct region must succeed.
//
//harbor:invariant INV-ENROLL-REGION-BOUND
func TestEnrollRegionBound(t *testing.T) {
	p := &fakePersister{}
	kp, err := crypto.NewLocalKeyProvider("test-secret-32-bytes-for-testing!")
	if err != nil {
		t.Fatalf("NewLocalKeyProvider: %v", err)
	}
	e := NewEnroller(kp, crypto.NewCipher(), p)
	if _, err := e.Enroll(context.Background(), "EU"); err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	r := p.records[0]
	// Cross-region unwrap must fail.
	if _, err := kp.UnwrapDEK(context.Background(), "US", r.DekWrapped); err == nil {
		t.Fatal("cross-region DEK unwrap must fail")
	}
	// Correct-region unwrap must succeed.
	if _, err := kp.UnwrapDEK(context.Background(), "EU", r.DekWrapped); err != nil {
		t.Fatalf("same-region DEK unwrap failed: %v", err)
	}
}

// --- Additional error path tests ---

func TestEnrollWrapDEKError(t *testing.T) {
	sentinel := errors.New("HSM unavailable")
	p := &fakePersister{}
	e := NewEnroller(errKeyProvider{wrapErr: sentinel}, crypto.NewCipher(), p)
	_, err := e.Enroll(context.Background(), "EU")
	if err == nil {
		t.Fatal("expected error when WrapDEK fails")
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected wrapped sentinel error, got %v", err)
	}
	if len(p.records) != 0 {
		t.Fatal("no DB write should occur when WrapDEK fails")
	}
}

func TestEnrollEncryptError(t *testing.T) {
	sentinel := errors.New("cipher failure")
	p := &fakePersister{}
	kp, err := crypto.NewLocalKeyProvider("test-secret-32-bytes-for-testing!")
	if err != nil {
		t.Fatalf("NewLocalKeyProvider: %v", err)
	}
	e := NewEnroller(kp, errCipher{encryptErr: sentinel}, p)
	_, err = e.Enroll(context.Background(), "EU")
	if err == nil {
		t.Fatal("expected error when Encrypt fails")
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected wrapped sentinel error, got %v", err)
	}
	if len(p.records) != 0 {
		t.Fatal("no DB write should occur when Encrypt fails")
	}
}
