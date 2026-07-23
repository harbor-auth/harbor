package identity

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/harbor-auth/harbor/internal/crypto"
	"github.com/harbor-auth/harbor/internal/gen/db"
)

// --- fakes ---

// fakeAuditUserLoader implements AuditUserLoader for tests.
type fakeAuditUserLoader struct {
	region     string
	dekWrapped []byte
	err        error
}

func (f *fakeAuditUserLoader) LoadUserForAudit(_ context.Context, _ string) (string, []byte, error) {
	if f.err != nil {
		return "", nil, f.err
	}
	return f.region, f.dekWrapped, nil
}

// slowAuditUserLoader blocks until released; used to verify RecordAsync is non-blocking.
type slowAuditUserLoader struct {
	released chan struct{}
}

func (s *slowAuditUserLoader) LoadUserForAudit(_ context.Context, _ string) (string, []byte, error) {
	<-s.released
	return "", nil, errors.New("released")
}

// fakeAuditEventInserter implements AuditEventInserter and captures inserted params.
type fakeAuditEventInserter struct {
	params []db.CreateAuditEventWithPayloadParams
	err    error
}

func (f *fakeAuditEventInserter) CreateAuditEventWithPayload(_ context.Context, arg db.CreateAuditEventWithPayloadParams) (db.AuditEvent, error) {
	if f.err != nil {
		return db.AuditEvent{}, f.err
	}
	f.params = append(f.params, arg)
	return db.AuditEvent{
		ID:               arg.ID,
		Region:           arg.Region,
		UserID:           arg.UserID,
		EventType:        arg.EventType,
		ClientID:         arg.ClientID,
		PayloadEncrypted: arg.PayloadEncrypted,
	}, nil
}

// --- test setup ---

// auditTestSetup holds shared state for AuditRecorder unit tests.
type auditTestSetup struct {
	recorder *AuditRecorder
	cipher   *crypto.Cipher
	store    *fakeAuditEventInserter
	userID   string
	dek      crypto.DEK
}

// newAuditTestSetup builds a real AuditRecorder backed by a local key provider,
// a real AES-GCM cipher, and in-memory stubs. It pre-wraps a fresh DEK so tests
// can decrypt assertions without touching the DB.
func newAuditTestSetup(t *testing.T) *auditTestSetup {
	t.Helper()
	const region = "EU"
	kp, err := crypto.NewLocalKeyProvider("test-secret-32-bytes-for-testing!")
	if err != nil {
		t.Fatalf("NewLocalKeyProvider: %v", err)
	}
	dek, err := crypto.GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK: %v", err)
	}
	wrapped, err := kp.WrapDEK(context.Background(), region, dek)
	if err != nil {
		t.Fatalf("WrapDEK: %v", err)
	}
	loader := &fakeAuditUserLoader{region: region, dekWrapped: wrapped}
	store := &fakeAuditEventInserter{}
	ci := crypto.NewCipher()
	rec := NewAuditRecorder(loader, store, kp, ci, slog.Default())
	return &auditTestSetup{
		recorder: rec,
		cipher:   ci,
		store:    store,
		userID:   uuid.New().String(),
		dek:      dek,
	}
}

// --- tests ---

// TestAuditRecordPayloadEncrypted verifies that the value written to
// PayloadEncrypted is ciphertext — not the raw JSON of the detail struct.
// Storing plaintext would be a data-at-rest leak (DESIGN §4.4).
//
//harbor:invariant INV-AUDIT-PAYLOAD-ENCRYPTED
func TestAuditRecordPayloadEncrypted(t *testing.T) {
	s := newAuditTestSetup(t)

	type detail struct{ Action string }
	d := detail{Action: "test-action"}
	cid := "test-client"

	if err := s.recorder.Record(context.Background(), s.userID, EventTokenIssued, &cid, d); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if len(s.store.params) != 1 {
		t.Fatalf("expected 1 inserted row, got %d", len(s.store.params))
	}

	plainJSON, _ := json.Marshal(d)
	ciphertext := s.store.params[0].PayloadEncrypted

	// Stored bytes must NOT equal the raw JSON.
	if bytes.Equal(ciphertext, plainJSON) {
		t.Fatal("PayloadEncrypted equals raw JSON — payload is stored in plaintext, not encrypted")
	}
	// Ciphertext must be larger than plaintext due to nonce + GCM tag overhead.
	if len(ciphertext) <= len(plainJSON) {
		t.Fatalf("PayloadEncrypted (%d bytes) is not longer than raw JSON (%d bytes) — expected encryption overhead",
			len(ciphertext), len(plainJSON))
	}
}

// TestAuditRecordDecryptRoundTrip verifies that the stored ciphertext decrypts
// back to the original detail under the correct DEK and AAD.
func TestAuditRecordDecryptRoundTrip(t *testing.T) {
	s := newAuditTestSetup(t)

	type detail struct {
		Grant string `json:"grant"`
		Scope string `json:"scope"`
	}
	d := detail{Grant: "auth_code", Scope: "openid offline_access"}
	cid := "my-client"

	if err := s.recorder.Record(context.Background(), s.userID, EventTokenIssued, &cid, d); err != nil {
		t.Fatalf("Record: %v", err)
	}

	ciphertext := s.store.params[0].PayloadEncrypted
	plain, err := s.cipher.Decrypt(s.dek, ciphertext, auditPayloadAAD(s.userID))
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	var got detail
	if err := json.Unmarshal(plain, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got != d {
		t.Fatalf("round-trip mismatch: got %+v, want %+v", got, d)
	}
}

// TestAuditPayloadAADBound verifies that a payload encrypted for user A cannot
// be authenticated (let alone decrypted) as if it belonged to user B. This is
// the cross-user AAD isolation invariant (DESIGN §4.4).
//
//harbor:invariant INV-AUDIT-AAD-USER-BOUND
func TestAuditPayloadAADBound(t *testing.T) {
	s := newAuditTestSetup(t)

	if err := s.recorder.Record(context.Background(), s.userID, EventAuthLogin, nil, map[string]string{"ip": "1.2.3.4"}); err != nil {
		t.Fatalf("Record: %v", err)
	}

	ciphertext := s.store.params[0].PayloadEncrypted

	// Decrypting with a DIFFERENT user ID as AAD must fail (GCM tag mismatch).
	otherUserID := uuid.New().String()
	if _, err := s.cipher.Decrypt(s.dek, ciphertext, auditPayloadAAD(otherUserID)); err == nil {
		t.Fatal("expected decryption to fail with wrong AAD user ID — cross-user isolation broken")
	}

	// Decrypting with the CORRECT user ID as AAD must succeed.
	if _, err := s.cipher.Decrypt(s.dek, ciphertext, auditPayloadAAD(s.userID)); err != nil {
		t.Fatalf("expected decryption to succeed with correct AAD: %v", err)
	}
}

// TestAuditRecordAsyncNonBlocking verifies that RecordAsync returns immediately
// even when the underlying I/O blocks. A slow audit write must never stall the
// auth hot path (DESIGN §2.1, Decision 3).
func TestAuditRecordAsyncNonBlocking(t *testing.T) {
	released := make(chan struct{})
	loader := &slowAuditUserLoader{released: released}
	store := &fakeAuditEventInserter{}
	kp, err := crypto.NewLocalKeyProvider("test-secret-32-bytes-for-testing!")
	if err != nil {
		t.Fatalf("NewLocalKeyProvider: %v", err)
	}
	rec := NewAuditRecorder(loader, store, kp, crypto.NewCipher(), slog.Default())

	start := time.Now()
	rec.RecordAsync(context.Background(), uuid.New().String(), EventAuthLogin, nil, nil)
	elapsed := time.Since(start)

	close(released) // unblock the background goroutine (it will error — that's fine)

	if elapsed > 50*time.Millisecond {
		t.Fatalf("RecordAsync blocked for %v; must return immediately without waiting for I/O", elapsed)
	}
}

// TestAuditRecordUserLoadError verifies that Record surfaces an error when the
// user loader fails, and that no DB write occurs.
func TestAuditRecordUserLoadError(t *testing.T) {
	sentinel := errors.New("user not found")
	loader := &fakeAuditUserLoader{err: sentinel}
	store := &fakeAuditEventInserter{}
	kp, err := crypto.NewLocalKeyProvider("test-secret-32-bytes-for-testing!")
	if err != nil {
		t.Fatalf("NewLocalKeyProvider: %v", err)
	}
	rec := NewAuditRecorder(loader, store, kp, crypto.NewCipher(), slog.Default())

	err = rec.Record(context.Background(), uuid.New().String(), EventAuthLogin, nil, nil)
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected error wrapping %v, got %v", sentinel, err)
	}
	if len(store.params) != 0 {
		t.Fatal("no DB write should occur when user load fails")
	}
}

// TestAuditRecordStoreError verifies that Record surfaces an error when the
// event inserter fails.
func TestAuditRecordStoreError(t *testing.T) {
	s := newAuditTestSetup(t)
	sentinel := errors.New("DB unavailable")
	s.store.err = sentinel

	err := s.recorder.Record(context.Background(), s.userID, EventTokenIssued, nil, nil)
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected error wrapping %v, got %v", sentinel, err)
	}
}

// TestAuditRecordNilDetail verifies that a nil detail is handled gracefully:
// the event is stored with valid ciphertext (encrypting an empty plaintext)
// that decrypts back to zero bytes.
func TestAuditRecordNilDetail(t *testing.T) {
	s := newAuditTestSetup(t)

	if err := s.recorder.Record(context.Background(), s.userID, EventConsentRevoked, nil, nil); err != nil {
		t.Fatalf("Record with nil detail: %v", err)
	}
	if len(s.store.params) != 1 {
		t.Fatalf("expected 1 inserted row, got %d", len(s.store.params))
	}

	ciphertext := s.store.params[0].PayloadEncrypted
	// Ciphertext must be non-empty even for a nil detail (nonce + GCM tag = 28 bytes minimum).
	if len(ciphertext) == 0 {
		t.Fatal("PayloadEncrypted must not be empty even for nil detail")
	}

	// Decrypting must yield empty plaintext (not an error).
	plain, err := s.cipher.Decrypt(s.dek, ciphertext, auditPayloadAAD(s.userID))
	if err != nil {
		t.Fatalf("Decrypt nil-detail ciphertext: %v", err)
	}
	if len(plain) != 0 {
		t.Fatalf("expected empty plaintext for nil detail, got %d bytes", len(plain))
	}
}

// TestAuditRecordUnwrapDEKError verifies that Record surfaces an error when the
// key provider cannot unwrap the user's DEK (e.g. HSM unavailable or crypto-shred).
func TestAuditRecordUnwrapDEKError(t *testing.T) {
	sentinel := errors.New("HSM unavailable")
	kp, err := crypto.NewLocalKeyProvider("test-secret-32-bytes-for-testing!")
	if err != nil {
		t.Fatalf("NewLocalKeyProvider: %v", err)
	}
	// Wrap a DEK in the correct region so LoadUserForAudit succeeds, but use
	// errKeyProvider (unwrapErr set) so UnwrapDEK fails.
	dek, err := crypto.GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK: %v", err)
	}
	wrapped, err := kp.WrapDEK(context.Background(), "EU", dek)
	if err != nil {
		t.Fatalf("WrapDEK: %v", err)
	}
	loader := &fakeAuditUserLoader{region: "EU", dekWrapped: wrapped}
	store := &fakeAuditEventInserter{}
	// Use an errKeyProvider that fails on UnwrapDEK.
	rec := NewAuditRecorder(loader, store, errKeyProvider{unwrapErr: sentinel}, crypto.NewCipher(), slog.Default())

	err = rec.Record(context.Background(), uuid.New().String(), EventAuthLogin, nil, nil)
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected error wrapping %v, got %v", sentinel, err)
	}
	if len(store.params) != 0 {
		t.Fatal("no DB write should occur when DEK unwrap fails")
	}
}
