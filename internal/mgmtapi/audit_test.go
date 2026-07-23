package mgmtapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/harbor-auth/harbor/internal/crypto"
)

// --- fakes ---

// fakeAuditStore implements AuditStore for tests.
type fakeAuditStore struct {
	events      []RawAuditEvent
	err         error
	capturedID  string
	capturedLt  int
	capturedOff int
}

func (f *fakeAuditStore) ListAuditEvents(_ context.Context, userID string, limit, offset int) ([]RawAuditEvent, error) {
	f.capturedID = userID
	f.capturedLt = limit
	f.capturedOff = offset
	if f.err != nil {
		return nil, f.err
	}
	return f.events, nil
}

// fakeAuditUserReader implements AuditUserReader for tests.
type fakeAuditUserReader struct {
	region string
	dek    []byte
	err    error
}

func (f *fakeAuditUserReader) LoadUserForAudit(_ context.Context, _ string) (string, []byte, error) {
	if f.err != nil {
		return "", nil, f.err
	}
	return f.region, f.dek, nil
}

// fakeAuditKeyUnwrapper implements AuditKeyUnwrapper for tests.
type fakeAuditKeyUnwrapper struct {
	dek crypto.DEK
	err error
}

func (f *fakeAuditKeyUnwrapper) UnwrapDEK(_ context.Context, _ string, _ []byte) (crypto.DEK, error) {
	if f.err != nil {
		return crypto.DEK{}, f.err
	}
	return f.dek, nil
}

// fakeAuditDecryptor implements AuditDecryptor for tests.
type fakeAuditDecryptor struct {
	plaintext []byte
	err       error
}

func (f *fakeAuditDecryptor) Decrypt(_ crypto.DEK, _ []byte, _ []byte) ([]byte, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.plaintext, nil
}

// newTestAuditDeps builds a wired AuditTrailDeps with the provided components.
func newTestAuditDeps(store AuditStore, users AuditUserReader, keys AuditKeyUnwrapper, dec AuditDecryptor) *AuditTrailDeps {
	return &AuditTrailDeps{
		Store:     store,
		Users:     users,
		Keys:      keys,
		Decryptor: dec,
	}
}

// newAuditMux builds a mgmtapi Server with the given AuditTrailDeps wired and
// returns its ServeMux, ready for httptest requests.
func newAuditMux(deps *AuditTrailDeps) *http.ServeMux {
	srv := New(nil, nil).WithAuditTrail(deps)
	mux := http.NewServeMux()
	srv.Routes(mux)
	return mux
}

// --- tests ---

func TestGetAuditEvents_Unauthorized(t *testing.T) {
	mux := newAuditMux(newTestAuditDeps(
		&fakeAuditStore{},
		&fakeAuditUserReader{region: "EU"},
		&fakeAuditKeyUnwrapper{},
		&fakeAuditDecryptor{},
	))

	req := httptest.NewRequest("GET", "/audit-events", nil)
	// No X-Harbor-User-ID header.
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	var resp errorResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Error != "unauthorized" {
		t.Errorf("error = %q, want %q", resp.Error, "unauthorized")
	}
}

func TestGetAuditEvents_ServiceUnavailable(t *testing.T) {
	// nil auditTrail → 503.
	srv := New(nil, nil)
	mux := http.NewServeMux()
	srv.Routes(mux)

	req := httptest.NewRequest("GET", "/audit-events", nil)
	req.Header.Set(UserIDHeader, "user-123")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
	var resp errorResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Error != "service_unavailable" {
		t.Errorf("error = %q, want %q", resp.Error, "service_unavailable")
	}
}

func TestGetAuditEvents_Success(t *testing.T) {
	occurredAt := time.Date(2026, 1, 15, 10, 30, 0, 0, time.UTC)
	clientID := "test-rp"
	detail := `{"scope":"openid"}`

	store := &fakeAuditStore{
		events: []RawAuditEvent{
			{
				ID:               "evt-001",
				EventType:        "token.issued",
				ClientID:         &clientID,
				OccurredAt:       occurredAt,
				Region:           "EU",
				PayloadEncrypted: []byte("fake-ciphertext"),
			},
			{
				ID:         "evt-002",
				EventType:  "auth.login",
				ClientID:   nil,
				OccurredAt: occurredAt.Add(-time.Hour),
				Region:     "EU",
				// No ciphertext — pre-migration row.
			},
		},
	}

	mux := newAuditMux(newTestAuditDeps(
		store,
		&fakeAuditUserReader{region: "EU"},
		&fakeAuditKeyUnwrapper{},
		// Decryptor returns the detail JSON for any non-empty ciphertext.
		&fakeAuditDecryptor{plaintext: []byte(detail)},
	))

	req := httptest.NewRequest("GET", "/audit-events", nil)
	req.Header.Set(UserIDHeader, "user-123")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var resp auditEventsListResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Events) != 2 {
		t.Fatalf("got %d events, want 2", len(resp.Events))
	}

	// First event: has ciphertext → detail is populated.
	if resp.Events[0].ID != "evt-001" {
		t.Errorf("events[0].id = %q, want evt-001", resp.Events[0].ID)
	}
	if resp.Events[0].EventType != "token.issued" {
		t.Errorf("events[0].event_type = %q, want token.issued", resp.Events[0].EventType)
	}
	if resp.Events[0].ClientID == nil || *resp.Events[0].ClientID != clientID {
		t.Errorf("events[0].client_id = %v, want %q", resp.Events[0].ClientID, clientID)
	}
	if string(resp.Events[0].Detail) != detail {
		t.Errorf("events[0].detail = %q, want %q", string(resp.Events[0].Detail), detail)
	}

	// Second event: no ciphertext → detail is absent (skeleton).
	if resp.Events[1].ID != "evt-002" {
		t.Errorf("events[1].id = %q, want evt-002", resp.Events[1].ID)
	}
	if resp.Events[1].Detail != nil {
		t.Errorf("events[1].detail should be absent for pre-migration row, got %q", string(resp.Events[1].Detail))
	}
}

// TestGetAuditEvents_OnlyOwnEvents verifies that the handler passes the
// authenticated user's ID to the store — guaranteeing event ownership is
// enforced at query time and user A cannot retrieve user B's events.
func TestGetAuditEvents_OnlyOwnEvents(t *testing.T) {
	store := &fakeAuditStore{
		events: []RawAuditEvent{
			{ID: "evt-A", EventType: "auth.login", OccurredAt: time.Now()},
		},
	}
	mux := newAuditMux(newTestAuditDeps(
		store,
		&fakeAuditUserReader{region: "EU"},
		&fakeAuditKeyUnwrapper{},
		&fakeAuditDecryptor{},
	))

	req := httptest.NewRequest("GET", "/audit-events", nil)
	req.Header.Set(UserIDHeader, "user-A")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	// The store must have been called with the authenticated user's ID.
	if store.capturedID != "user-A" {
		t.Errorf("store called with userID = %q, want user-A", store.capturedID)
	}
}

// TestGetAuditEvents_CryptoShredSkeletonFallback verifies that a decryption
// failure (simulating DEK destruction / crypto-shred per §11.6) causes the
// event to be returned skeleton-only (event_type + occurred_at, no detail)
// rather than a 500 error. The user sees a complete event log even after
// erasure, just without sensitive detail.
func TestGetAuditEvents_CryptoShredSkeletonFallback(t *testing.T) {
	store := &fakeAuditStore{
		events: []RawAuditEvent{
			{
				ID:               "evt-shredded",
				EventType:        "token.issued",
				OccurredAt:       time.Now(),
				PayloadEncrypted: []byte("unreachable-ciphertext"),
			},
		},
	}
	mux := newAuditMux(newTestAuditDeps(
		store,
		&fakeAuditUserReader{region: "EU"},
		&fakeAuditKeyUnwrapper{},
		// Decryptor returns ErrDecryptFailed — simulates DEK destroyed.
		&fakeAuditDecryptor{err: crypto.ErrDecryptFailed},
	))

	req := httptest.NewRequest("GET", "/audit-events", nil)
	req.Header.Set(UserIDHeader, "user-erasure")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	// Must return 200, not 500 — a failed decrypt is best-effort.
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var resp auditEventsListResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Events) != 1 {
		t.Fatalf("got %d events, want 1", len(resp.Events))
	}
	if resp.Events[0].ID != "evt-shredded" {
		t.Errorf("event id = %q, want evt-shredded", resp.Events[0].ID)
	}
	// Detail must be absent (nil) after crypto-shred.
	if resp.Events[0].Detail != nil {
		t.Errorf("expected no detail after crypto-shred, got %q", string(resp.Events[0].Detail))
	}
}

func TestGetAuditEvents_UserLoadError(t *testing.T) {
	mux := newAuditMux(newTestAuditDeps(
		&fakeAuditStore{},
		&fakeAuditUserReader{err: errors.New("DB connection failed")},
		&fakeAuditKeyUnwrapper{},
		&fakeAuditDecryptor{},
	))

	req := httptest.NewRequest("GET", "/audit-events", nil)
	req.Header.Set(UserIDHeader, "user-123")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
	var resp errorResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Error != "server_error" {
		t.Errorf("error = %q, want server_error", resp.Error)
	}
}

func TestGetAuditEvents_DEKUnwrapError(t *testing.T) {
	mux := newAuditMux(newTestAuditDeps(
		&fakeAuditStore{},
		&fakeAuditUserReader{region: "EU"},
		&fakeAuditKeyUnwrapper{err: errors.New("HSM unavailable")},
		&fakeAuditDecryptor{},
	))

	req := httptest.NewRequest("GET", "/audit-events", nil)
	req.Header.Set(UserIDHeader, "user-123")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
	var resp errorResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Error != "server_error" {
		t.Errorf("error = %q, want server_error", resp.Error)
	}
}

func TestGetAuditEvents_StoreError(t *testing.T) {
	mux := newAuditMux(newTestAuditDeps(
		&fakeAuditStore{err: errors.New("query timeout")},
		&fakeAuditUserReader{region: "EU"},
		&fakeAuditKeyUnwrapper{},
		&fakeAuditDecryptor{},
	))

	req := httptest.NewRequest("GET", "/audit-events", nil)
	req.Header.Set(UserIDHeader, "user-123")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
	var resp errorResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Error != "server_error" {
		t.Errorf("error = %q, want server_error", resp.Error)
	}
}

func TestGetAuditEvents_EmptyList(t *testing.T) {
	mux := newAuditMux(newTestAuditDeps(
		&fakeAuditStore{events: nil},
		&fakeAuditUserReader{region: "EU"},
		&fakeAuditKeyUnwrapper{},
		&fakeAuditDecryptor{},
	))

	req := httptest.NewRequest("GET", "/audit-events", nil)
	req.Header.Set(UserIDHeader, "user-no-events")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	var resp auditEventsListResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Events) != 0 {
		t.Fatalf("got %d events, want 0", len(resp.Events))
	}
}

// TestGetAuditEvents_PaginationClamped verifies that a limit above auditMaxLimit
// (100) is silently clamped, and that the offset param is forwarded correctly.
func TestGetAuditEvents_PaginationClamped(t *testing.T) {
	store := &fakeAuditStore{}
	mux := newAuditMux(newTestAuditDeps(
		store,
		&fakeAuditUserReader{region: "EU"},
		&fakeAuditKeyUnwrapper{},
		&fakeAuditDecryptor{},
	))

	req := httptest.NewRequest("GET", "/audit-events?limit=200&offset=25", nil)
	req.Header.Set(UserIDHeader, "user-123")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	// limit must be clamped to auditMaxLimit (100), not the requested 200.
	if store.capturedLt != auditMaxLimit {
		t.Errorf("store received limit = %d, want %d (clamped)", store.capturedLt, auditMaxLimit)
	}
	// offset must be forwarded as-is.
	if store.capturedOff != 25 {
		t.Errorf("store received offset = %d, want 25", store.capturedOff)
	}
}

// TestGetAuditEvents_DefaultPagination verifies the default limit is applied
// when no query params are provided.
func TestGetAuditEvents_DefaultPagination(t *testing.T) {
	store := &fakeAuditStore{}
	mux := newAuditMux(newTestAuditDeps(
		store,
		&fakeAuditUserReader{region: "EU"},
		&fakeAuditKeyUnwrapper{},
		&fakeAuditDecryptor{},
	))

	req := httptest.NewRequest("GET", "/audit-events", nil)
	req.Header.Set(UserIDHeader, "user-123")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if store.capturedLt != auditDefaultLimit {
		t.Errorf("default limit = %d, want %d", store.capturedLt, auditDefaultLimit)
	}
	if store.capturedOff != 0 {
		t.Errorf("default offset = %d, want 0", store.capturedOff)
	}
}
