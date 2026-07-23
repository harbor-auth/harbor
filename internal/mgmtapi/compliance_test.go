package mgmtapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/harbor-auth/harbor/internal/identity"
)

// --- fakes ---

// fakeBundleAssembler implements BundleAssembler for tests.
type fakeBundleAssembler struct {
	bundle      *identity.Bundle
	err         error
	capturedUID string
}

func (f *fakeBundleAssembler) Assemble(_ context.Context, userID string) (*identity.Bundle, error) {
	f.capturedUID = userID
	if f.err != nil {
		return nil, f.err
	}
	return f.bundle, nil
}

// fakeAccountEraser implements AccountEraser for tests.
type fakeAccountEraser struct {
	err         error
	capturedUID string
	called      bool
}

func (f *fakeAccountEraser) Erase(_ context.Context, userID string) error {
	f.called = true
	f.capturedUID = userID
	return f.err
}

// fakeComplianceUserLoader implements ComplianceUserLoader for tests.
type fakeComplianceUserLoader struct {
	region string
	err    error
}

func (f *fakeComplianceUserLoader) LoadUserForAudit(_ context.Context, _ string) (string, []byte, error) {
	if f.err != nil {
		return "", nil, f.err
	}
	return f.region, nil, nil
}

// newComplianceDeps builds a ComplianceDeps with the provided fakes.
func newComplianceDeps(bundler BundleAssembler, eraser AccountEraser, users ComplianceUserLoader) *ComplianceDeps {
	return &ComplianceDeps{
		Bundler: bundler,
		Eraser:  eraser,
		Users:   users,
	}
}

// newComplianceMux builds a mgmtapi Server with ComplianceDeps wired and
// returns its ServeMux ready for httptest requests.
func newComplianceMux(deps *ComplianceDeps) *http.ServeMux {
	srv := New(nil, nil)
	srv.compliance = deps
	mux := http.NewServeMux()
	srv.Routes(mux)
	return mux
}

// testBundle returns a minimal Bundle suitable for happy-path assertions.
func testBundle(userID string) *identity.Bundle {
	return &identity.Bundle{
		UserID:        userID,
		Region:        "EU",
		Status:        "active",
		CreatedAt:     time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC),
		ConsentGrants: []identity.ConsentGrantEntry{},
		AuditEvents:   []identity.AuditEventEntry{},
		RelayMappings: []identity.RelayMappingEntry{},
	}
}

// --- PostExport tests ---

func TestPostExport_Unauthorized(t *testing.T) {
	mux := newComplianceMux(newComplianceDeps(
		&fakeBundleAssembler{bundle: testBundle("user-123")},
		&fakeAccountEraser{},
		&fakeComplianceUserLoader{region: "EU"},
	))

	req := httptest.NewRequest("POST", "/compliance/export", nil)
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

func TestPostExport_ServiceUnavailable(t *testing.T) {
	// nil compliance → 503.
	srv := New(nil, nil)
	mux := http.NewServeMux()
	srv.Routes(mux)

	req := httptest.NewRequest("POST", "/compliance/export", nil)
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

func TestPostExport_Success(t *testing.T) {
	bundle := testBundle("user-123")
	bundler := &fakeBundleAssembler{bundle: bundle}
	mux := newComplianceMux(newComplianceDeps(
		bundler,
		&fakeAccountEraser{},
		&fakeComplianceUserLoader{region: "EU"},
	))

	req := httptest.NewRequest("POST", "/compliance/export", nil)
	req.Header.Set(UserIDHeader, "user-123")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var got identity.Bundle
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode bundle: %v", err)
	}
	if got.UserID != "user-123" {
		t.Errorf("bundle.user_id = %q, want user-123", got.UserID)
	}
	if got.Region != "EU" {
		t.Errorf("bundle.region = %q, want EU", got.Region)
	}
	if got.Status != "active" {
		t.Errorf("bundle.status = %q, want active", got.Status)
	}
}

// TestPostExport_CallerScoped verifies that Assemble is called with the
// authenticated user's ID from the X-Harbor-User-ID header — guaranteeing the
// export is strictly caller-scoped and cannot be directed at another user.
func TestPostExport_CallerScoped(t *testing.T) {
	bundler := &fakeBundleAssembler{bundle: testBundle("alice")}
	mux := newComplianceMux(newComplianceDeps(
		bundler,
		&fakeAccountEraser{},
		&fakeComplianceUserLoader{region: "EU"},
	))

	req := httptest.NewRequest("POST", "/compliance/export", nil)
	req.Header.Set(UserIDHeader, "alice")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	// The bundler must have been called with exactly the authenticated user ID.
	if bundler.capturedUID != "alice" {
		t.Errorf("SECURITY: bundler called with userID = %q, want alice", bundler.capturedUID)
	}
}

// TestSecurity_PostExport_CrossUserIsolation verifies that user B cannot
// trigger an export for user A. The handler passes the X-Harbor-User-ID header
// value to the bundler — so user B's request assembles only user B's bundle.
func TestSecurity_PostExport_CrossUserIsolation(t *testing.T) {
	bundler := &fakeBundleAssembler{bundle: testBundle("user-B")}
	mux := newComplianceMux(newComplianceDeps(
		bundler,
		&fakeAccountEraser{},
		&fakeComplianceUserLoader{region: "EU"},
	))

	// user-B makes the request — must only trigger assembly for user-B.
	req := httptest.NewRequest("POST", "/compliance/export", nil)
	req.Header.Set(UserIDHeader, "user-B")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	// SECURITY: bundler must be called with user-B, never user-A.
	if bundler.capturedUID != "user-B" {
		t.Errorf("SECURITY: bundler called with %q, want user-B (cross-user isolation broken)", bundler.capturedUID)
	}
}

func TestPostExport_BundlerError(t *testing.T) {
	mux := newComplianceMux(newComplianceDeps(
		&fakeBundleAssembler{err: errors.New("DEK unwrap failed")},
		&fakeAccountEraser{},
		&fakeComplianceUserLoader{region: "EU"},
	))

	req := httptest.NewRequest("POST", "/compliance/export", nil)
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

// --- PostErase tests ---

func TestPostErase_Unauthorized(t *testing.T) {
	mux := newComplianceMux(newComplianceDeps(
		&fakeBundleAssembler{bundle: testBundle("user-123")},
		&fakeAccountEraser{},
		&fakeComplianceUserLoader{region: "EU"},
	))

	req := httptest.NewRequest("POST", "/compliance/erase", nil)
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

func TestPostErase_ServiceUnavailable(t *testing.T) {
	// nil compliance → 503.
	srv := New(nil, nil)
	mux := http.NewServeMux()
	srv.Routes(mux)

	req := httptest.NewRequest("POST", "/compliance/erase", nil)
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

func TestPostErase_Success(t *testing.T) {
	eraser := &fakeAccountEraser{}
	mux := newComplianceMux(newComplianceDeps(
		&fakeBundleAssembler{bundle: testBundle("user-123")},
		eraser,
		&fakeComplianceUserLoader{region: "EU"},
	))

	req := httptest.NewRequest("POST", "/compliance/erase", nil)
	req.Header.Set(UserIDHeader, "user-123")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusNoContent, rec.Body.String())
	}
	// The eraser must have been called with the authenticated user ID.
	if !eraser.called {
		t.Fatal("eraser.Erase was not called")
	}
	if eraser.capturedUID != "user-123" {
		t.Errorf("eraser called with userID = %q, want user-123", eraser.capturedUID)
	}
}

// TestPostErase_EraseCalledWithAuthenticatedUser verifies the eraser is always
// called with the X-Harbor-User-ID value — the caller cannot target another user.
func TestPostErase_EraseCalledWithAuthenticatedUser(t *testing.T) {
	eraser := &fakeAccountEraser{}
	mux := newComplianceMux(newComplianceDeps(
		&fakeBundleAssembler{bundle: testBundle("alice")},
		eraser,
		&fakeComplianceUserLoader{region: "EU"},
	))

	req := httptest.NewRequest("POST", "/compliance/erase", nil)
	req.Header.Set(UserIDHeader, "alice")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
	if eraser.capturedUID != "alice" {
		t.Errorf("SECURITY: eraser called with %q, want alice", eraser.capturedUID)
	}
}

func TestPostErase_UserLoadError(t *testing.T) {
	mux := newComplianceMux(newComplianceDeps(
		&fakeBundleAssembler{bundle: testBundle("user-123")},
		&fakeAccountEraser{},
		&fakeComplianceUserLoader{err: errors.New("DB unavailable")},
	))

	req := httptest.NewRequest("POST", "/compliance/erase", nil)
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

// TestPostErase_UserLoadError_ShredNotCalled verifies that if the user region
// load fails, the crypto-shred is NOT performed — fail-closed before the
// point of no return.
func TestPostErase_UserLoadError_ShredNotCalled(t *testing.T) {
	eraser := &fakeAccountEraser{}
	mux := newComplianceMux(newComplianceDeps(
		&fakeBundleAssembler{bundle: testBundle("user-123")},
		eraser,
		&fakeComplianceUserLoader{err: errors.New("DB unavailable")},
	))

	req := httptest.NewRequest("POST", "/compliance/erase", nil)
	req.Header.Set(UserIDHeader, "user-123")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
	// The crypto-shred must NOT have been triggered.
	if eraser.called {
		t.Fatal("SAFETY: eraser.Erase must NOT be called when user load fails")
	}
}

func TestPostErase_EraserError(t *testing.T) {
	mux := newComplianceMux(newComplianceDeps(
		&fakeBundleAssembler{bundle: testBundle("user-123")},
		&fakeAccountEraser{err: errors.New("crypto-shred failed")},
		&fakeComplianceUserLoader{region: "EU"},
	))

	req := httptest.NewRequest("POST", "/compliance/erase", nil)
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

// TestPostErase_NoUsersLoader verifies that a nil Users loader in ComplianceDeps
// is tolerated — the handler skips region resolution and still calls Erase.
func TestPostErase_NoUsersLoader(t *testing.T) {
	eraser := &fakeAccountEraser{}
	deps := &ComplianceDeps{
		Bundler: &fakeBundleAssembler{bundle: testBundle("user-123")},
		Eraser:  eraser,
		Users:   nil, // no region loader wired
	}
	mux := newComplianceMux(deps)

	req := httptest.NewRequest("POST", "/compliance/erase", nil)
	req.Header.Set(UserIDHeader, "user-123")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	// Should still succeed — region metering is best-effort.
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusNoContent, rec.Body.String())
	}
	if !eraser.called {
		t.Fatal("eraser.Erase must be called even when Users loader is nil")
	}
}
