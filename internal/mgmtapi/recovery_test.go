package mgmtapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/harbor-auth/harbor/internal/identity"
)

// --- fakes ---

type fakeRecoveryCodeGenerator struct {
	codes []identity.RecoveryCode
	err   error
}

func (f *fakeRecoveryCodeGenerator) GenerateCodes(n int) ([]identity.RecoveryCode, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.codes != nil {
		return f.codes, nil
	}
	out := make([]identity.RecoveryCode, n)
	for i := range out {
		out[i] = identity.RecoveryCode{Plaintext: "CODE-0000", Hash: []byte{1}, Salt: []byte{2}}
	}
	return out, nil
}

type fakeRecoveryCodeStore struct {
	stored []identity.RecoveryCode
	err    error
}

func (f *fakeRecoveryCodeStore) StoreRecoveryCodes(_ context.Context, _ string, codes []identity.RecoveryCode) error {
	if f.err != nil {
		return f.err
	}
	f.stored = codes
	return nil
}

type fakeRecoveryVerifier struct {
	err       error
	gotUserID string
	gotCode   string
	called    bool
}

func (f *fakeRecoveryVerifier) ConsumeCode(_ context.Context, userID, code string) error {
	f.called = true
	f.gotUserID = userID
	f.gotCode = code
	return f.err
}

type fakeScopedSessionIssuer struct {
	token string
	err   error
}

func (f *fakeScopedSessionIssuer) IssueEnrollmentSession(_ context.Context, _ string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	return f.token, nil
}

type fakeRecoveryLimiter struct {
	allow bool
}

func (f *fakeRecoveryLimiter) Allow(_ string) bool { return f.allow }

type fakeRecoveryFactorLister struct {
	factors []RecoveryFactor
	err     error
}

func (f *fakeRecoveryFactorLister) ListFactors(_ context.Context, _ string) ([]RecoveryFactor, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.factors, nil
}

// recoveryAuditEvent captures a single LogRecoveryEvent call for assertions.
type recoveryAuditEvent struct {
	userID    string
	region    string
	eventType string
}

type fakeRecoveryAuditLogger struct {
	events []recoveryAuditEvent
	err    error
}

func (f *fakeRecoveryAuditLogger) LogRecoveryEvent(_ context.Context, userID, region, eventType string) error {
	f.events = append(f.events, recoveryAuditEvent{userID: userID, region: region, eventType: eventType})
	return f.err
}

// containsAuditEvent reports whether the logger recorded an event of the given
// type.
func containsAuditEvent(f *fakeRecoveryAuditLogger, eventType string) bool {
	for _, e := range f.events {
		if e.eventType == eventType {
			return true
		}
	}
	return false
}

// newRecoveryServer builds a Server with the in-memory ceremony store plus the
// given fakes wired in.
func newRecoveryServer(codes RecoveryCodeGenerator, store RecoveryCodeStore, verifier RecoveryVerifier) (*Server, *InMemoryRecoveryCeremonyStore) {
	ceremonies := NewInMemoryRecoveryCeremonyStore()
	s := New(nil, nil).WithRecovery(codes, store, verifier, ceremonies)
	return s, ceremonies
}

// --- POST /recovery/codes ---

func TestPostRecoveryCodes_Success(t *testing.T) {
	gen := &fakeRecoveryCodeGenerator{}
	store := &fakeRecoveryCodeStore{}
	s, _ := newRecoveryServer(gen, store, &fakeRecoveryVerifier{})

	req := httptest.NewRequest(http.MethodPost, "/recovery/codes", strings.NewReader("{}"))
	req.Header.Set(UserIDHeader, "user-1")
	rec := httptest.NewRecorder()
	s.PostRecoveryCodes(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	var resp recoveryCodesResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Count != identity.DefaultCodeCount || len(resp.Codes) != identity.DefaultCodeCount {
		t.Errorf("count = %d / codes = %d, want %d", resp.Count, len(resp.Codes), identity.DefaultCodeCount)
	}
	if len(store.stored) != identity.DefaultCodeCount {
		t.Errorf("stored %d codes, want %d", len(store.stored), identity.DefaultCodeCount)
	}
}

func TestPostRecoveryCodes_Unauthorized(t *testing.T) {
	s, _ := newRecoveryServer(&fakeRecoveryCodeGenerator{}, &fakeRecoveryCodeStore{}, &fakeRecoveryVerifier{})
	req := httptest.NewRequest(http.MethodPost, "/recovery/codes", strings.NewReader("{}"))
	rec := httptest.NewRecorder()
	s.PostRecoveryCodes(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestPostRecoveryCodes_Unavailable(t *testing.T) {
	s := New(nil, nil) // no recovery wired
	req := httptest.NewRequest(http.MethodPost, "/recovery/codes", strings.NewReader("{}"))
	req.Header.Set(UserIDHeader, "user-1")
	rec := httptest.NewRecorder()
	s.PostRecoveryCodes(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

func TestPostRecoveryCodes_RateLimited(t *testing.T) {
	s, _ := newRecoveryServer(&fakeRecoveryCodeGenerator{}, &fakeRecoveryCodeStore{}, &fakeRecoveryVerifier{})
	s.WithRecoveryRateLimiter(&fakeRecoveryLimiter{allow: false})
	req := httptest.NewRequest(http.MethodPost, "/recovery/codes", strings.NewReader("{}"))
	req.Header.Set(UserIDHeader, "user-1")
	rec := httptest.NewRecorder()
	s.PostRecoveryCodes(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rec.Code)
	}
}

func TestPostRecoveryCodes_GenerateError(t *testing.T) {
	s, _ := newRecoveryServer(&fakeRecoveryCodeGenerator{err: errors.New("rng down")}, &fakeRecoveryCodeStore{}, &fakeRecoveryVerifier{})
	req := httptest.NewRequest(http.MethodPost, "/recovery/codes", strings.NewReader("{}"))
	req.Header.Set(UserIDHeader, "user-1")
	rec := httptest.NewRecorder()
	s.PostRecoveryCodes(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

func TestPostRecoveryCodes_StoreError(t *testing.T) {
	s, _ := newRecoveryServer(&fakeRecoveryCodeGenerator{}, &fakeRecoveryCodeStore{err: errors.New("db down")}, &fakeRecoveryVerifier{})
	req := httptest.NewRequest(http.MethodPost, "/recovery/codes", strings.NewReader("{}"))
	req.Header.Set(UserIDHeader, "user-1")
	rec := httptest.NewRecorder()
	s.PostRecoveryCodes(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

// --- POST /recovery/begin ---

func TestPostRecoveryBegin_Success(t *testing.T) {
	s, _ := newRecoveryServer(&fakeRecoveryCodeGenerator{}, &fakeRecoveryCodeStore{}, &fakeRecoveryVerifier{})
	req := httptest.NewRequest(http.MethodPost, "/recovery/begin", strings.NewReader(`{"user_id":"user-1","method":"code"}`))
	rec := httptest.NewRecorder()
	s.PostRecoveryBegin(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp recoveryBeginResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.RecoveryRequestID == "" {
		t.Error("expected a recovery_request_id")
	}
}

func TestPostRecoveryBegin_DefaultsToCodeMethod(t *testing.T) {
	s, _ := newRecoveryServer(&fakeRecoveryCodeGenerator{}, &fakeRecoveryCodeStore{}, &fakeRecoveryVerifier{})
	req := httptest.NewRequest(http.MethodPost, "/recovery/begin", strings.NewReader(`{"user_id":"user-1"}`))
	rec := httptest.NewRecorder()
	s.PostRecoveryBegin(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestPostRecoveryBegin_UnsupportedMethod(t *testing.T) {
	s, _ := newRecoveryServer(&fakeRecoveryCodeGenerator{}, &fakeRecoveryCodeStore{}, &fakeRecoveryVerifier{})
	req := httptest.NewRequest(http.MethodPost, "/recovery/begin", strings.NewReader(`{"user_id":"user-1","method":"totp"}`))
	rec := httptest.NewRecorder()
	s.PostRecoveryBegin(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestPostRecoveryBegin_MissingUserID(t *testing.T) {
	s, _ := newRecoveryServer(&fakeRecoveryCodeGenerator{}, &fakeRecoveryCodeStore{}, &fakeRecoveryVerifier{})
	req := httptest.NewRequest(http.MethodPost, "/recovery/begin", strings.NewReader(`{"method":"code"}`))
	rec := httptest.NewRecorder()
	s.PostRecoveryBegin(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestPostRecoveryBegin_MalformedBody(t *testing.T) {
	s, _ := newRecoveryServer(&fakeRecoveryCodeGenerator{}, &fakeRecoveryCodeStore{}, &fakeRecoveryVerifier{})
	req := httptest.NewRequest(http.MethodPost, "/recovery/begin", strings.NewReader(`{not json`))
	rec := httptest.NewRecorder()
	s.PostRecoveryBegin(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestPostRecoveryBegin_RateLimited(t *testing.T) {
	s, _ := newRecoveryServer(&fakeRecoveryCodeGenerator{}, &fakeRecoveryCodeStore{}, &fakeRecoveryVerifier{})
	s.WithRecoveryRateLimiter(&fakeRecoveryLimiter{allow: false})
	req := httptest.NewRequest(http.MethodPost, "/recovery/begin", strings.NewReader(`{"user_id":"user-1"}`))
	rec := httptest.NewRecorder()
	s.PostRecoveryBegin(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rec.Code)
	}
}

// --- POST /recovery/complete ---

// beginCeremony is a helper that starts a ceremony and returns its request id.
func beginCeremony(t *testing.T, s *Server, host string) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/recovery/begin", strings.NewReader(`{"user_id":"user-1"}`))
	if host != "" {
		req.Host = host
	}
	rec := httptest.NewRecorder()
	s.PostRecoveryBegin(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("begin status = %d, want 200", rec.Code)
	}
	var resp recoveryBeginResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode begin: %v", err)
	}
	return resp.RecoveryRequestID
}

func TestPostRecoveryComplete_Success(t *testing.T) {
	verifier := &fakeRecoveryVerifier{}
	issuer := &fakeScopedSessionIssuer{token: "scoped-token"}
	s, _ := newRecoveryServer(&fakeRecoveryCodeGenerator{}, &fakeRecoveryCodeStore{}, verifier)
	s.WithScopedSessionIssuer(issuer)

	id := beginCeremony(t, s, "eu.harbor.test")

	body := `{"recovery_request_id":"` + id + `","code":"CODE-0000"}`
	req := httptest.NewRequest(http.MethodPost, "/recovery/complete", strings.NewReader(body))
	req.Host = "eu.harbor.test"
	rec := httptest.NewRecorder()
	s.PostRecoveryComplete(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if !verifier.called || verifier.gotUserID != "user-1" || verifier.gotCode != "CODE-0000" {
		t.Errorf("verifier not called correctly: %+v", verifier)
	}
	// Scoped session cookie must be set.
	var found bool
	for _, c := range rec.Result().Cookies() {
		if c.Name == RecoveryScopedSessionCookieName && c.Value == "scoped-token" {
			found = true
		}
	}
	if !found {
		t.Error("expected scoped session cookie to be set")
	}
}

func TestPostRecoveryComplete_UnknownCeremony(t *testing.T) {
	s, _ := newRecoveryServer(&fakeRecoveryCodeGenerator{}, &fakeRecoveryCodeStore{}, &fakeRecoveryVerifier{})
	body := `{"recovery_request_id":"does-not-exist","code":"CODE-0000"}`
	req := httptest.NewRequest(http.MethodPost, "/recovery/complete", strings.NewReader(body))
	rec := httptest.NewRecorder()
	s.PostRecoveryComplete(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (uniform failure)", rec.Code)
	}
}

func TestPostRecoveryComplete_InvalidCode(t *testing.T) {
	verifier := &fakeRecoveryVerifier{err: identity.ErrInvalidCode}
	s, _ := newRecoveryServer(&fakeRecoveryCodeGenerator{}, &fakeRecoveryCodeStore{}, verifier)
	id := beginCeremony(t, s, "eu.harbor.test")
	body := `{"recovery_request_id":"` + id + `","code":"WRONG"}`
	req := httptest.NewRequest(http.MethodPost, "/recovery/complete", strings.NewReader(body))
	req.Host = "eu.harbor.test"
	rec := httptest.NewRecorder()
	s.PostRecoveryComplete(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (uniform failure)", rec.Code)
	}
}

func TestPostRecoveryComplete_LockedOut(t *testing.T) {
	verifier := &fakeRecoveryVerifier{err: identity.ErrUserLocked}
	s, _ := newRecoveryServer(&fakeRecoveryCodeGenerator{}, &fakeRecoveryCodeStore{}, verifier)
	id := beginCeremony(t, s, "eu.harbor.test")
	body := `{"recovery_request_id":"` + id + `","code":"CODE-0000"}`
	req := httptest.NewRequest(http.MethodPost, "/recovery/complete", strings.NewReader(body))
	req.Host = "eu.harbor.test"
	rec := httptest.NewRecorder()
	s.PostRecoveryComplete(rec, req)
	// Lockout must return the SAME uniform failure as an invalid code so it does
	// not leak that the account exists and is locked.
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (uniform failure for lockout)", rec.Code)
	}
}

func TestPostRecoveryComplete_RegionMismatch(t *testing.T) {
	verifier := &fakeRecoveryVerifier{}
	s, _ := newRecoveryServer(&fakeRecoveryCodeGenerator{}, &fakeRecoveryCodeStore{}, verifier)
	id := beginCeremony(t, s, "eu.harbor.test")
	// Complete from a different region (host) → uniform failure, verifier untouched.
	body := `{"recovery_request_id":"` + id + `","code":"CODE-0000"}`
	req := httptest.NewRequest(http.MethodPost, "/recovery/complete", strings.NewReader(body))
	req.Host = "us.harbor.test"
	rec := httptest.NewRecorder()
	s.PostRecoveryComplete(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (region mismatch)", rec.Code)
	}
	if verifier.called {
		t.Error("verifier must not be called on region mismatch")
	}
}

// TestPostRecoveryComplete_RateLimited_DoesNotVerify proves the rate limiter
// throttles brute force fail-closed: when the limiter denies, the request is
// rejected with 429 and the code is NEVER checked.
//
//harbor:invariant INV-RECOVERY-RATE-LIMITED
func TestPostRecoveryComplete_RateLimited_DoesNotVerify(t *testing.T) {
	verifier := &fakeRecoveryVerifier{}
	s, _ := newRecoveryServer(&fakeRecoveryCodeGenerator{}, &fakeRecoveryCodeStore{}, verifier)
	id := beginCeremony(t, s, "eu.harbor.test")
	// Deny only after the ceremony exists so we reach the complete rate-limit gate.
	s.WithRecoveryRateLimiter(&fakeRecoveryLimiter{allow: false})

	body := `{"recovery_request_id":"` + id + `","code":"CODE-0000"}`
	req := httptest.NewRequest(http.MethodPost, "/recovery/complete", strings.NewReader(body))
	req.Host = "eu.harbor.test"
	rec := httptest.NewRecorder()
	s.PostRecoveryComplete(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rec.Code)
	}
	if verifier.called {
		t.Error("verifier must NOT be called when rate-limited (brute-force throttle)")
	}
}

// TestPostRecoveryComplete_UniformFailureBodies proves every failure mode —
// invalid code, lockout, region mismatch, and unknown ceremony — returns a
// byte-identical response, so the endpoint is not an oracle for account
// existence, lockout state, or how close a code was (docs/DESIGN.md §6.5).
//
//harbor:invariant INV-RECOVERY-UNIFORM-FAILURE
func TestPostRecoveryComplete_UniformFailureBodies(t *testing.T) {
	// fail runs one /recovery/complete failure path and returns (status, body).
	// A non-empty reqID skips beginCeremony (used for the unknown-ceremony case).
	fail := func(verifierErr error, beginHost, completeHost, reqID string) (int, string) {
		s, _ := newRecoveryServer(&fakeRecoveryCodeGenerator{}, &fakeRecoveryCodeStore{}, &fakeRecoveryVerifier{err: verifierErr})
		id := reqID
		if id == "" {
			id = beginCeremony(t, s, beginHost)
		}
		body := `{"recovery_request_id":"` + id + `","code":"CODE-0000"}`
		req := httptest.NewRequest(http.MethodPost, "/recovery/complete", strings.NewReader(body))
		req.Host = completeHost
		rec := httptest.NewRecorder()
		s.PostRecoveryComplete(rec, req)
		return rec.Code, rec.Body.String()
	}

	invalidStatus, invalidBody := fail(identity.ErrInvalidCode, "eu.harbor.test", "eu.harbor.test", "")
	lockedStatus, lockedBody := fail(identity.ErrUserLocked, "eu.harbor.test", "eu.harbor.test", "")
	mismatchStatus, mismatchBody := fail(nil, "eu.harbor.test", "us.harbor.test", "")
	unknownStatus, unknownBody := fail(nil, "", "eu.harbor.test", "does-not-exist")

	if invalidStatus != http.StatusUnauthorized || lockedStatus != http.StatusUnauthorized ||
		mismatchStatus != http.StatusUnauthorized || unknownStatus != http.StatusUnauthorized {
		t.Fatalf("statuses differ: invalid=%d locked=%d mismatch=%d unknown=%d",
			invalidStatus, lockedStatus, mismatchStatus, unknownStatus)
	}
	if invalidBody != lockedBody || invalidBody != mismatchBody || invalidBody != unknownBody {
		t.Errorf("failure bodies differ (oracle!):\n invalid=%q\n locked=%q\n mismatch=%q\n unknown=%q",
			invalidBody, lockedBody, mismatchBody, unknownBody)
	}
}

func TestPostRecoveryComplete_MissingFields(t *testing.T) {
	s, _ := newRecoveryServer(&fakeRecoveryCodeGenerator{}, &fakeRecoveryCodeStore{}, &fakeRecoveryVerifier{})
	req := httptest.NewRequest(http.MethodPost, "/recovery/complete", strings.NewReader(`{"code":"CODE-0000"}`))
	rec := httptest.NewRecorder()
	s.PostRecoveryComplete(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestPostRecoveryComplete_Unavailable(t *testing.T) {
	s := New(nil, nil) // no recovery wired
	req := httptest.NewRequest(http.MethodPost, "/recovery/complete", strings.NewReader(`{"recovery_request_id":"x","code":"y"}`))
	rec := httptest.NewRecorder()
	s.PostRecoveryComplete(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

func TestPostRecoveryComplete_OneTimeUse(t *testing.T) {
	verifier := &fakeRecoveryVerifier{}
	s, _ := newRecoveryServer(&fakeRecoveryCodeGenerator{}, &fakeRecoveryCodeStore{}, verifier)
	id := beginCeremony(t, s, "eu.harbor.test")
	body := `{"recovery_request_id":"` + id + `","code":"CODE-0000"}`

	// First completion succeeds.
	req1 := httptest.NewRequest(http.MethodPost, "/recovery/complete", strings.NewReader(body))
	req1.Host = "eu.harbor.test"
	rec1 := httptest.NewRecorder()
	s.PostRecoveryComplete(rec1, req1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("first completion status = %d, want 200", rec1.Code)
	}

	// Second completion with the same ceremony must fail uniformly (ceremony was
	// deleted after the first success).
	req2 := httptest.NewRequest(http.MethodPost, "/recovery/complete", strings.NewReader(body))
	req2.Host = "eu.harbor.test"
	rec2 := httptest.NewRecorder()
	s.PostRecoveryComplete(rec2, req2)
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("replay status = %d, want 401", rec2.Code)
	}
}

// --- GET /recovery/factors ---

func TestListCredentialsByUser_Success(t *testing.T) {
	lister := &fakeRecoveryFactorLister{factors: []RecoveryFactor{
		{ID: "cred-1", Type: "passkey", AAGUID: "AAGUID-1"},
		{ID: "cred-2", Type: "passkey"},
	}}
	s, _ := newRecoveryServer(&fakeRecoveryCodeGenerator{}, &fakeRecoveryCodeStore{}, &fakeRecoveryVerifier{})
	s.WithRecoveryFactors(lister)

	req := httptest.NewRequest(http.MethodGet, "/recovery/factors", nil)
	req.Header.Set(UserIDHeader, "user-1")
	rec := httptest.NewRecorder()
	s.ListCredentialsByUser(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp recoveryFactorsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Count != 2 || len(resp.Factors) != 2 {
		t.Errorf("count = %d / factors = %d, want 2", resp.Count, len(resp.Factors))
	}
	if resp.Factors[0].ID != "cred-1" || resp.Factors[0].Type != "passkey" {
		t.Errorf("factor[0] = %+v, want {cred-1 passkey ...}", resp.Factors[0])
	}
}

func TestListCredentialsByUser_EmptyIsArray(t *testing.T) {
	s, _ := newRecoveryServer(&fakeRecoveryCodeGenerator{}, &fakeRecoveryCodeStore{}, &fakeRecoveryVerifier{})
	s.WithRecoveryFactors(&fakeRecoveryFactorLister{}) // nil factors

	req := httptest.NewRequest(http.MethodGet, "/recovery/factors", nil)
	req.Header.Set(UserIDHeader, "user-1")
	rec := httptest.NewRecorder()
	s.ListCredentialsByUser(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	// An empty list must serialize as [] (not null) so clients can iterate.
	if !strings.Contains(rec.Body.String(), `"factors":[]`) {
		t.Errorf("body = %s, want factors:[]", rec.Body.String())
	}
}

func TestListCredentialsByUser_Unauthorized(t *testing.T) {
	s, _ := newRecoveryServer(&fakeRecoveryCodeGenerator{}, &fakeRecoveryCodeStore{}, &fakeRecoveryVerifier{})
	s.WithRecoveryFactors(&fakeRecoveryFactorLister{})
	req := httptest.NewRequest(http.MethodGet, "/recovery/factors", nil)
	rec := httptest.NewRecorder()
	s.ListCredentialsByUser(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestListCredentialsByUser_Unavailable(t *testing.T) {
	s, _ := newRecoveryServer(&fakeRecoveryCodeGenerator{}, &fakeRecoveryCodeStore{}, &fakeRecoveryVerifier{})
	// No factor lister wired.
	req := httptest.NewRequest(http.MethodGet, "/recovery/factors", nil)
	req.Header.Set(UserIDHeader, "user-1")
	rec := httptest.NewRecorder()
	s.ListCredentialsByUser(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

func TestListCredentialsByUser_RateLimited(t *testing.T) {
	s, _ := newRecoveryServer(&fakeRecoveryCodeGenerator{}, &fakeRecoveryCodeStore{}, &fakeRecoveryVerifier{})
	s.WithRecoveryFactors(&fakeRecoveryFactorLister{})
	s.WithRecoveryRateLimiter(&fakeRecoveryLimiter{allow: false})
	req := httptest.NewRequest(http.MethodGet, "/recovery/factors", nil)
	req.Header.Set(UserIDHeader, "user-1")
	rec := httptest.NewRecorder()
	s.ListCredentialsByUser(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rec.Code)
	}
}

func TestListCredentialsByUser_ListError(t *testing.T) {
	s, _ := newRecoveryServer(&fakeRecoveryCodeGenerator{}, &fakeRecoveryCodeStore{}, &fakeRecoveryVerifier{})
	s.WithRecoveryFactors(&fakeRecoveryFactorLister{err: errors.New("db down")})
	req := httptest.NewRequest(http.MethodGet, "/recovery/factors", nil)
	req.Header.Set(UserIDHeader, "user-1")
	rec := httptest.NewRecorder()
	s.ListCredentialsByUser(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

func TestListCredentialsByUser_Routed(t *testing.T) {
	s, _ := newRecoveryServer(&fakeRecoveryCodeGenerator{}, &fakeRecoveryCodeStore{}, &fakeRecoveryVerifier{})
	s.WithRecoveryFactors(&fakeRecoveryFactorLister{factors: []RecoveryFactor{{ID: "cred-1", Type: "passkey"}}})
	mux := http.NewServeMux()
	s.Routes(mux)

	req := httptest.NewRequest(http.MethodGet, "/recovery/factors", nil)
	req.Header.Set(UserIDHeader, "user-1")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("routed status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
}

// --- recovery audit trail ---

func TestPostRecoveryBegin_EmitsBeginAuditEvent(t *testing.T) {
	audit := &fakeRecoveryAuditLogger{}
	s, _ := newRecoveryServer(&fakeRecoveryCodeGenerator{}, &fakeRecoveryCodeStore{}, &fakeRecoveryVerifier{})
	s.WithRecoveryAuditLog(audit)

	req := httptest.NewRequest(http.MethodPost, "/recovery/begin", strings.NewReader(`{"user_id":"user-1"}`))
	req.Host = "eu.harbor.test"
	rec := httptest.NewRecorder()
	s.PostRecoveryBegin(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if len(audit.events) != 1 {
		t.Fatalf("audit events = %d, want 1", len(audit.events))
	}
	got := audit.events[0]
	if got.eventType != auditRecoveryBegin || got.userID != "user-1" || got.region != "eu.harbor.test" {
		t.Errorf("audit event = %+v, want begin for user-1 @ eu.harbor.test", got)
	}
}

func TestPostRecoveryComplete_EmitsSucceededAuditEvent(t *testing.T) {
	audit := &fakeRecoveryAuditLogger{}
	s, _ := newRecoveryServer(&fakeRecoveryCodeGenerator{}, &fakeRecoveryCodeStore{}, &fakeRecoveryVerifier{})
	s.WithRecoveryAuditLog(audit)

	id := beginCeremony(t, s, "eu.harbor.test")
	body := `{"recovery_request_id":"` + id + `","code":"CODE-0000"}`
	req := httptest.NewRequest(http.MethodPost, "/recovery/complete", strings.NewReader(body))
	req.Host = "eu.harbor.test"
	rec := httptest.NewRecorder()
	s.PostRecoveryComplete(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !containsAuditEvent(audit, auditRecoverySucceeded) {
		t.Errorf("expected a %q audit event, got %+v", auditRecoverySucceeded, audit.events)
	}
}

func TestPostRecoveryComplete_InvalidCodeEmitsFailedAuditEvent(t *testing.T) {
	audit := &fakeRecoveryAuditLogger{}
	s, _ := newRecoveryServer(&fakeRecoveryCodeGenerator{}, &fakeRecoveryCodeStore{}, &fakeRecoveryVerifier{err: identity.ErrInvalidCode})
	s.WithRecoveryAuditLog(audit)

	id := beginCeremony(t, s, "eu.harbor.test")
	body := `{"recovery_request_id":"` + id + `","code":"WRONG"}`
	req := httptest.NewRequest(http.MethodPost, "/recovery/complete", strings.NewReader(body))
	req.Host = "eu.harbor.test"
	rec := httptest.NewRecorder()
	s.PostRecoveryComplete(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if !containsAuditEvent(audit, auditRecoveryFailed) {
		t.Errorf("expected a %q audit event, got %+v", auditRecoveryFailed, audit.events)
	}
	if containsAuditEvent(audit, auditRecoverySucceeded) {
		t.Error("must NOT emit succeeded on an invalid code")
	}
}

func TestPostRecoveryComplete_LockedOutEmitsFailedAuditEvent(t *testing.T) {
	audit := &fakeRecoveryAuditLogger{}
	s, _ := newRecoveryServer(&fakeRecoveryCodeGenerator{}, &fakeRecoveryCodeStore{}, &fakeRecoveryVerifier{err: identity.ErrUserLocked})
	s.WithRecoveryAuditLog(audit)

	id := beginCeremony(t, s, "eu.harbor.test")
	body := `{"recovery_request_id":"` + id + `","code":"CODE-0000"}`
	req := httptest.NewRequest(http.MethodPost, "/recovery/complete", strings.NewReader(body))
	req.Host = "eu.harbor.test"
	rec := httptest.NewRecorder()
	s.PostRecoveryComplete(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if !containsAuditEvent(audit, auditRecoveryFailed) {
		t.Errorf("expected a %q audit event on lockout, got %+v", auditRecoveryFailed, audit.events)
	}
}

func TestPostRecoveryComplete_RegionMismatchEmitsFailedAuditEvent(t *testing.T) {
	audit := &fakeRecoveryAuditLogger{}
	s, _ := newRecoveryServer(&fakeRecoveryCodeGenerator{}, &fakeRecoveryCodeStore{}, &fakeRecoveryVerifier{})
	s.WithRecoveryAuditLog(audit)

	id := beginCeremony(t, s, "eu.harbor.test")
	body := `{"recovery_request_id":"` + id + `","code":"CODE-0000"}`
	req := httptest.NewRequest(http.MethodPost, "/recovery/complete", strings.NewReader(body))
	req.Host = "us.harbor.test"
	rec := httptest.NewRecorder()
	s.PostRecoveryComplete(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if !containsAuditEvent(audit, auditRecoveryFailed) {
		t.Errorf("expected a %q audit event on region mismatch, got %+v", auditRecoveryFailed, audit.events)
	}
}

func TestPostRecoveryComplete_UnknownCeremonyEmitsNoAuditEvent(t *testing.T) {
	audit := &fakeRecoveryAuditLogger{}
	s, _ := newRecoveryServer(&fakeRecoveryCodeGenerator{}, &fakeRecoveryCodeStore{}, &fakeRecoveryVerifier{})
	s.WithRecoveryAuditLog(audit)

	body := `{"recovery_request_id":"does-not-exist","code":"CODE-0000"}`
	req := httptest.NewRequest(http.MethodPost, "/recovery/complete", strings.NewReader(body))
	rec := httptest.NewRecorder()
	s.PostRecoveryComplete(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	// No user is resolved for an unknown ceremony, so nothing can be keyed to a
	// trail — no event must be recorded.
	if len(audit.events) != 0 {
		t.Errorf("audit events = %+v, want none for an unknown ceremony", audit.events)
	}
}

// TestRecoveryAudit_WriteErrorIsSwallowed proves that a failing audit logger
// never fails the ceremony: begin still returns 200.
func TestRecoveryAudit_WriteErrorIsSwallowed(t *testing.T) {
	audit := &fakeRecoveryAuditLogger{err: errors.New("audit db down")}
	s, _ := newRecoveryServer(&fakeRecoveryCodeGenerator{}, &fakeRecoveryCodeStore{}, &fakeRecoveryVerifier{})
	s.WithRecoveryAuditLog(audit)

	req := httptest.NewRequest(http.MethodPost, "/recovery/begin", strings.NewReader(`{"user_id":"user-1"}`))
	rec := httptest.NewRecorder()
	s.PostRecoveryBegin(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (audit failure must not fail the ceremony)", rec.Code)
	}
}

// --- routing ---

func TestRoutesRegistersRecovery(t *testing.T) {
	s, _ := newRecoveryServer(&fakeRecoveryCodeGenerator{}, &fakeRecoveryCodeStore{}, &fakeRecoveryVerifier{})
	mux := http.NewServeMux()
	s.Routes(mux)

	req := httptest.NewRequest(http.MethodPost, "/recovery/begin", strings.NewReader(`{"user_id":"user-1"}`))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("routed status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
}

// --- in-memory ceremony store ---

func TestInMemoryRecoveryCeremonyStore_SaveLookupDelete(t *testing.T) {
	store := NewInMemoryRecoveryCeremonyStore()
	ctx := context.Background()

	if err := store.Save(ctx, "req-1", "user-1", "eu"); err != nil {
		t.Fatalf("Save: %v", err)
	}
	userID, region, err := store.Lookup(ctx, "req-1")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if userID != "user-1" || region != "eu" {
		t.Errorf("Lookup = (%q,%q), want (user-1,eu)", userID, region)
	}
	if err := store.Delete(ctx, "req-1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, _, err := store.Lookup(ctx, "req-1"); !errors.Is(err, ErrRecoveryCeremonyNotFound) {
		t.Errorf("Lookup after delete = %v, want ErrRecoveryCeremonyNotFound", err)
	}
}

func TestInMemoryRecoveryCeremonyStore_LookupUnknown(t *testing.T) {
	store := NewInMemoryRecoveryCeremonyStore()
	if _, _, err := store.Lookup(context.Background(), "nope"); !errors.Is(err, ErrRecoveryCeremonyNotFound) {
		t.Errorf("Lookup(unknown) = %v, want ErrRecoveryCeremonyNotFound", err)
	}
}
