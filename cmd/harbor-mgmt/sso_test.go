package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/harbor-auth/harbor/internal/bff"
	"github.com/harbor-auth/harbor/internal/cloudapi"
	"github.com/harbor-auth/harbor/internal/identity"
	"github.com/harbor-auth/harbor/internal/oidc"
	bfftest "github.com/harbor-auth/harbor/internal/testsupport/bff"
)

// --- fakes ---------------------------------------------------------------

// fakeActiveUserChecker answers UserActive from a fixed map, defaulting to
// "not active" for any id not explicitly listed.
type fakeActiveUserChecker struct {
	active map[string]bool
	err    error
}

func (f fakeActiveUserChecker) UserActive(_ context.Context, userID string) (bool, error) {
	if f.err != nil {
		return false, f.err
	}
	return f.active[userID], nil
}

// fakeAuditRecord captures one RecordAsync call.
type fakeAuditRecord struct {
	userID string
	event  identity.EventType
	detail any
}

type fakeAuditRecorder struct {
	records []fakeAuditRecord
}

func (f *fakeAuditRecorder) RecordAsync(_ context.Context, userID string, et identity.EventType, _ *string, detail any) {
	f.records = append(f.records, fakeAuditRecord{userID: userID, event: et, detail: detail})
}

func newSSOTestDeps(t *testing.T) (*cloudapi.RedisLoginCodeStore, *bfftest.InMemoryBFFSessionStore, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() }) //nolint:errcheck // test cleanup
	return cloudapi.NewRedisLoginCodeStore(client), bfftest.NewInMemoryBFFSessionStore(), mr
}

// newSSOTestHandler wires wireSSOLoginRoute with an active "user-1" and an
// always-allow rate limiter — the baseline every scenario below narrows.
func newSSOTestHandler(t *testing.T) (http.HandlerFunc, *cloudapi.RedisLoginCodeStore, *bfftest.InMemoryBFFSessionStore, *fakeAuditRecorder) {
	t.Helper()
	codes, sessions, _ := newSSOTestDeps(t)
	audit := &fakeAuditRecorder{}
	users := fakeActiveUserChecker{active: map[string]bool{"user-1": true}}
	h := wireSSOLoginRoute(codes, sessions, users, audit, alwaysAllow(), "/dashboard", discardLogger())
	return h, codes, sessions, audit
}

func doGetLoginSSO(h http.HandlerFunc, code string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/login/sso?code="+code, nil)
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec
}

// bffCookieValue extracts the __Host-harbor-bff cookie's value (the BFF
// session request_id) from rec, or "" if no such cookie was set.
func bffCookieValue(rec *httptest.ResponseRecorder) string {
	for _, c := range rec.Result().Cookies() {
		if c.Name == bff.CookieName {
			return c.Value
		}
	}
	return ""
}

// --- tests -----------------------------------------------------------------

func TestSSOLoginSuccessRedeemsCodeExactlyOnce(t *testing.T) {
	h, codes, sessions, audit := newSSOTestHandler(t)
	code, err := codes.Issue(context.Background(), cloudapi.LoginCode{UserID: "user-1", NamespaceID: "acme", IssuedAt: time.Now()})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	first := doGetLoginSSO(h, code)
	if first.Code != http.StatusSeeOther {
		t.Fatalf("first request status = %d, want 303; body = %s", first.Code, first.Body.String())
	}
	if got := first.Header().Get("Location"); got != "/dashboard" {
		t.Errorf("Location = %q, want /dashboard", got)
	}

	// The session the handler created must carry the SSO security
	// properties: full scope, recovery not required, federated auth method,
	// and — the load-bearing property — a NIL BrowserNonceHash.
	requestID := bffCookieValue(first)
	if requestID == "" {
		t.Fatal("no __Host-harbor-bff cookie was set on success")
	}
	record, err := sessions.Get(context.Background(), requestID)
	if err != nil {
		t.Fatalf("sessions.Get(%q): %v", requestID, err)
	}
	if record.UserID != "user-1" {
		t.Errorf("session UserID = %q, want user-1", record.UserID)
	}
	if record.SessionScope != bff.SessionScopeFull {
		t.Errorf("session SessionScope = %q, want full", record.SessionScope)
	}
	if record.RecoveryRequired {
		t.Error("session RecoveryRequired = true, want false")
	}
	if record.AuthMethod != oidc.AuthMethodFederated {
		t.Errorf("session AuthMethod = %q, want federated", record.AuthMethod)
	}
	if len(record.BrowserNonceHash) != 0 {
		t.Error("session BrowserNonceHash must be nil/empty — a non-empty hash would let this session complete an OIDC authorization it never proved browser ownership for")
	}

	if len(audit.records) != 1 {
		t.Fatalf("got %d audit records, want 1", len(audit.records))
	}
	if audit.records[0].userID != "user-1" || audit.records[0].event != identity.EventAuthLogin {
		t.Errorf("audit record = %+v, want userID=user-1 event=auth.login", audit.records[0])
	}

	// Second redemption of the SAME code must fail — single-use.
	second := doGetLoginSSO(h, code)
	if second.Code != http.StatusBadRequest {
		t.Fatalf("second request status = %d, want 400 (code already consumed); body = %s", second.Code, second.Body.String())
	}
}

func TestSSOLoginExpiredCodeFails(t *testing.T) {
	codes, sessions, mr := newSSOTestDeps(t)
	audit := &fakeAuditRecorder{}
	users := fakeActiveUserChecker{active: map[string]bool{"user-1": true}}
	h := wireSSOLoginRoute(codes, sessions, users, audit, alwaysAllow(), "/dashboard", discardLogger())

	code, err := codes.Issue(context.Background(), cloudapi.LoginCode{UserID: "user-1", NamespaceID: "acme", IssuedAt: time.Now()})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	mr.FastForward(3 * time.Minute) // > loginCodeTTL

	rec := doGetLoginSSO(h, code)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body = %s", rec.Code, rec.Body.String())
	}
	if bffCookieValue(rec) != "" {
		t.Error("an expired code must never create a BFF session")
	}
}

// TestSSOLoginIdenticalGenericErrorForEveryFailure proves expired, unknown,
// and already-consumed codes are indistinguishable to the caller — same
// status code and same response body — so a caller can never learn which
// case applied.
func TestSSOLoginIdenticalGenericErrorForEveryFailure(t *testing.T) {
	codes, sessions, mr := newSSOTestDeps(t)
	audit := &fakeAuditRecorder{}
	users := fakeActiveUserChecker{active: map[string]bool{"user-1": true}}
	h := wireSSOLoginRoute(codes, sessions, users, audit, alwaysAllow(), "/dashboard", discardLogger())

	unknown := doGetLoginSSO(h, "never-issued-code-xyz")

	expiredCode, err := codes.Issue(context.Background(), cloudapi.LoginCode{UserID: "user-1", NamespaceID: "acme", IssuedAt: time.Now()})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	mr.FastForward(3 * time.Minute)
	expired := doGetLoginSSO(h, expiredCode)

	consumedCode, err := codes.Issue(context.Background(), cloudapi.LoginCode{UserID: "user-1", NamespaceID: "acme", IssuedAt: time.Now()})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if rec := doGetLoginSSO(h, consumedCode); rec.Code != http.StatusSeeOther {
		t.Fatalf("priming consume: status = %d, want 303", rec.Code)
	}
	consumed := doGetLoginSSO(h, consumedCode)

	for name, rec := range map[string]*httptest.ResponseRecorder{"unknown": unknown, "expired": expired, "already-consumed": consumed} {
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", name, rec.Code)
		}
	}
	if unknown.Body.String() != expired.Body.String() || expired.Body.String() != consumed.Body.String() {
		t.Errorf("error bodies differ across failure modes:\nunknown:  %s\nexpired:  %s\nconsumed: %s",
			unknown.Body.String(), expired.Body.String(), consumed.Body.String())
	}
}

func TestSSOLoginInactiveUserFails(t *testing.T) {
	codes, sessions, _ := newSSOTestDeps(t)
	audit := &fakeAuditRecorder{}
	users := fakeActiveUserChecker{active: map[string]bool{}} // user-1 NOT active
	h := wireSSOLoginRoute(codes, sessions, users, audit, alwaysAllow(), "/dashboard", discardLogger())

	code, err := codes.Issue(context.Background(), cloudapi.LoginCode{UserID: "user-1", NamespaceID: "acme", IssuedAt: time.Now()})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	rec := doGetLoginSSO(h, code)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body = %s", rec.Code, rec.Body.String())
	}
	if bffCookieValue(rec) != "" {
		t.Error("an inactive user must never get a BFF session")
	}
}

func TestSSOLoginEmptyCodeFails(t *testing.T) {
	h, _, _, _ := newSSOTestHandler(t)
	rec := doGetLoginSSO(h, "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body = %s", rec.Code, rec.Body.String())
	}
}

func TestSSOLoginResponseHeaders(t *testing.T) {
	h, codes, _, _ := newSSOTestHandler(t)
	code, err := codes.Issue(context.Background(), cloudapi.LoginCode{UserID: "user-1", NamespaceID: "acme", IssuedAt: time.Now()})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	rec := doGetLoginSSO(h, code)

	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	if got := rec.Header().Get("Referrer-Policy"); got != "no-referrer" {
		t.Errorf("Referrer-Policy = %q, want no-referrer", got)
	}
}

// TestSSOLoginErrorResponseAlsoCarriesSecurityHeaders proves the headers are
// set unconditionally, before any validation short-circuit — not only on
// the success path.
func TestSSOLoginErrorResponseAlsoCarriesSecurityHeaders(t *testing.T) {
	h, _, _, _ := newSSOTestHandler(t)
	rec := doGetLoginSSO(h, "")
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	if got := rec.Header().Get("Referrer-Policy"); got != "no-referrer" {
		t.Errorf("Referrer-Policy = %q, want no-referrer", got)
	}
}

func TestSSOLoginCookieAttributes(t *testing.T) {
	h, codes, _, _ := newSSOTestHandler(t)
	code, err := codes.Issue(context.Background(), cloudapi.LoginCode{UserID: "user-1", NamespaceID: "acme", IssuedAt: time.Now()})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	rec := doGetLoginSSO(h, code)

	var found *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == bff.CookieName {
			found = c
			break
		}
	}
	if found == nil {
		t.Fatalf("no %s cookie set; headers = %v", bff.CookieName, rec.Header())
	}
	if found.Name != "__Host-harbor-bff" {
		t.Errorf("cookie name = %q, want __Host-harbor-bff", found.Name)
	}
	if !found.HttpOnly {
		t.Error("cookie is not HttpOnly")
	}
	if !found.Secure {
		t.Error("cookie is not Secure")
	}
	if found.SameSite != http.SameSiteStrictMode {
		t.Errorf("cookie SameSite = %v, want Strict", found.SameSite)
	}
	if found.Path != "/" {
		t.Errorf("cookie Path = %q, want /", found.Path)
	}

	// Never the enrollment/recovery cookies — this is not an enrollment
	// session and must not unlock the WebAuthn ceremony endpoints.
	for _, c := range rec.Result().Cookies() {
		if c.Name == "harbor_enrollment_session" || c.Name == "__Host-harbor-recovery-session" {
			t.Errorf("unexpected enrollment/recovery cookie set: %s", c.Name)
		}
	}
}

func TestSSOLoginRedirectsToFixedDashboardPath(t *testing.T) {
	codes, sessions, _ := newSSOTestDeps(t)
	audit := &fakeAuditRecorder{}
	users := fakeActiveUserChecker{active: map[string]bool{"user-1": true}}
	h := wireSSOLoginRoute(codes, sessions, users, audit, alwaysAllow(), "/custom-dashboard", discardLogger())

	code, err := codes.Issue(context.Background(), cloudapi.LoginCode{UserID: "user-1", NamespaceID: "acme", IssuedAt: time.Now()})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	rec := doGetLoginSSO(h, code)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", rec.Code)
	}
	if got := rec.Header().Get("Location"); got != "/custom-dashboard" {
		t.Errorf("Location = %q, want /custom-dashboard", got)
	}
}

// TestSSOLoginRateLimiterFailsClosed proves a rate-limiter backend error is
// treated exactly like an over-limit request — never an implicit pass.
func TestSSOLoginRateLimiterFailsClosed(t *testing.T) {
	codes, sessions, _ := newSSOTestDeps(t)
	audit := &fakeAuditRecorder{}
	users := fakeActiveUserChecker{active: map[string]bool{"user-1": true}}
	limiter := fakeRateLimiter{allowed: false, err: errors.New("redis: connection refused")}
	h := wireSSOLoginRoute(codes, sessions, users, audit, limiter, "/dashboard", discardLogger())

	code, err := codes.Issue(context.Background(), cloudapi.LoginCode{UserID: "user-1", NamespaceID: "acme", IssuedAt: time.Now()})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	rec := doGetLoginSSO(h, code)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429; body = %s", rec.Code, rec.Body.String())
	}
	// The code must not have been consumed by a request that never got past
	// the rate limiter.
	if _, err := codes.Consume(context.Background(), code); err != nil {
		t.Errorf("code was consumed despite being rate-limited: %v", err)
	}
}

func TestSSOLoginRateLimiterOverLimit(t *testing.T) {
	codes, sessions, _ := newSSOTestDeps(t)
	audit := &fakeAuditRecorder{}
	users := fakeActiveUserChecker{active: map[string]bool{"user-1": true}}
	limiter := fakeRateLimiter{allowed: false, err: nil}
	h := wireSSOLoginRoute(codes, sessions, users, audit, limiter, "/dashboard", discardLogger())

	rec := doGetLoginSSO(h, "irrelevant-code")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429; body = %s", rec.Code, rec.Body.String())
	}
}

// --- validateSSODashboardPath / decodeSSOSubjectHMACKey --------------------

func TestValidateSSODashboardPath(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		want    string
		wantErr bool
	}{
		{name: "empty defaults", raw: "", want: defaultSSODashboardPath},
		{name: "valid absolute path", raw: "/custom", want: "/custom"},
		{name: "missing leading slash", raw: "custom", wantErr: true},
		{name: "protocol-relative", raw: "//evil.example.com", wantErr: true},
		{name: "full URL", raw: "https://evil.example.com/dashboard", wantErr: true},
		{name: "embedded whitespace", raw: "/dash board", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := validateSSODashboardPath(tc.raw)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("validateSSODashboardPath(%q): expected an error, got %q", tc.raw, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("validateSSODashboardPath(%q): unexpected error: %v", tc.raw, err)
			}
			if got != tc.want {
				t.Errorf("validateSSODashboardPath(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

func TestDecodeSSOSubjectHMACKey(t *testing.T) {
	if _, err := decodeSSOSubjectHMACKey(""); err == nil {
		t.Error("expected an error for an empty key")
	}
	if _, err := decodeSSOSubjectHMACKey("not-valid-base64url-or-hex!!!"); err == nil {
		t.Error("expected an error for an undecodable key")
	}
	// hex-encoded 32 bytes
	if b, err := decodeSSOSubjectHMACKey("aabbccddeeff00112233445566778899aabbccddeeff0011223344556677"); err != nil || len(b) == 0 {
		t.Errorf("decode hex key: got %v, %v", b, err)
	}
}
