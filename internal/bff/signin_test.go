package bff

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/harbor-auth/harbor/web"
)

func testSigninTemplates(t *testing.T) *template.Template {
	t.Helper()
	tmpl, err := web.ParseDashboardTemplates()
	if err != nil {
		t.Fatalf("parse templates: %v", err)
	}
	return tmpl
}

func TestNewSigninHandler_RequiresSessionsAndTemplate(t *testing.T) {
	tmpl := testSigninTemplates(t)
	store := NewInMemoryBFFSessionStore()

	if _, err := NewSigninHandler(nil, tmpl, 5*time.Minute, nil, nil); err == nil {
		t.Error("expected error when sessions store is nil")
	}
	if _, err := NewSigninHandler(store, nil, 5*time.Minute, nil, nil); err == nil {
		t.Error("expected error when template is nil")
	}
	if _, err := NewSigninHandler(store, tmpl, 5*time.Minute, nil, nil); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSigninHandler_ServeSignin_HappyPath(t *testing.T) {
	store := NewInMemoryBFFSessionStore()
	handler, err := NewSigninHandler(store, testSigninTemplates(t), 5*time.Minute, []string{"marketing.example.com"}, nil)
	if err != nil {
		t.Fatalf("NewSigninHandler: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/signin", nil)
	rec := httptest.NewRecorder()

	handler.ServeSignin(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}

	// No email/username input field anywhere on the page.
	body := rec.Body.String()
	for _, forbidden := range []string{`type="email"`, `name="email"`, `name="username"`, `autocomplete="username`} {
		if strings.Contains(body, forbidden) {
			t.Errorf("signin page must not contain an identifier field, found %q", forbidden)
		}
	}
	if !strings.Contains(body, "navigator.credentials.get") {
		t.Error("signin page must drive navigator.credentials.get()")
	}
	if !strings.Contains(body, "mediation") {
		t.Error("signin page must request conditional mediation")
	}
	if !strings.Contains(body, "isConditionalMediationAvailable") {
		t.Error("signin page must feature-detect conditional mediation with a modal fallback")
	}

	// The nonce cookie must be set before the page is ever delivered.
	var nonceCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == NonceCookieName {
			nonceCookie = c
		}
	}
	if nonceCookie == nil {
		t.Fatal("missing browser nonce cookie")
	}
	if !nonceCookie.Secure || !nonceCookie.HttpOnly || nonceCookie.SameSite != http.SameSiteStrictMode {
		t.Error("browser nonce cookie must be Secure, HttpOnly, SameSite=Strict")
	}

	nonce, err := base64.RawURLEncoding.DecodeString(nonceCookie.Value)
	if err != nil {
		t.Fatalf("decode nonce cookie: %v", err)
	}

	// The page must embed exactly one session's request_id, and that session
	// must exist with a matching BrowserNonceHash.
	if len(store.sessions) != 1 {
		t.Fatalf("len(sessions) = %d, want 1", len(store.sessions))
	}
	var record BFFSessionRecord
	for _, r := range store.sessions {
		record = r
	}
	if !strings.Contains(body, record.RequestID) {
		t.Error("rendered page does not embed the created session's request_id")
	}
	if !NonceMatches(nonce, record.BrowserNonceHash) {
		t.Error("session BrowserNonceHash does not match the nonce cookie")
	}
	if record.ClientID != "" || record.RedirectURI != "" {
		t.Error("a plain signin session must not carry OIDC fields")
	}
}

func TestSigninHandler_ServeSignin_ReturnToAllowlist(t *testing.T) {
	tests := []struct {
		name       string
		rawQuery   string
		allowlist  []string
		wantEcho   string // substring expected in the rendered ReturnTo
		wantAbsent string
	}{
		{
			name:     "same-origin relative path accepted",
			rawQuery: "return_to=" + "%2Fdashboard",
			wantEcho: "/dashboard",
		},
		{
			name:      "allowlisted host accepted",
			rawQuery:  "return_to=" + "https%3A%2F%2Fmarketing.example.com%2Fwelcome",
			allowlist: []string{"marketing.example.com"},
			// html/template's JS-string escaper backslash-escapes "/" (to guard
			// against a "</script>" breakout); this is valid JS and decodes to
			// the same string at runtime.
			wantEcho: `https:\/\/marketing.example.com\/welcome`,
		},
		{
			name:       "unrecognized host falls back to default and is never echoed",
			rawQuery:   "return_to=" + "https%3A%2F%2Fevil.example.com%2Fphish",
			wantEcho:   `returnTo: "\/"`,
			wantAbsent: "evil.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := NewInMemoryBFFSessionStore()
			handler, err := NewSigninHandler(store, testSigninTemplates(t), 5*time.Minute, tt.allowlist, nil)
			if err != nil {
				t.Fatalf("NewSigninHandler: %v", err)
			}

			req := httptest.NewRequest(http.MethodGet, "/signin?"+tt.rawQuery, nil)
			rec := httptest.NewRecorder()
			handler.ServeSignin(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
			}
			body := rec.Body.String()
			if tt.wantEcho != "" && !strings.Contains(body, tt.wantEcho) {
				t.Errorf("body does not contain %q", tt.wantEcho)
			}
			if tt.wantAbsent != "" && strings.Contains(body, tt.wantAbsent) {
				t.Errorf("body must not contain unrecognized return_to host %q", tt.wantAbsent)
			}
		})
	}
}

// TestSigninHandler_DiscoverableSignin_HappyPath exercises the full path this
// feature composes: GET /signin mints the session, and the existing,
// unmodified LoginHandler (DiscoverableUserResolver) completes sign-in from
// it — proving no identifier is ever required, in or out of the session
// /signin created.
func TestSigninHandler_DiscoverableSignin_HappyPath(t *testing.T) {
	store := NewInMemoryBFFSessionStore()
	signinHandler, err := NewSigninHandler(store, testSigninTemplates(t), 5*time.Minute, nil, nil)
	if err != nil {
		t.Fatalf("NewSigninHandler: %v", err)
	}

	signinReq := httptest.NewRequest(http.MethodGet, "/signin", nil)
	signinRec := httptest.NewRecorder()
	signinHandler.ServeSignin(signinRec, signinReq)

	var nonceCookie *http.Cookie
	for _, c := range signinRec.Result().Cookies() {
		if c.Name == NonceCookieName {
			nonceCookie = c
		}
	}
	if nonceCookie == nil {
		t.Fatal("missing browser nonce cookie from /signin")
	}
	var requestID string
	for id := range store.sessions {
		requestID = id
	}
	if requestID == "" {
		t.Fatal("no session created by /signin")
	}

	loginHandler := NewLoginHandler(store, &mockWebAuthnService{}, DiscoverableUserResolver{}, "http://localhost:8080/authorize/complete")

	// GET /login: no identifier of any kind is submitted, only the opaque
	// request_id and the browser nonce cookie /signin already set.
	loginReq := httptest.NewRequest(http.MethodGet, "/login?request_id="+requestID, nil)
	loginReq.AddCookie(nonceCookie)
	loginRec := httptest.NewRecorder()
	loginHandler.BeginLogin(loginRec, loginReq)

	if loginRec.Code != http.StatusOK {
		t.Fatalf("BeginLogin status = %d, want %d", loginRec.Code, http.StatusOK)
	}
	var options protocol.CredentialAssertion
	if err := json.NewDecoder(loginRec.Body).Decode(&options); err != nil {
		t.Fatalf("decode assertion options: %v", err)
	}
	if len(options.Response.Challenge) == 0 {
		t.Error("expected a discoverable-login challenge")
	}

	var bffCookie, webauthnCookie *http.Cookie
	for _, c := range loginRec.Result().Cookies() {
		switch c.Name {
		case CookieName:
			bffCookie = c
		case webauthnSessionCookieName:
			webauthnCookie = c
		}
	}
	if bffCookie == nil || webauthnCookie == nil {
		t.Fatal("BeginLogin did not set the expected cookies")
	}

	// POST /login/complete: completes the ceremony purely from the assertion
	// response — the authenticator resolves identity via userHandle, never a
	// client-supplied identifier.
	completeReq := httptest.NewRequest(http.MethodPost, "/login/complete", nil)
	completeReq.AddCookie(bffCookie)
	completeReq.AddCookie(webauthnCookie)
	completeReq.AddCookie(nonceCookie)
	completeRec := httptest.NewRecorder()
	loginHandler.FinishLoginWithParsedData(completeRec, completeReq, &protocol.ParsedCredentialAssertionData{})

	if completeRec.Code != http.StatusFound {
		t.Fatalf("FinishLogin status = %d, want %d", completeRec.Code, http.StatusFound)
	}

	finalSession, err := store.Get(context.Background(), requestID)
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	if finalSession.UserID != "discoverable-user-id" {
		t.Errorf("session.UserID = %q, want %q", finalSession.UserID, "discoverable-user-id")
	}
	// Regression guard (task 19): a returning user signing in through GET
	// /signin with no pending recovery requirement must land in
	// SessionScopeFull. ServeSignin's BFFSessionRecord never sets SessionScope
	// at creation, so if FinishLoginWithParsedData ever regresses back to
	// calling sessions.SetUser (which leaves SessionScope untouched) instead of
	// SetUserWithRecoveryStatus, this session would stay at the Go zero value
	// "" and fail every bff.RequireFullScope route despite a fully successful
	// sign-in.
	if finalSession.SessionScope != SessionScopeFull {
		t.Errorf("session.SessionScope = %q, want %q", finalSession.SessionScope, SessionScopeFull)
	}
}

// TestSigninHandler_DiscoverableSignin_UnknownCredentialFailsClosed proves an
// unknown/invalid credential fails closed with the existing generic error —
// no signal that distinguishes "no such account" from any other failure.
func TestSigninHandler_DiscoverableSignin_UnknownCredentialFailsClosed(t *testing.T) {
	store := NewInMemoryBFFSessionStore()
	signinHandler, err := NewSigninHandler(store, testSigninTemplates(t), 5*time.Minute, nil, nil)
	if err != nil {
		t.Fatalf("NewSigninHandler: %v", err)
	}

	signinReq := httptest.NewRequest(http.MethodGet, "/signin", nil)
	signinRec := httptest.NewRecorder()
	signinHandler.ServeSignin(signinRec, signinReq)

	var nonceCookie *http.Cookie
	for _, c := range signinRec.Result().Cookies() {
		if c.Name == NonceCookieName {
			nonceCookie = c
		}
	}
	var requestID string
	for id := range store.sessions {
		requestID = id
	}

	webauthn := &mockWebAuthnService{
		finishDiscoverableFunc: func(ctx context.Context, sessionKey string, response *protocol.ParsedCredentialAssertionData) (string, bool, error) {
			return "", false, errors.New("unknown userHandle")
		},
	}
	loginHandler := NewLoginHandler(store, webauthn, DiscoverableUserResolver{}, "http://localhost:8080/authorize/complete")

	completeReq := httptest.NewRequest(http.MethodPost, "/login/complete", nil)
	completeReq.AddCookie(&http.Cookie{Name: CookieName, Value: requestID})
	completeReq.AddCookie(&http.Cookie{Name: webauthnSessionCookieName, Value: "discoverable-session-key"})
	completeReq.AddCookie(nonceCookie)
	completeRec := httptest.NewRecorder()
	loginHandler.FinishLoginWithParsedData(completeRec, completeReq, &protocol.ParsedCredentialAssertionData{})

	if completeRec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", completeRec.Code, http.StatusUnauthorized)
	}
	var resp loginErrorResponse
	if err := json.NewDecoder(completeRec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Code != "authentication_failed" {
		t.Errorf("code = %q, want %q (must not leak account existence)", resp.Code, "authentication_failed")
	}

	finalSession, err := store.Get(context.Background(), requestID)
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	if finalSession.UserID != "" {
		t.Error("session.UserID must remain empty after a failed ceremony")
	}
}
