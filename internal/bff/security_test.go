package bff

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
)

// TestSecurity_MissingCookieUnauthorized verifies that when no BFF session cookie
// is present, a handler using BFFAuthSource (via the BFF middleware) correctly
// sees no authenticated user and can enforce 401 Unauthorized.
// This is the primary "missing cookie → 401" gate (docs/plans/bff-session-middleware.md).
func TestSecurity_MissingCookieUnauthorized(t *testing.T) {
	store := NewInMemoryBFFSessionStore()
	authSource := NewBFFAuthSource()

	// A handler that enforces authentication via BFFAuthSource — this is the
	// pattern used by routes behind the BFF middleware.
	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := authSource.AuthenticatedUserID(r.Context())
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	handler := Middleware(store)(protected)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	// Deliberately no __Host-harbor-bff cookie.
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 (no BFF cookie → no user in context → unauthorized)", rec.Code)
	}
}

// TestSecurity_TamperedRequestID verifies that a forged/tampered request_id value
// in the BFF cookie is rejected when attempting to complete the login ceremony.
// An attacker who cannot read the cookie (HttpOnly) cannot supply a valid
// request_id; this test covers the case where they guess or brute-force one.
func TestSecurity_TamperedRequestID(t *testing.T) {
	store := NewInMemoryBFFSessionStore()
	ctx := context.Background()

	// A real, valid session exists.
	real := BFFSessionRecord{
		RequestID: "real-request-id-abc123",
		ClientID:  "test-client",
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
	if err := store.Create(ctx, real); err != nil {
		t.Fatalf("create: %v", err)
	}

	handler := NewLoginHandler(store, &mockWebAuthnService{}, &mockUserResolver{}, "http://localhost:8080/authorize/complete")

	// Cookie carries a forged value — not a real session ID in the store.
	req := httptest.NewRequest(http.MethodPost, "/login/complete", nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: "forged-id-does-not-exist"})
	req.AddCookie(&http.Cookie{Name: webauthnSessionCookieName, Value: "any-key"})
	rec := httptest.NewRecorder()

	handler.FinishLogin(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for tampered request_id", rec.Code)
	}
	// The real session must remain untouched.
	realSess, err := store.Get(ctx, real.RequestID)
	if err != nil {
		t.Fatalf("real session unexpectedly gone: %v", err)
	}
	if realSess.UserID != "" {
		t.Errorf("real session.UserID = %q, must not be set by tampered request", realSess.UserID)
	}
}

// TestSecurity_ReplayAfterDeletion verifies that a session consumed by
// /authorize/complete (one-time use, deleted after code issuance) cannot be
// replayed — the stale cookie is rejected at /login/complete.
func TestSecurity_ReplayAfterDeletion(t *testing.T) {
	store := NewInMemoryBFFSessionStore()
	ctx := context.Background()

	sess := BFFSessionRecord{
		RequestID: "consumed-session-xyz",
		ClientID:  "test-client",
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
	if err := store.Create(ctx, sess); err != nil {
		t.Fatalf("create: %v", err)
	}

	// Simulate /authorize/complete consuming the session (one-time use).
	if err := store.Delete(ctx, sess.RequestID); err != nil {
		t.Fatalf("delete: %v", err)
	}

	handler := NewLoginHandler(store, &mockWebAuthnService{}, &mockUserResolver{}, "http://localhost:8080/authorize/complete")

	// Attacker replays the old cookie after the session was consumed.
	req := httptest.NewRequest(http.MethodPost, "/login/complete", nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: "consumed-session-xyz"})
	req.AddCookie(&http.Cookie{Name: webauthnSessionCookieName, Value: "old-key"})
	rec := httptest.NewRecorder()

	handler.FinishLogin(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for replayed deleted session", rec.Code)
	}
}

// TestSecurity_CrossTabIsolation verifies that completing the login ceremony for
// tab A (using tab A's cookie) does not affect tab B's independent session.
// This is the cross-tab session fixation defense: each /authorize creates its own
// request_id, so tab A and tab B are fully isolated.
func TestSecurity_CrossTabIsolation(t *testing.T) {
	store := NewInMemoryBFFSessionStore()
	ctx := context.Background()

	// Two concurrent sessions from two browser tabs.
	sessionA := BFFSessionRecord{
		RequestID: "session-tab-A",
		ClientID:  "test-client",
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
	sessionB := BFFSessionRecord{
		RequestID: "session-tab-B",
		ClientID:  "test-client",
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
	if err := store.Create(ctx, sessionA); err != nil {
		t.Fatalf("create A: %v", err)
	}
	if err := store.Create(ctx, sessionB); err != nil {
		t.Fatalf("create B: %v", err)
	}

	handler := NewLoginHandler(store, &mockWebAuthnService{}, &mockUserResolver{}, "http://localhost:8080/authorize/complete")

	// Tab A completes the ceremony using its own cookie.
	reqA := httptest.NewRequest(http.MethodPost, "/login/complete", nil)
	reqA.AddCookie(&http.Cookie{Name: CookieName, Value: "session-tab-A"})
	reqA.AddCookie(&http.Cookie{Name: webauthnSessionCookieName, Value: "webauthn-key-A"})
	recA := httptest.NewRecorder()
	handler.FinishLoginWithParsedData(recA, reqA, &protocol.ParsedCredentialAssertionData{})

	if recA.Code != http.StatusFound {
		t.Fatalf("tab A FinishLogin: want 302, got %d", recA.Code)
	}

	// Session A must now carry the authenticated user_id.
	sessA, err := store.Get(ctx, "session-tab-A")
	if err != nil {
		t.Fatalf("get session A: %v", err)
	}
	if sessA.UserID == "" {
		t.Error("session A must have user_id after FinishLogin")
	}

	// Session B must be completely untouched — cross-tab fixation is prevented.
	sessB, err := store.Get(ctx, "session-tab-B")
	if err != nil {
		t.Fatalf("get session B: %v", err)
	}
	if sessB.UserID != "" {
		t.Errorf("session B.UserID = %q, must not be affected by tab A's FinishLogin", sessB.UserID)
	}
}

// =============================================================
// Browser Nonce Gate Tests (audit finding C3 — session fixation)
// These tests FAIL before tasks 4-5 implement the nonce gate in
// BeginLogin and FinishLoginWithParsedData.
// =============================================================

// TestSecurity_SessionFixation_AttackerMintedRequestID is the headline regression
// test for login session fixation (audit finding C3 / fix-bff-session-binding).
//
// Attack scenario:
//  1. Attacker calls /authorize with their own client_id + redirect_uri,
//     capturing request_id=R and its associated browser nonce cookie.
//  2. Attacker lures the victim to /login?request_id=R.
//  3. Victim's browser has NO nonce cookie — they never visited /authorize.
//
// With the nonce gate, BeginLogin must refuse immediately: missing nonce cookie
// proves this request did not originate from the browser that initiated the
// flow. No BFF cookie must be set, and no code is ever issued.
//
// This test FAILS before tasks 4-5 implement the gate.
func TestSecurity_SessionFixation_AttackerMintedRequestID(t *testing.T) {
	store := NewInMemoryBFFSessionStore()
	ctx := context.Background()

	// Mint an attacker-controlled nonce and store its hash in the session,
	// exactly as /authorize would after the fix is deployed.
	attackerNonce, err := NewBrowserNonce()
	if err != nil {
		t.Fatalf("NewBrowserNonce: %v", err)
	}

	attackerSession := BFFSessionRecord{
		RequestID:        "attacker-session-R",
		ClientID:         "attacker-client-id",
		RedirectURI:      "https://attacker.example.com/steal",
		State:            "attacker-state",
		BrowserNonceHash: HashNonce(attackerNonce),
		ExpiresAt:        time.Now().Add(5 * time.Minute),
	}
	if err := store.Create(ctx, attackerSession); err != nil {
		t.Fatalf("create attacker session: %v", err)
	}

	handler := NewLoginHandler(store, &mockWebAuthnService{}, &mockUserResolver{}, "http://localhost:8080/authorize/complete")

	// Victim is lured to /login?request_id=R — they have NO nonce cookie
	// because they never visited /authorize.
	req := httptest.NewRequest(http.MethodGet, "/login?request_id=attacker-session-R", nil)
	// Deliberately no __Host-harbor-bff-nonce cookie.
	rec := httptest.NewRecorder()
	handler.BeginLogin(rec, req)

	// The nonce gate MUST refuse: missing nonce ≠ stored hash.
	if rec.Code == http.StatusOK {
		t.Errorf("status = 200: BeginLogin accepted victim request with no nonce cookie — "+
			"session fixation is NOT prevented (want 4xx refusal)")
	}
	if rec.Code/100 == 3 {
		t.Errorf("status = %d: BeginLogin issued a redirect without nonce validation — "+
			"session fixation is NOT prevented", rec.Code)
	}
	// No Location header — must not redirect the victim anywhere.
	if loc := rec.Header().Get("Location"); loc != "" {
		t.Errorf("Location = %q: must not redirect when nonce is absent", loc)
	}
	// The attacker's session must remain unauthenticated — the victim's
	// passkey assertion must never be written into it.
	sess, err := store.Get(ctx, "attacker-session-R")
	if err != nil {
		t.Fatalf("get attacker session: %v", err)
	}
	if sess.UserID != "" {
		t.Errorf("attacker session.UserID = %q: must not be populated by victim request", sess.UserID)
	}
}

// TestSecurity_BeginLogin_RefusesWithMissingNonce verifies that BeginLogin refuses
// when the session has a BrowserNonceHash but no nonce cookie is present in the
// request. This is the gate at the very start of the login ceremony.
//
// This test FAILS before tasks 4-5 implement the gate.
func TestSecurity_BeginLogin_RefusesWithMissingNonce(t *testing.T) {
	store := NewInMemoryBFFSessionStore()
	ctx := context.Background()

	nonce, err := NewBrowserNonce()
	if err != nil {
		t.Fatalf("NewBrowserNonce: %v", err)
	}
	sess := BFFSessionRecord{
		RequestID:        "nonce-session",
		ClientID:         "test-client",
		BrowserNonceHash: HashNonce(nonce),
		ExpiresAt:        time.Now().Add(5 * time.Minute),
	}
	if err := store.Create(ctx, sess); err != nil {
		t.Fatalf("create: %v", err)
	}

	handler := NewLoginHandler(store, &mockWebAuthnService{}, &mockUserResolver{}, "http://localhost:8080/authorize/complete")

	req := httptest.NewRequest(http.MethodGet, "/login?request_id=nonce-session", nil)
	// No nonce cookie — should be refused.
	rec := httptest.NewRecorder()
	handler.BeginLogin(rec, req)

	if rec.Code == http.StatusOK {
		t.Errorf("status = 200: BeginLogin accepted request with missing nonce cookie (want 4xx)")
	}
	if loc := rec.Header().Get("Location"); loc != "" {
		t.Errorf("Location = %q: must not redirect when nonce is absent", loc)
	}
}

// TestSecurity_BeginLogin_RefusesWithWrongNonce verifies that BeginLogin refuses
// when the nonce cookie value does not match the session's BrowserNonceHash.
// An attacker who captures the request_id cannot forge a valid nonce.
//
// This test FAILS before tasks 4-5 implement the gate.
func TestSecurity_BeginLogin_RefusesWithWrongNonce(t *testing.T) {
	store := NewInMemoryBFFSessionStore()
	ctx := context.Background()

	legitimateNonce, err := NewBrowserNonce()
	if err != nil {
		t.Fatalf("NewBrowserNonce (legitimate): %v", err)
	}
	sess := BFFSessionRecord{
		RequestID:        "nonce-session",
		ClientID:         "test-client",
		BrowserNonceHash: HashNonce(legitimateNonce),
		ExpiresAt:        time.Now().Add(5 * time.Minute),
	}
	if err := store.Create(ctx, sess); err != nil {
		t.Fatalf("create: %v", err)
	}

	wrongNonce, err := NewBrowserNonce()
	if err != nil {
		t.Fatalf("NewBrowserNonce (wrong): %v", err)
	}

	handler := NewLoginHandler(store, &mockWebAuthnService{}, &mockUserResolver{}, "http://localhost:8080/authorize/complete")

	req := httptest.NewRequest(http.MethodGet, "/login?request_id=nonce-session", nil)
	req.AddCookie(&http.Cookie{
		Name:  NonceCookieName,
		Value: base64.RawURLEncoding.EncodeToString(wrongNonce),
	})
	rec := httptest.NewRecorder()
	handler.BeginLogin(rec, req)

	if rec.Code == http.StatusOK {
		t.Errorf("status = 200: BeginLogin accepted request with wrong nonce (want 4xx)")
	}
	if loc := rec.Header().Get("Location"); loc != "" {
		t.Errorf("Location = %q: must not redirect on nonce mismatch", loc)
	}
}

// TestSecurity_FinishLogin_RefusesWithMissingNonce verifies that FinishLogin
// refuses when the session has a BrowserNonceHash but the request carries no
// nonce cookie. Even possession of the correct BFF session cookie is insufficient
// without the matching browser nonce.
//
// This test FAILS before tasks 4-5 implement the gate.
func TestSecurity_FinishLogin_RefusesWithMissingNonce(t *testing.T) {
	store := NewInMemoryBFFSessionStore()
	ctx := context.Background()

	nonce, err := NewBrowserNonce()
	if err != nil {
		t.Fatalf("NewBrowserNonce: %v", err)
	}
	sess := BFFSessionRecord{
		RequestID:        "nonce-session",
		ClientID:         "test-client",
		BrowserNonceHash: HashNonce(nonce),
		ExpiresAt:        time.Now().Add(5 * time.Minute),
	}
	if err := store.Create(ctx, sess); err != nil {
		t.Fatalf("create: %v", err)
	}

	handler := NewLoginHandler(store, &mockWebAuthnService{}, &mockUserResolver{}, "http://localhost:8080/authorize/complete")

	req := httptest.NewRequest(http.MethodPost, "/login/complete", nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: "nonce-session"})
	req.AddCookie(&http.Cookie{Name: webauthnSessionCookieName, Value: "session-key"})
	// No nonce cookie.
	rec := httptest.NewRecorder()
	handler.FinishLoginWithParsedData(rec, req, &protocol.ParsedCredentialAssertionData{})

	if rec.Code == http.StatusFound {
		t.Errorf("status = 302: FinishLogin redirected without nonce validation (want 4xx)")
	}
	if loc := rec.Header().Get("Location"); loc != "" {
		t.Errorf("Location = %q: must not redirect when nonce is absent", loc)
	}
	// The session must remain unauthenticated — userID must not be written.
	updated, err := store.Get(ctx, "nonce-session")
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	if updated.UserID != "" {
		t.Errorf("session.UserID = %q: must not be set without valid nonce", updated.UserID)
	}
}

// TestSecurity_FinishLogin_RefusesWithWrongNonce verifies that FinishLogin refuses
// when the nonce cookie does not match the session's BrowserNonceHash. A forged or
// replayed nonce must not allow the ceremony to complete.
//
// This test FAILS before tasks 4-5 implement the gate.
func TestSecurity_FinishLogin_RefusesWithWrongNonce(t *testing.T) {
	store := NewInMemoryBFFSessionStore()
	ctx := context.Background()

	legitimateNonce, err := NewBrowserNonce()
	if err != nil {
		t.Fatalf("NewBrowserNonce (legitimate): %v", err)
	}
	sess := BFFSessionRecord{
		RequestID:        "nonce-session",
		ClientID:         "test-client",
		BrowserNonceHash: HashNonce(legitimateNonce),
		ExpiresAt:        time.Now().Add(5 * time.Minute),
	}
	if err := store.Create(ctx, sess); err != nil {
		t.Fatalf("create: %v", err)
	}

	wrongNonce, err := NewBrowserNonce()
	if err != nil {
		t.Fatalf("NewBrowserNonce (wrong): %v", err)
	}

	handler := NewLoginHandler(store, &mockWebAuthnService{}, &mockUserResolver{}, "http://localhost:8080/authorize/complete")

	req := httptest.NewRequest(http.MethodPost, "/login/complete", nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: "nonce-session"})
	req.AddCookie(&http.Cookie{Name: webauthnSessionCookieName, Value: "session-key"})
	req.AddCookie(&http.Cookie{
		Name:  NonceCookieName,
		Value: base64.RawURLEncoding.EncodeToString(wrongNonce),
	})
	rec := httptest.NewRecorder()
	handler.FinishLoginWithParsedData(rec, req, &protocol.ParsedCredentialAssertionData{})

	if rec.Code == http.StatusFound {
		t.Errorf("status = 302: FinishLogin redirected with wrong nonce (want 4xx)")
	}
	if loc := rec.Header().Get("Location"); loc != "" {
		t.Errorf("Location = %q: must not redirect on nonce mismatch", loc)
	}
	updated, err := store.Get(ctx, "nonce-session")
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	if updated.UserID != "" {
		t.Errorf("session.UserID = %q: must not be set on nonce mismatch", updated.UserID)
	}
}

// TestSecurity_NonceNeverInResponseBody verifies that the raw browser nonce value
// is never echoed in any response body or redirect Location header.
// The nonce lives exclusively in the browser cookie; the server stores only its
// SHA-256 hash. A compromised response must not yield a replayable nonce.
func TestSecurity_NonceNeverInResponseBody(t *testing.T) {
	store := NewInMemoryBFFSessionStore()
	ctx := context.Background()

	nonce, err := NewBrowserNonce()
	if err != nil {
		t.Fatalf("NewBrowserNonce: %v", err)
	}
	encodedNonce := base64.RawURLEncoding.EncodeToString(nonce)

	sess := BFFSessionRecord{
		RequestID:        "nonce-leak-check",
		ClientID:         "test-client",
		BrowserNonceHash: HashNonce(nonce),
		ExpiresAt:        time.Now().Add(5 * time.Minute),
	}
	if err := store.Create(ctx, sess); err != nil {
		t.Fatalf("create: %v", err)
	}

	handler := NewLoginHandler(store, &mockWebAuthnService{}, &mockUserResolver{}, "http://localhost:8080/authorize/complete")

	t.Run("BeginLogin response does not contain nonce", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/login?request_id=nonce-leak-check", nil)
		req.AddCookie(&http.Cookie{
			Name:  NonceCookieName,
			Value: encodedNonce,
		})
		rec := httptest.NewRecorder()
		handler.BeginLogin(rec, req)

		body := rec.Body.String()
		if strings.Contains(body, encodedNonce) {
			t.Errorf("BeginLogin response body contains raw nonce (base64url-encoded): must never be returned")
		}
		if loc := rec.Header().Get("Location"); strings.Contains(loc, encodedNonce) {
			t.Errorf("BeginLogin Location header contains raw nonce: must never be exposed")
		}
	})

	t.Run("error responses do not contain nonce", func(t *testing.T) {
		// A request with missing nonce triggers an error response — verify the
		// error body does not accidentally echo back the nonce from any context.
		req := httptest.NewRequest(http.MethodGet, "/login?request_id=nonce-leak-check", nil)
		// Deliberately wrong nonce to provoke an error path.
		wrongNonce, err := NewBrowserNonce()
		if err != nil {
			t.Fatalf("NewBrowserNonce: %v", err)
		}
		req.AddCookie(&http.Cookie{
			Name:  NonceCookieName,
			Value: base64.RawURLEncoding.EncodeToString(wrongNonce),
		})
		rec := httptest.NewRecorder()
		handler.BeginLogin(rec, req)

		body := rec.Body.String()
		if strings.Contains(body, encodedNonce) {
			t.Errorf("error response body contains legitimate nonce: must never be returned")
		}
		if strings.Contains(body, base64.RawURLEncoding.EncodeToString(wrongNonce)) {
			t.Errorf("error response body contains wrong nonce: must never echo cookie values")
		}
	})
}

// TestSecurity_CSRFBindingEnforced verifies that /login/complete requires the BFF
// cookie, enforcing the CSRF binding between the browser tab and the ceremony.
// A cross-origin CSRF attack cannot succeed because:
//   - The __Host-harbor-bff cookie is HttpOnly (JS cannot read it).
//   - The __Host-harbor-bff cookie is SameSite=Strict (other origins cannot trigger the POST).
//   - Even if the POST were triggered, the missing cookie causes an immediate 400.
//
// This test covers the case where the cookie is simply absent (simulating a
// cross-origin POST that cannot carry the HttpOnly cookie).
func TestSecurity_CSRFBindingEnforced(t *testing.T) {
	store := NewInMemoryBFFSessionStore()
	ctx := context.Background()

	sess := BFFSessionRecord{
		RequestID: "csrf-target-session",
		ClientID:  "test-client",
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
	if err := store.Create(ctx, sess); err != nil {
		t.Fatalf("create: %v", err)
	}

	handler := NewLoginHandler(store, &mockWebAuthnService{}, &mockUserResolver{}, "http://localhost:8080/authorize/complete")

	// POST /login/complete without the __Host-harbor-bff cookie.
	// This simulates a CSRF attack from another origin — it cannot set or read the
	// HttpOnly cookie, so the CSRF gate fires immediately.
	req := httptest.NewRequest(http.MethodPost, "/login/complete", nil)
	// No BFF cookie. Only the WebAuthn cookie (which an attacker could freely set,
	// but it's useless without the BFF CSRF token).
	req.AddCookie(&http.Cookie{Name: webauthnSessionCookieName, Value: "attacker-session-key"})
	rec := httptest.NewRecorder()

	handler.FinishLogin(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (CSRF gate — missing BFF cookie)", rec.Code)
	}

	// The target session must remain unauthenticated.
	untouched, err := store.Get(ctx, "csrf-target-session")
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	if untouched.UserID != "" {
		t.Errorf("session.UserID = %q after CSRF attempt, must remain empty", untouched.UserID)
	}
}
