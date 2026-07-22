package bff

import (
	"context"
	"net/http"
	"net/http/httptest"
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

	handler := NewLoginHandler(store, &mockWebAuthnService{}, &mockUserResolver{})

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

	handler := NewLoginHandler(store, &mockWebAuthnService{}, &mockUserResolver{})

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

	handler := NewLoginHandler(store, &mockWebAuthnService{}, &mockUserResolver{})

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

	handler := NewLoginHandler(store, &mockWebAuthnService{}, &mockUserResolver{})

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
