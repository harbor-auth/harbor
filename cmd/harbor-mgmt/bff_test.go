package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/harbor-auth/harbor/internal/bff"
	"github.com/harbor-auth/harbor/internal/oidc"
	bfftest "github.com/harbor-auth/harbor/internal/testsupport/bff"
)

// probeEnrollmentAllowed wires guard.EnrollmentAllowed behind bff.Middleware
// exactly as production does (bff.SessionIDFromContext only resolves once
// Middleware has authenticated the request), and returns what the guard saw.
func probeEnrollmentAllowed(t *testing.T, store bff.BFFSessionStore, cookie string) bool {
	t.Helper()
	guard := bffMFAEnrollmentGuard{store: store}
	var got bool
	mux := http.NewServeMux()
	mux.HandleFunc("/probe", func(w http.ResponseWriter, r *http.Request) {
		got = guard.EnrollmentAllowed(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	handler := bff.Middleware(store)(mux)

	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: bff.CookieName, Value: cookie})
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("probe handler status = %d, want 200", rec.Code)
	}
	return got
}

// TestBffMFAEnrollmentGuard_RefusesFederatedSession is M3's cmd-level
// integration proof: wired exactly as main.go wires it
// (WithMFAEnrollmentGuard(bffMFAEnrollmentGuard{store: bffStore})), the
// EXACT session shape cmd/harbor-mgmt/sso.go's wireSSOLoginRoute mints for a
// corporate-SSO handoff (AuthMethod=federated, no BrowserNonceHash) is
// refused MFA enrollment.
func TestBffMFAEnrollmentGuard_RefusesFederatedSession(t *testing.T) {
	store := bfftest.NewInMemoryBFFSessionStore()
	if err := store.Create(context.Background(), bff.BFFSessionRecord{
		RequestID:  "sess-federated",
		UserID:     "user-1",
		AuthMethod: oidc.AuthMethodFederated,
		// BrowserNonceHash deliberately nil, mirroring wireSSOLoginRoute.
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("store.Create: %v", err)
	}

	if probeEnrollmentAllowed(t, store, "sess-federated") {
		t.Error("EnrollmentAllowed(federated session) = true, want false")
	}
}

// TestBffMFAEnrollmentGuard_AllowsNormalSession proves the guard does not
// over-block: an ordinary nonce-bound, non-federated session may enroll.
func TestBffMFAEnrollmentGuard_AllowsNormalSession(t *testing.T) {
	store := bfftest.NewInMemoryBFFSessionStore()
	if err := store.Create(context.Background(), bff.BFFSessionRecord{
		RequestID:        "sess-normal",
		UserID:           "user-1",
		AuthMethod:       oidc.AuthMethodWebAuthn,
		BrowserNonceHash: []byte("nonce-hash"),
		ExpiresAt:        time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("store.Create: %v", err)
	}

	if !probeEnrollmentAllowed(t, store, "sess-normal") {
		t.Error("EnrollmentAllowed(normal webauthn session) = false, want true")
	}
}

// TestBffMFAEnrollmentGuard_NoSessionDenies proves the guard fails closed
// when it cannot resolve a session at all (no cookie, unknown session id) —
// "we couldn't check" must never collapse to "allowed".
func TestBffMFAEnrollmentGuard_NoSessionDenies(t *testing.T) {
	store := bfftest.NewInMemoryBFFSessionStore()
	if probeEnrollmentAllowed(t, store, "" /* no cookie */) {
		t.Error("EnrollmentAllowed(no session cookie) = true, want false (fail closed)")
	}
	if probeEnrollmentAllowed(t, store, "unknown-session-id") {
		t.Error("EnrollmentAllowed(unknown session id) = true, want false (fail closed)")
	}
}
