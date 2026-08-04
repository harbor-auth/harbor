//go:build e2e

// End-to-end tests for the public, passkey-first signup journey (docs/DESIGN.md
// §9, §11.1; docs/design/product/signup-cta-contract.md): the pre-session
// GET /signup and GET /signup/passkey pages, the mandatory post-registration
// recovery step (GET /signup/recovery, POST /recovery/codes, POST
// /recovery/acknowledge), and the full-scope completion state
// (GET /signup/success).
//
// This file covers the happy path and cancellation. The security invariants
// that must hold across the whole chain — fail-closed expiry, one-time
// ceremonies, origin/RP validation, mandatory recovery gating, and isolation
// between concurrent sessions — live in the sibling
// signup_expiry_replay_test.go, signup_origin_gating_test.go, and
// signup_concurrency_test.go (§1.10: one concern per file). All four share the
// helpers in signup_helpers_test.go and the constants below.
//
// Like enrollment_test.go and recovery_test.go, they drive the cold-path
// harbor-mgmt binary AND inspect Postgres directly, reuse the same harness
// helpers (mgmtBaseURL, jarClient, openDB, enroll, registerPasskey,
// enrollRegion, envOr, registerPasskeyWithKey, makeAttestation,
// generateRecoveryCodes, hasCookie, readRecoveryRequired), are behind the
// `e2e` build tag (excluded from `go test ./...`), and skip gracefully
// whenever a prerequisite (mgmt binary, DB, a given ceremony) is not wired on
// the target stack.
//
// One addition beyond the existing harness: signupJarClient
// (signup_helpers_test.go) uses a small custom cookie jar instead of
// jarClient's stdlib cookiejar.Jar. Every cookie this system sets is Secure
// (internal/bff/cookie.go, internal/webauthn/handlers.go,
// internal/mgmtapi/session.go), but the checked-in e2e/docker-compose.yml
// stack serves harbor-mgmt over plain HTTP with no TLS termination. The
// stdlib jar's shouldSend rule (`https || !e.Secure`, net/http/cookiejar)
// silently drops every Secure cookie on the second hop of any http://
// request — which would make almost every multi-step assertion in these
// files "pass" by skipping instead of actually exercising the chain (the
// whole signup journey is one long chain of Secure-cookied hops: /enroll ->
// register/begin -> register/finish -> /signup/recovery -> /recovery/codes ->
// /recovery/acknowledge -> /signup/success). See also bff_login_test.go's
// nonceValue comment, which hit the same Secure-cookie-over-http limitation
// on the read side.
//
// Run (example):
//
//	docker compose -f e2e/docker-compose.yml up -d --wait
//	HARBOR_MGMT_E2E_BASE_URL=http://localhost:8081 \
//	HARBOR_E2E_DATABASE_URL=postgres://harbor:harbor@localhost:5432/harbor?sslmode=disable \
//	go test -tags e2e ./e2e/... -run Signup
package e2e

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

const (
	signupPath              = "/signup"
	signupPasskeyPath       = "/signup/passkey"
	signupRecoveryPath      = "/signup/recovery"
	signupSuccessPath       = "/signup/success"
	recoveryAcknowledgePath = "/recovery/acknowledge"

	// bffSessionCookieName is the BFF session cookie
	// (bff.CookieName == mgmtapi.RecoveryScopedSessionCookieName), set by the
	// post-registration handoff (cmd/harbor-mgmt/caller.go) and by
	// POST /recovery/complete. NOTE: e2e/recovery_test.go's
	// recoveryScopedSessionCookie constant ("harbor_recovery_session") does
	// not match any cookie the server actually sets — do not reuse it here.
	bffSessionCookieName = "__Host-harbor-bff"

	// enrollmentSessionCookieName carries the one-time enrollment handoff
	// (mgmtapi.EnrollmentSessionCookieName).
	enrollmentSessionCookieName = "harbor_enrollment_session"

	// webauthnCeremonySessionCookieName carries the in-progress WebAuthn
	// ceremony's opaque session key (internal/webauthn/handlers.go), scoped
	// Path=/webauthn by the raw ceremony endpoints.
	webauthnCeremonySessionCookieName = "harbor_webauthn_session"
)

// =========================================================================
// 1) Happy path
// =========================================================================

// TestSignupHappyPath_FullJourneyToSuccessWithReturnTo drives the whole
// public journey — GET /signup, GET /signup/passkey, POST /enroll, first
// passkey registration, GET /signup/recovery, POST /recovery/codes,
// POST /recovery/acknowledge, GET /signup/success — and proves the SAME
// browser session ends up full-scope, honors return_to, clears
// recovery_required, and leaves the expected audit trail.
func TestSignupHappyPath_FullJourneyToSuccessWithReturnTo(t *testing.T) {
	conn := openDB(t)
	client := signupJarClient(t)

	// GET /signup and GET /signup/passkey: cosmetic, pre-session, no cookies
	// required (internal/bff/signup.go: SignupHandler.Routes).
	for _, p := range []string{signupPath, signupPasskeyPath} {
		resp, err := client.Get(mgmtBaseURL() + p)
		if err != nil {
			unavailable(t, "GET %s unreachable: %v", p, err)
		}
		raw, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if readErr != nil {
			t.Fatalf("read GET %s response: %v", p, readErr)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200\n%s", p, resp.StatusCode, raw)
		}
		if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
			t.Errorf("GET %s Content-Type = %q, want text/html", p, ct)
		}
	}

	// The page's own form POSTs to /enroll; then register the first passkey.
	userID, _ := enroll(t, client)
	if !registerPasskey(t, client) {
		t.Skip("first passkey registration did not complete on this stack — skipping signup happy path")
	}

	// The post-registration handoff must have landed an enrollment-only BFF
	// session: full scope is refused until recovery setup completes.
	resp, err := client.Get(mgmtBaseURL() + signupSuccessPath)
	if err != nil {
		unavailable(t, "GET %s unreachable: %v", signupSuccessPath, err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("GET %s before recovery setup = %d, want 403 (enrollment-only scope)", signupSuccessPath, resp.StatusCode)
	}

	// GET /signup/recovery is reachable under enrollment-only scope.
	resp, err = client.Get(mgmtBaseURL() + signupRecoveryPath)
	if err != nil {
		unavailable(t, "GET %s unreachable: %v", signupRecoveryPath, err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200", signupRecoveryPath, resp.StatusCode)
	}

	// The page's two calls: generate codes, then acknowledge.
	_ = generateRecoveryCodes(t, client)
	ackResp, err := client.Post(mgmtBaseURL()+recoveryAcknowledgePath, "application/json", strings.NewReader("{}"))
	if err != nil {
		unavailable(t, "POST %s unreachable: %v", recoveryAcknowledgePath, err)
	}
	ackRaw, readErr := io.ReadAll(ackResp.Body)
	_ = ackResp.Body.Close()
	if readErr != nil {
		t.Fatalf("read %s response: %v", recoveryAcknowledgePath, readErr)
	}
	if ackResp.StatusCode != http.StatusOK {
		t.Fatalf("POST %s = %d, want 200\n%s", recoveryAcknowledgePath, ackResp.StatusCode, ackRaw)
	}

	// The SAME cookie now reaches full scope and honors return_to.
	const returnTo = "/dashboard/after-signup"
	resp, err = client.Get(mgmtBaseURL() + signupSuccessPath + "?return_to=" + url.QueryEscape(returnTo))
	if err != nil {
		unavailable(t, "GET %s unreachable: %v", signupSuccessPath, err)
	}
	raw, readErr := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if readErr != nil {
		t.Fatalf("read %s response: %v", signupSuccessPath, readErr)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s after recovery setup = %d, want 200\n%s", signupSuccessPath, resp.StatusCode, raw)
	}
	if want := fmt.Sprintf("href=%q", returnTo); !strings.Contains(string(raw), want) {
		t.Errorf("GET %s body does not honor return_to=%q (want %s present)\n%s", signupSuccessPath, returnTo, want, raw)
	}

	if readRecoveryRequired(t, conn, userID) {
		t.Errorf("users.recovery_required = true after the full signup journey, want false")
	}

	want := []string{"signup.enrolled", "signup.passkey_registered", "signup.recovery_completed"}
	got := pollAuditEventTypes(t, conn, userID, want)
	if !hasAllEventTypes(got, want) {
		t.Errorf("audit_events for user %s = %v, want at least %v", userID, got, want)
	}
}

// =========================================================================
// 2) Cancellation
// =========================================================================

// TestSignupCancellation_AbandonedEnrollmentGrantsNoFullScopeAccess proves
// that abandoning the flow right after POST /enroll — before ever
// registering a passkey — leaves no usable full-scope account and no
// exploitable leftover session state. The post-registration handoff only
// fires on a successful register/finish (cmd/harbor-mgmt/caller.go), so an
// abandoned attempt must never mint a BFF session at all.
func TestSignupCancellation_AbandonedEnrollmentGrantsNoFullScopeAccess(t *testing.T) {
	conn := openDB(t)
	client := signupJarClient(t)

	userID, _ := enroll(t, client)
	// Deliberately never register a passkey.

	if got := cookieValue(t, client, bffSessionCookieName); got != "" {
		t.Fatalf("abandoned enrollment left a %s cookie (value %q) — the post-registration handoff must only fire on a successful passkey registration", bffSessionCookieName, got)
	}

	resp, err := client.Get(mgmtBaseURL() + signupSuccessPath)
	if err != nil {
		unavailable(t, "GET %s unreachable: %v", signupSuccessPath, err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("abandoned enrollment: GET %s = %d, want 401 (no BFF session exists at all)", signupSuccessPath, resp.StatusCode)
	}

	ackResp, err := client.Post(mgmtBaseURL()+recoveryAcknowledgePath, "application/json", strings.NewReader("{}"))
	if err != nil {
		unavailable(t, "POST %s unreachable: %v", recoveryAcknowledgePath, err)
	}
	_ = ackResp.Body.Close()
	if ackResp.StatusCode != http.StatusUnauthorized {
		t.Errorf("abandoned enrollment: POST %s = %d, want 401 (no authenticated session to resolve)", recoveryAcknowledgePath, ackResp.StatusCode)
	}

	if status := userStatus(t, conn, userID); status != "pending" {
		t.Errorf("users.status for abandoned enrollment = %q, want pending (never activated without a passkey)", status)
	}
	if n := credentialCount(t, conn, userID); n != 0 {
		t.Errorf("credentials for abandoned enrollment user %s = %d, want 0", userID, n)
	}
}
