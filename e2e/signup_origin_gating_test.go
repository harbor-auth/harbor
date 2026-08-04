//go:build e2e

// Origin/RP validation and mandatory recovery gating for the signup journey.
// See signup_test.go's package doc comment for the shared harness/jar notes.
package e2e

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

// =========================================================================
// 5) Wrong origin / RP
// =========================================================================

// TestSignupWrongOrigin_FailsWebAuthnValidation proves that a registration
// ceremony asserting an origin outside WEBAUTHN_RP_ORIGINS is rejected by
// go-webauthn's own origin validation when exercised through the new signup
// pages' ceremony endpoints, and leaves no partial state — exactly like a
// garbage attestation (enrollment_test.go's
// TestPasskeyFailureLeavesPendingUserWithNoCredential), but isolating the
// origin check specifically.
func TestSignupWrongOrigin_FailsWebAuthnValidation(t *testing.T) {
	conn := openDB(t)
	client := signupJarClient(t)
	userID, _ := enroll(t, client)

	beginResp, err := client.Post(mgmtBaseURL()+registerBeginPath, "application/json", nil)
	if err != nil {
		unavailable(t, "register/begin unreachable: %v", err)
	}
	beginBody, readErr := io.ReadAll(beginResp.Body)
	_ = beginResp.Body.Close()
	if readErr != nil {
		t.Fatalf("read register/begin response: %v", readErr)
	}
	if beginResp.StatusCode != http.StatusOK {
		unavailable(t, "register/begin = %d (ceremony not wired) — skipping wrong-origin assertion", beginResp.StatusCode)
	}

	rpID, challenge, err := parseBeginRegistrationResponse(beginBody)
	if err != nil {
		t.Fatalf("parse register/begin response: %v\n%s", err, beginBody)
	}

	const wrongOrigin = "https://evil.example"
	if wrongOrigin == webauthnOrigin() {
		t.Fatalf("test setup bug: wrongOrigin equals the configured webauthnOrigin() %q", wrongOrigin)
	}
	attestation, err := makeAttestationWithOrigin(rpID, challenge, wrongOrigin)
	if err != nil {
		t.Fatalf("build wrong-origin attestation: %v", err)
	}

	finishResp, err := client.Post(mgmtBaseURL()+registerFinishPath, "application/json", strings.NewReader(attestation))
	if err != nil {
		t.Fatalf("register/finish: %v", err)
	}
	finishRaw, readErr := io.ReadAll(finishResp.Body)
	_ = finishResp.Body.Close()
	if readErr != nil {
		t.Fatalf("read register/finish response: %v", readErr)
	}
	if finishResp.StatusCode >= 200 && finishResp.StatusCode < 300 {
		t.Fatalf("register/finish from origin %q (outside WEBAUTHN_RP_ORIGINS) = %d, want a client error\n%s", wrongOrigin, finishResp.StatusCode, finishRaw)
	}

	if status := userStatus(t, conn, userID); status != "pending" {
		t.Errorf("users.status after a wrong-origin register/finish = %q, want pending (no partial state)", status)
	}
	if n := credentialCount(t, conn, userID); n != 0 {
		t.Errorf("credentials for user %s after a wrong-origin register/finish = %d, want 0", userID, n)
	}
}

// =========================================================================
// 6) Recovery gating
// =========================================================================

// TestSignupRecoveryGating_FullScopeRouteRefusesUntilRecoveryComplete proves
// the bff.RequireFullScope gate on GET /signup/success specifically: the SAME
// BFF session refuses full-scope access before recovery setup and accepts it
// immediately after — no fresh sign-in required — exercised end-to-end
// through the real HTTP surface and Postgres, unlike the equivalent in-process
// unit test (cmd/harbor-mgmt/caller_test.go's
// TestPostRegistrationHandoffAndRecoveryGating_EndToEnd).
func TestSignupRecoveryGating_FullScopeRouteRefusesUntilRecoveryComplete(t *testing.T) {
	conn := openDB(t)
	client := signupJarClient(t)
	userID, _ := enroll(t, client)
	if !registerPasskey(t, client) {
		t.Skip("first passkey registration did not complete on this stack — skipping recovery gating assertion")
	}

	resp, err := client.Get(mgmtBaseURL() + signupSuccessPath)
	if err != nil {
		unavailable(t, "GET %s unreachable: %v", signupSuccessPath, err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("GET %s before recovery acknowledge = %d, want 403 (bff.RequireFullScope)", signupSuccessPath, resp.StatusCode)
	}
	if !readRecoveryRequired(t, conn, userID) {
		t.Fatalf("users.recovery_required = false right after first-passkey registration, want true")
	}

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

	// The SAME cookie, no fresh sign-in, now passes.
	resp, err = client.Get(mgmtBaseURL() + signupSuccessPath)
	if err != nil {
		unavailable(t, "GET %s unreachable: %v", signupSuccessPath, err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s after recovery acknowledge = %d, want 200 (same session, refreshed scope)", signupSuccessPath, resp.StatusCode)
	}
	if readRecoveryRequired(t, conn, userID) {
		t.Errorf("users.recovery_required = true after POST %s succeeded, want false", recoveryAcknowledgePath)
	}
}
