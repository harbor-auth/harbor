//go:build e2e

// Expiry and replay invariants for the signup ceremony endpoints, exercised
// through the new signup pages' underlying calls (POST /webauthn/register/*).
// See signup_test.go's package doc comment for the shared harness/jar notes.
package e2e

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

// =========================================================================
// 3) Expiry
// =========================================================================

// TestSignupExpiry_EnrollmentSessionFailsClosed proves that presenting an
// unknown harbor_enrollment_session value — indistinguishable, from the
// server's perspective, from a real one whose Redis TTL
// (mgmtapi.enrollmentSessionTTL, 10 min) has already elapsed — fails closed
// with a generic error rather than a specific, oracle-like signal.
func TestSignupExpiry_EnrollmentSessionFailsClosed(t *testing.T) {
	resp := rawRequest(t, http.MethodPost, registerBeginPath, "", map[string]string{
		enrollmentSessionCookieName: "expired-or-forged-enrollment-session-token",
	})
	raw, readErr := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if readErr != nil {
		t.Fatalf("read register/begin response: %v", readErr)
	}
	if resp.StatusCode < 400 {
		t.Fatalf("register/begin with an expired/unknown enrollment session = %d, want a failure\n%s", resp.StatusCode, raw)
	}
	var body struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("decode register/begin error response: %v\n%s", err, raw)
	}
	if body.Code == "" {
		t.Errorf("expired/unknown enrollment session failure carried no generic error code\n%s", raw)
	}
}

// TestSignupExpiry_WebAuthnCeremonySessionFailsClosed proves that presenting
// a valid, live enrollment session but an unknown/expired
// harbor_webauthn_session ceremony key fails closed with a generic error and
// leaves no partial state — matching an expired 5-minute ceremony
// (internal/webauthn/handlers.go's session TTL) exactly, since an evicted key
// and a forged one are indistinguishable to the ceremony store.
func TestSignupExpiry_WebAuthnCeremonySessionFailsClosed(t *testing.T) {
	conn := openDB(t)
	client := signupJarClient(t)
	userID, _ := enroll(t, client)

	beginResp, err := client.Post(mgmtBaseURL()+registerBeginPath, "application/json", nil)
	if err != nil {
		unavailable(t, "register/begin unreachable: %v", err)
	}
	_ = beginResp.Body.Close()
	if beginResp.StatusCode != http.StatusOK {
		unavailable(t, "register/begin = %d (ceremony not wired) — skipping ceremony-expiry assertion", beginResp.StatusCode)
	}

	enrollCookie := cookieValue(t, client, enrollmentSessionCookieName)
	if enrollCookie == "" {
		t.Fatal("register/begin succeeded but no enrollment cookie is present in the jar")
	}

	resp := rawRequest(t, http.MethodPost, registerFinishPath,
		`{"id":"AAAA","rawId":"AAAA","type":"public-key","response":{"attestationObject":"AAAA","clientDataJSON":"AAAA"}}`,
		map[string]string{
			enrollmentSessionCookieName:       enrollCookie,
			webauthnCeremonySessionCookieName: "expired-or-forged-ceremony-session-token",
		})
	raw, readErr := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if readErr != nil {
		t.Fatalf("read register/finish response: %v", readErr)
	}
	if resp.StatusCode < 400 {
		t.Fatalf("register/finish with an expired/unknown ceremony session = %d, want a failure\n%s", resp.StatusCode, raw)
	}

	if status := userStatus(t, conn, userID); status != "pending" {
		t.Errorf("users.status after an expired-ceremony register/finish = %q, want pending (no partial state)", status)
	}
	if n := credentialCount(t, conn, userID); n != 0 {
		t.Errorf("credentials for user %s after an expired-ceremony register/finish = %d, want 0", userID, n)
	}
}

// =========================================================================
// 4) Replay
// =========================================================================

// TestSignupReplay_RegisterFinishCannotMintSecondCredential proves that a
// captured POST /webauthn/register/finish request — same cookies, same
// body — cannot be replayed to mint a second credential from the same
// challenge. The ceremony session is one-time-use (SessionStore.Take,
// internal/webauthn/store_redis.go: atomic GET+DEL), so the second, replayed
// request must fail even though every byte matches the first.
func TestSignupReplay_RegisterFinishCannotMintSecondCredential(t *testing.T) {
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
		unavailable(t, "register/begin = %d (ceremony not wired) — skipping replay assertion", beginResp.StatusCode)
	}

	rpID, challenge, err := parseBeginRegistrationResponse(beginBody)
	if err != nil {
		t.Fatalf("parse register/begin response: %v\n%s", err, beginBody)
	}
	attestation, _, _, err := makeAttestation(rpID, challenge)
	if err != nil {
		t.Fatalf("build attestation: %v", err)
	}

	enrollCookie := cookieValue(t, client, enrollmentSessionCookieName)
	webauthnCookie := cookieValue(t, client, webauthnCeremonySessionCookieName)
	if enrollCookie == "" || webauthnCookie == "" {
		t.Fatal("register/begin did not leave the expected ceremony cookies in the jar")
	}
	cookies := map[string]string{
		enrollmentSessionCookieName:       enrollCookie,
		webauthnCeremonySessionCookieName: webauthnCookie,
	}

	// First finish: the legitimate ceremony completes.
	resp1 := rawRequest(t, http.MethodPost, registerFinishPath, attestation, cookies)
	body1, readErr := io.ReadAll(resp1.Body)
	_ = resp1.Body.Close()
	if readErr != nil {
		t.Fatalf("read first register/finish response: %v", readErr)
	}
	if resp1.StatusCode != http.StatusOK {
		t.Skipf("first register/finish = %d (ceremony not wired on this stack) — skipping replay assertion\n%s", resp1.StatusCode, body1)
	}

	// Replay: the exact same captured cookies and body, presented again.
	resp2 := rawRequest(t, http.MethodPost, registerFinishPath, attestation, cookies)
	body2, readErr := io.ReadAll(resp2.Body)
	_ = resp2.Body.Close()
	if readErr != nil {
		t.Fatalf("read replayed register/finish response: %v", readErr)
	}
	if resp2.StatusCode >= 200 && resp2.StatusCode < 300 {
		t.Fatalf("replayed register/finish = %d, want a failure (the ceremony session is one-time-use)\n%s", resp2.StatusCode, body2)
	}

	if n := credentialCount(t, conn, userID); n != 1 {
		t.Errorf("credentials for user %s after a replayed register/finish = %d, want exactly 1 (replay must not mint a second credential)", userID, n)
	}
}
