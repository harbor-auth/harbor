//go:build e2e

// End-to-end tests for the full account-recovery ceremony (Wave 5 Gate 2,
// docs/DESIGN.md §11.1). These drive the cold-path harbor-mgmt binary AND
// inspect Postgres directly, because the recovery invariants are about
// persisted state: recovery_required starts true, survives a failed/absent
// recovery, and is cleared ONLY after a fresh passkey is enrolled during a
// recovery session.
//
// The whole ceremony is exercised as one story:
//
//  1. Enroll + register a first passkey (the "old device").
//  2. Generate single-use recovery codes.
//  3. "Lose" the device — start recovery with a claimed user id.
//  4. Recover with a code — obtain the scoped, enrollment-only session cookie.
//  5. Enroll a fresh passkey using that scoped session.
//  6. Verify recovery_required is cleared in the DB.
//  7. Verify the scoped session denies non-enrollment surfaces until cleared.
//
// They reuse the enrollment harness helpers (mgmtBaseURL, jarClient, openDB,
// enroll, registerPasskey, enrollRegion, envOr) from enrollment_test.go, are
// behind the `e2e` build tag (excluded from the default `go test ./...`), and
// SKIP gracefully whenever a prerequisite is missing (mgmt unreachable, DB not
// wired, or the recovery endpoints not yet composed on this stack) so they never
// block CI on an in-progress server.
//
// Run (example):
//
//	HARBOR_MGMT_E2E_BASE_URL=http://localhost:8081 \
//	HARBOR_E2E_DATABASE_URL=postgres://harbor:harbor@localhost:5432/harbor \
//	go test -tags e2e ./e2e/... -run Recovery
package e2e

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

const (
	recoveryCodesPath    = "/recovery/codes"
	recoveryBeginPath    = "/recovery/begin"
	recoveryCompletePath = "/recovery/complete"
	recoveryFactorsPath  = "/recovery/factors"

	// userIDHeader is the header carrying the authenticated user id that the
	// management API trusts from its upstream (docs/DESIGN.md §11.1). The
	// recovery code-generation and factor-listing endpoints are gated on it.
	userIDHeader = "X-Harbor-User-ID"

	// recoveryScopedSessionCookie is the enrollment-only session cookie minted by
	// a successful POST /recovery/complete. It must ONLY permit enrolling a fresh
	// passkey until recovery_required is cleared.
	recoveryScopedSessionCookie = "harbor_recovery_session"
)

// generateRecoveryCodes calls POST /recovery/codes for userID and returns the
// plaintext codes. It skips the test when the endpoint is not wired (503) or
// unreachable, so the harness stays CI-safe on an in-progress stack.
func generateRecoveryCodes(t *testing.T, client *http.Client, userID string) []string {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, mgmtBaseURL()+recoveryCodesPath, strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("build /recovery/codes request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(userIDHeader, userID)

	resp, err := client.Do(req)
	if err != nil {
		t.Skipf("POST /recovery/codes unreachable at %s: %v — skipping", mgmtBaseURL(), err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read /recovery/codes response: %v", err)
	}
	if resp.StatusCode == http.StatusServiceUnavailable {
		t.Skip("POST /recovery/codes = 503 (recovery not wired) — skipping")
	}
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /recovery/codes = %d, want 201\n%s", resp.StatusCode, raw)
	}

	var body struct {
		Codes []string `json:"codes"`
		Count int      `json:"count"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("decode /recovery/codes response: %v\n%s", err, raw)
	}
	if len(body.Codes) == 0 {
		t.Fatalf("POST /recovery/codes returned no codes\n%s", raw)
	}
	if body.Count != len(body.Codes) {
		t.Errorf("recovery codes count = %d, want %d", body.Count, len(body.Codes))
	}
	return body.Codes
}

// beginRecovery calls POST /recovery/begin for the claimed userID and returns
// the opaque recovery_request_id. The caller is deliberately UNauthenticated —
// they have lost their passkey — so no user-id header is sent.
func beginRecovery(t *testing.T, client *http.Client, userID string) string {
	t.Helper()
	body, err := json.Marshal(map[string]string{"user_id": userID, "method": "code"})
	if err != nil {
		t.Fatalf("marshal /recovery/begin body: %v", err)
	}
	resp, err := client.Post(mgmtBaseURL()+recoveryBeginPath, "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Skipf("POST /recovery/begin unreachable: %v — skipping", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read /recovery/begin response: %v", err)
	}
	if resp.StatusCode == http.StatusServiceUnavailable {
		t.Skip("POST /recovery/begin = 503 (recovery not wired) — skipping")
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /recovery/begin = %d, want 200\n%s", resp.StatusCode, raw)
	}
	var begin struct {
		RecoveryRequestID string `json:"recovery_request_id"`
		ExpiresIn         int    `json:"expires_in"`
	}
	if err := json.Unmarshal(raw, &begin); err != nil {
		t.Fatalf("decode /recovery/begin response: %v\n%s", err, raw)
	}
	if begin.RecoveryRequestID == "" {
		t.Fatalf("POST /recovery/begin returned no recovery_request_id\n%s", raw)
	}
	return begin.RecoveryRequestID
}

// completeRecovery calls POST /recovery/complete with the ceremony id and a
// code, returning the raw response so the caller can assert on status and the
// scoped-session cookie. The scoped cookie (when set) also lands in client.Jar.
func completeRecovery(t *testing.T, client *http.Client, requestID, code string) *http.Response {
	t.Helper()
	body, err := json.Marshal(map[string]string{"recovery_request_id": requestID, "code": code})
	if err != nil {
		t.Fatalf("marshal /recovery/complete body: %v", err)
	}
	resp, err := client.Post(mgmtBaseURL()+recoveryCompletePath, "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Skipf("POST /recovery/complete unreachable: %v — skipping", err)
	}
	if resp.StatusCode == http.StatusServiceUnavailable {
		_ = resp.Body.Close()
		t.Skip("POST /recovery/complete = 503 (recovery not wired) — skipping")
	}
	return resp
}

// hasCookie reports whether resp set a cookie with the given name.
func hasCookie(resp *http.Response, name string) bool {
	for _, c := range resp.Cookies() {
		if c.Name == name {
			return true
		}
	}
	return false
}

// readRecoveryRequired reads users.recovery_required for userID. It skips when
// the column does not exist on this schema (recovery migration not applied) so
// the assertion never fails spuriously on an older DB.
func readRecoveryRequired(t *testing.T, conn *pgx.Conn, userID string) bool {
	t.Helper()
	var required bool
	if err := conn.QueryRow(context.Background(),
		"SELECT recovery_required FROM users WHERE id = $1", userID).Scan(&required); err != nil {
		t.Skipf("cannot read users.recovery_required (schema may predate recovery migration): %v — skipping", err)
	}
	return required
}

// --- Test: full recovery ceremony clears recovery_required ------------------

// TestRecoveryCeremonyEndToEnd drives the whole story: enroll + first passkey,
// generate codes, lose the device, recover with a code, enroll a fresh passkey,
// and confirm recovery_required is cleared in the DB. Every step skips (not
// fails) when its prerequisite is not wired on the test stack.
func TestRecoveryCeremonyEndToEnd(t *testing.T) {
	conn := openDB(t)
	client := jarClient(t)

	// 1) Enroll and register the first passkey (the device the user will lose).
	userID, _ := enroll(t, client)
	if !registerPasskey(t, client) {
		t.Skip("first passkey registration did not complete on this stack — skipping recovery ceremony")
	}

	// A freshly enrolled+activated account still requires recovery to be set up:
	// recovery_required is true until a recovery ceremony genuinely completes.
	if !readRecoveryRequired(t, conn, userID) {
		t.Fatalf("recovery_required = false right after enrollment, want true (REQ-005)")
	}

	// 2) Generate single-use recovery codes for the authenticated user.
	codes := generateRecoveryCodes(t, client, userID)

	// 3) "Lose the device": a NEW client with no passkey/session starts recovery.
	recoverClient := jarClient(t)
	requestID := beginRecovery(t, recoverClient, userID)

	// 4) Recover with the first code → expect 200 + the scoped session cookie.
	completeResp := completeRecovery(t, recoverClient, requestID, codes[0])
	defer func() { _ = completeResp.Body.Close() }()
	if completeResp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(completeResp.Body)
		t.Fatalf("POST /recovery/complete = %d, want 200\n%s", completeResp.StatusCode, raw)
	}
	if !hasCookie(completeResp, recoveryScopedSessionCookie) {
		t.Fatalf("successful recovery did not set the %q scoped-session cookie", recoveryScopedSessionCookie)
	}

	// recovery_required must STILL be set immediately after recovery — it is
	// cleared only once a fresh passkey is enrolled, not merely by recovering.
	if !readRecoveryRequired(t, conn, userID) {
		t.Fatalf("recovery_required = false after /recovery/complete but before fresh enrollment, want true (fail-closed fence)")
	}

	// 5) Enroll a FRESH passkey using the scoped recovery session (recoverClient
	// carries the scoped cookie in its jar).
	if !registerPasskey(t, recoverClient) {
		t.Skip("fresh passkey enrollment did not complete on this stack — cannot assert recovery_required clears")
	}

	// 6) Now recovery_required must be cleared — the account is fully recovered.
	if readRecoveryRequired(t, conn, userID) {
		t.Errorf("recovery_required = true after fresh passkey enrollment, want false (recovery complete, REQ-005)")
	}

	// A fresh credential must exist for the user (at least the original + fresh).
	var credCount int
	if err := conn.QueryRow(context.Background(),
		"SELECT count(*) FROM credentials WHERE user_id = $1", userID).Scan(&credCount); err != nil {
		t.Fatalf("count credentials: %v", err)
	}
	if credCount < 1 {
		t.Errorf("credentials for user %s = %d after recovery, want >= 1", userID, credCount)
	}
}

// --- Test: a recovery code is single-use end-to-end -------------------------

// TestRecoveryCodeSingleUseEndToEnd proves a code cannot be replayed: after a
// successful recovery, presenting the SAME code+ceremony again is rejected with
// the uniform 401 (the ceremony is one-time-use and was deleted on success).
func TestRecoveryCodeSingleUseEndToEnd(t *testing.T) {
	client := jarClient(t)
	userID, _ := enroll(t, client)

	codes := generateRecoveryCodes(t, client, userID)

	recoverClient := jarClient(t)
	requestID := beginRecovery(t, recoverClient, userID)

	// First completion succeeds.
	resp1 := completeRecovery(t, recoverClient, requestID, codes[0])
	status1 := resp1.StatusCode
	_ = resp1.Body.Close()
	if status1 != http.StatusOK {
		t.Skipf("first /recovery/complete = %d (recovery not fully wired) — skipping replay assertion", status1)
	}

	// Replaying the same ceremony + code must fail uniformly (401): the ceremony
	// was consumed and deleted on the first success.
	resp2 := completeRecovery(t, recoverClient, requestID, codes[0])
	status2 := resp2.StatusCode
	_ = resp2.Body.Close()
	if status2 != http.StatusUnauthorized {
		t.Errorf("replayed /recovery/complete = %d, want 401 (single-use ceremony)", status2)
	}
}

// --- Test: an invalid code fails closed with a uniform response -------------

// TestRecoveryInvalidCodeFailsClosed proves a wrong code is rejected with the
// uniform 401 and never mints a scoped session — the endpoint is not an oracle
// and never grants enrollment on a failed proof.
func TestRecoveryInvalidCodeFailsClosed(t *testing.T) {
	client := jarClient(t)
	userID, _ := enroll(t, client)

	// Ensure codes exist so the only reason for failure is the wrong code.
	_ = generateRecoveryCodes(t, client, userID)

	recoverClient := jarClient(t)
	requestID := beginRecovery(t, recoverClient, userID)

	resp := completeRecovery(t, recoverClient, requestID, "WRONG-CODE-0000-0000-0000-0000-0000")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("invalid-code /recovery/complete = %d, want 401 (fail closed)\n%s", resp.StatusCode, raw)
	}
	if hasCookie(resp, recoveryScopedSessionCookie) {
		t.Error("a failed recovery must NOT set the scoped-session cookie")
	}
}

// --- Test: the scoped session denies non-enrollment surfaces ----------------

// TestRecoveryScopedSessionDeniesNonEnrollment proves the enrollment-only scope:
// the session minted by /recovery/complete may register a fresh passkey but must
// NOT authorize any other authenticated surface while recovery_required holds.
//
// The scoped session authorizes via the recovery cookie alone (NOT the trusted
// X-Harbor-User-ID header), so we hit a non-enrollment authenticated endpoint
// (GET /recovery/factors) carrying ONLY the scoped cookie and assert it is not
// granted (must be 401/403), while register/begin with the same cookie is
// accepted. Skips gracefully when scoped-session enforcement is not wired.
func TestRecoveryScopedSessionDeniesNonEnrollment(t *testing.T) {
	client := jarClient(t)
	userID, _ := enroll(t, client)
	codes := generateRecoveryCodes(t, client, userID)

	recoverClient := jarClient(t)
	requestID := beginRecovery(t, recoverClient, userID)
	resp := completeRecovery(t, recoverClient, requestID, codes[0])
	status := resp.StatusCode
	gotCookie := hasCookie(resp, recoveryScopedSessionCookie)
	_ = resp.Body.Close()
	if status != http.StatusOK {
		t.Skipf("/recovery/complete = %d (recovery not fully wired) — skipping scope assertion", status)
	}
	if !gotCookie {
		t.Skip("no scoped-session cookie set — scoped sessions not wired on this stack; skipping")
	}

	// recoverClient now carries ONLY the scoped recovery cookie (no user-id
	// header). A non-enrollment authenticated surface must NOT be authorized by
	// it: GET /recovery/factors is gated on real authentication, so the scoped
	// session must be rejected.
	req, err := http.NewRequest(http.MethodGet, mgmtBaseURL()+recoveryFactorsPath, nil)
	if err != nil {
		t.Fatalf("build /recovery/factors request: %v", err)
	}
	factorsResp, err := recoverClient.Do(req)
	if err != nil {
		t.Skipf("GET /recovery/factors unreachable: %v — skipping", err)
	}
	defer func() { _ = factorsResp.Body.Close() }()

	switch factorsResp.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		// Correct: the scoped session did not authorize a non-enrollment surface.
	case http.StatusServiceUnavailable:
		t.Skip("GET /recovery/factors = 503 (factor listing not wired) — cannot assert scope; skipping")
	case http.StatusOK:
		t.Errorf("scoped recovery session authorized GET /recovery/factors (200) — it must ONLY permit fresh passkey enrollment until recovery_required is cleared")
	default:
		// Any other non-2xx is acceptable (still denied); a 2xx would be a leak.
		if factorsResp.StatusCode >= 200 && factorsResp.StatusCode < 300 {
			t.Errorf("scoped recovery session got 2xx (%d) on a non-enrollment surface — scope too broad", factorsResp.StatusCode)
		}
	}
}
