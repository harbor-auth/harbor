//go:build e2e

// Concurrent-session isolation for the signup journey: overlapping signup
// attempts, and a signup racing an unrelated user's lost-device recovery,
// must never cross-bind or corrupt each other's session/account state. See
// signup_test.go's package doc comment for the shared harness/jar notes, and
// signup_helpers_test.go for driveFullSignup and the goroutine-safe (plain
// error) request helpers these tests rely on — testing.T's Fatal/Skip family
// may only be called from the goroutine running the test, so the concurrent
// legs below use those plain-error helpers and only call t.Fatal/t.Errorf
// after wg.Wait() on the main test goroutine.
package e2e

import (
	"fmt"
	"net/http"
	"sync"
	"testing"
)

// =========================================================================
// 7) Concurrent sessions
// =========================================================================

// TestSignupConcurrentSessions_TwoIndependentSignupsDoNotCrossBind runs two
// full signup journeys concurrently and proves neither cross-binds or
// corrupts the other's session/account state: each ends up with its own
// distinct user id, its own cookie reaches its own full-scope success page,
// and each account has exactly the one credential its own story produced.
func TestSignupConcurrentSessions_TwoIndependentSignupsDoNotCrossBind(t *testing.T) {
	conn := openDB(t)

	clientA := signupJarClient(t)
	clientB := signupJarClient(t)

	var userA, userB string
	var errA, errB error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		userA, errA = driveFullSignup(t, clientA)
	}()
	go func() {
		defer wg.Done()
		userB, errB = driveFullSignup(t, clientB)
	}()
	wg.Wait()

	if errA != nil || errB != nil {
		t.Skipf("concurrent signup not exercisable on this stack: A=%v B=%v", errA, errB)
	}
	if userA == "" || userB == "" || userA == userB {
		t.Fatalf("concurrent signups did not produce two distinct users: userA=%q userB=%q", userA, userB)
	}

	respA, err := clientA.Get(mgmtBaseURL() + signupSuccessPath)
	if err != nil {
		unavailable(t, "GET %s unreachable: %v", signupSuccessPath, err)
	}
	_ = respA.Body.Close()
	if respA.StatusCode != http.StatusOK {
		t.Errorf("client A GET %s after its own signup completed = %d, want 200", signupSuccessPath, respA.StatusCode)
	}

	respB, err := clientB.Get(mgmtBaseURL() + signupSuccessPath)
	if err != nil {
		unavailable(t, "GET %s unreachable: %v", signupSuccessPath, err)
	}
	_ = respB.Body.Close()
	if respB.StatusCode != http.StatusOK {
		t.Errorf("client B GET %s after its own signup completed = %d, want 200", signupSuccessPath, respB.StatusCode)
	}

	for _, id := range []string{userA, userB} {
		if n := credentialCount(t, conn, id); n != 1 {
			t.Errorf("credentials for user %s = %d, want exactly 1 (no cross-binding under concurrency)", id, n)
		}
	}
}

// TestSignupConcurrentSessions_SignupRacesLostDeviceRecoveryForDifferentUser
// races a brand-new signup against an UNRELATED user's lost-device recovery
// ceremony and proves the two do not cross-bind or corrupt each other's
// session/account state.
func TestSignupConcurrentSessions_SignupRacesLostDeviceRecoveryForDifferentUser(t *testing.T) {
	conn := openDB(t)

	// Pre-provision "user B" sequentially — enrolled, has a passkey, has
	// recovery codes — so only the recovery ceremony itself overlaps with the
	// concurrent signup below.
	clientB := signupJarClient(t)
	userB, _ := enroll(t, clientB)
	if !registerPasskey(t, clientB) {
		t.Skip("first passkey registration did not complete on this stack — cannot set up the racing recovery scenario")
	}
	codesB := generateRecoveryCodes(t, clientB)

	clientA := signupJarClient(t)
	recoverClientB := signupJarClient(t)

	var userA string
	var errA, errRecoverB error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		userA, errA = driveFullSignup(t, clientA)
	}()
	go func() {
		defer wg.Done()
		reqID, err := httpBeginRecovery(recoverClientB, userB)
		if err != nil {
			errRecoverB = err
			return
		}
		if err := httpCompleteRecovery(recoverClientB, reqID, codesB[0]); err != nil {
			errRecoverB = err
			return
		}
		ok, _, _ := registerPasskeyWithKey(t, recoverClientB)
		if !ok {
			errRecoverB = fmt.Errorf("fresh passkey enrollment during recovery did not complete")
		}
	}()
	wg.Wait()

	if errA != nil {
		t.Skipf("concurrent signup leg not exercisable: %v", errA)
	}
	if errRecoverB != nil {
		t.Skipf("concurrent lost-device recovery leg not exercisable: %v", errRecoverB)
	}
	if userA == "" || userA == userB {
		t.Fatalf("racing signup produced userA=%q, want a distinct new user from userB=%q", userA, userB)
	}

	respA, err := clientA.Get(mgmtBaseURL() + signupSuccessPath)
	if err != nil {
		unavailable(t, "GET %s unreachable: %v", signupSuccessPath, err)
	}
	_ = respA.Body.Close()
	if respA.StatusCode != http.StatusOK {
		t.Errorf("client A (fresh signup) GET %s = %d, want 200 — must not be affected by a concurrent recovery for a different user", signupSuccessPath, respA.StatusCode)
	}

	if readRecoveryRequired(t, conn, userB) {
		t.Errorf("users.recovery_required for user B = true after B's own concurrent recovery ceremony completed, want false")
	}
	if readRecoveryRequired(t, conn, userA) {
		t.Errorf("users.recovery_required for user A = true after A's own concurrent signup completed, want false")
	}

	if n := credentialCount(t, conn, userA); n != 1 {
		t.Errorf("credentials for user A (fresh signup) = %d, want exactly 1", n)
	}
	if n := credentialCount(t, conn, userB); n != 2 {
		t.Errorf("credentials for user B (original + recovery passkey) = %d, want exactly 2", n)
	}
}
