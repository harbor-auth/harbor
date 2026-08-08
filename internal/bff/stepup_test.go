package bff

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/harbor-auth/harbor/internal/oidc"
)

// fixedNow returns a clock function pinned to t, for deterministic TTL tests.
func fixedNow(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

// newStepUpFixture builds a StepUpGate over an in-memory store whose clock and
// gate clock are both pinned to now, plus a session seeded with the given
// userID and MFAVerifiedAt. It returns the gate and the seeded request id.
func newStepUpFixture(t *testing.T, now time.Time, ttl time.Duration, userID string, mfaVerifiedAt time.Time) (*StepUpGate, string) {
	t.Helper()
	store := NewInMemoryBFFSessionStore()
	store.now = fixedNow(now)

	const requestID = "req-stepup"
	record := BFFSessionRecord{
		RequestID:     requestID,
		UserID:        userID,
		MFAVerifiedAt: mfaVerifiedAt,
		ExpiresAt:     now.Add(1 * time.Hour), // session itself is fresh
	}
	if err := store.Create(context.Background(), record); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	gate := NewStepUpGate(store, ttl)
	gate.now = fixedNow(now)
	return gate, requestID
}

// serveStepUp runs a request (optionally carrying the BFF cookie) through the
// gate and reports whether next was invoked plus the recorder.
func serveStepUp(gate *StepUpGate, cookieValue string) (bool, *httptest.ResponseRecorder) {
	var reached bool
	handler := gate.Require(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodPost, "/sensitive", nil)
	if cookieValue != "" {
		req.AddCookie(&http.Cookie{Name: CookieName, Value: cookieValue})
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return reached, rec
}

func TestStepUpGate_AllowsFreshVerification(t *testing.T) {
	now := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)
	// Verified 1 minute ago, well within the 5-minute TTL.
	gate, reqID := newStepUpFixture(t, now, DefaultStepUpTTL, "user-1", now.Add(-1*time.Minute))

	reached, rec := serveStepUp(gate, reqID)

	if !reached {
		t.Error("expected next handler to be reached for a fresh verification")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestStepUpGate_DeniesStaleVerification(t *testing.T) {
	now := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)
	// Verified 6 minutes ago, beyond the 5-minute TTL.
	gate, reqID := newStepUpFixture(t, now, DefaultStepUpTTL, "user-1", now.Add(-6*time.Minute))

	reached, rec := serveStepUp(gate, reqID)

	if reached {
		t.Error("next handler must NOT be reached for a stale verification")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestStepUpGate_DeniesNeverVerified(t *testing.T) {
	now := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)
	// Zero MFAVerifiedAt → never passed a step-up challenge.
	gate, reqID := newStepUpFixture(t, now, DefaultStepUpTTL, "user-1", time.Time{})

	reached, rec := serveStepUp(gate, reqID)

	if reached {
		t.Error("next handler must NOT be reached when never verified")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestStepUpGate_DeniesNoUser(t *testing.T) {
	now := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)
	// A fresh verification timestamp but no authenticated user must still deny —
	// a session with no user cannot have completed a step-up.
	gate, reqID := newStepUpFixture(t, now, DefaultStepUpTTL, "", now.Add(-1*time.Minute))

	reached, rec := serveStepUp(gate, reqID)

	if reached {
		t.Error("next handler must NOT be reached when the session has no user")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestStepUpGate_DeniesNoCookie(t *testing.T) {
	now := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)
	gate, _ := newStepUpFixture(t, now, DefaultStepUpTTL, "user-1", now.Add(-1*time.Minute))

	// No cookie sent.
	reached, rec := serveStepUp(gate, "")

	if reached {
		t.Error("next handler must NOT be reached without a BFF cookie")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestStepUpGate_DeniesUnknownSession(t *testing.T) {
	now := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)
	gate, _ := newStepUpFixture(t, now, DefaultStepUpTTL, "user-1", now.Add(-1*time.Minute))

	// A cookie pointing at a session that does not exist.
	reached, rec := serveStepUp(gate, "does-not-exist")

	if reached {
		t.Error("next handler must NOT be reached for an unknown session")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestStepUpGate_VerificationIsBoundToOneSession(t *testing.T) {
	now := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)
	store := NewInMemoryBFFSessionStore()
	store.now = fixedNow(now)
	for _, id := range []string{"session-a", "session-b"} {
		if err := store.Create(context.Background(), BFFSessionRecord{
			// A non-empty BrowserNonceHash represents a normal, nonce-bound
			// login (e.g. via /authorize or /signin) — the only kind of
			// session RecordTOTPStepUp is willing to step up (M3).
			RequestID: id, UserID: "user-1", BrowserNonceHash: []byte("nonce-hash"), ExpiresAt: now.Add(time.Hour),
		}); err != nil {
			t.Fatalf("Create(%s): %v", id, err)
		}
	}
	if err := RecordTOTPStepUp(context.Background(), store, "session-a", now); err != nil {
		t.Fatalf("RecordTOTPStepUp: %v", err)
	}
	gate := NewStepUpGate(store, DefaultStepUpTTL)
	gate.now = fixedNow(now)

	if reached, _ := serveStepUp(gate, "session-a"); !reached {
		t.Fatal("the verified session must pass")
	}
	if reached, rec := serveStepUp(gate, "session-b"); reached || rec.Code != http.StatusForbidden {
		t.Fatalf("sibling session reached=%v status=%d, want false/403", reached, rec.Code)
	}
}

type failingStepUpStore struct{ BFFSessionStore }

func (failingStepUpStore) Get(context.Context, string) (BFFSessionRecord, error) {
	return BFFSessionRecord{}, errors.New("redis unavailable")
}

func TestStepUpGate_RedisOutageFailsClosed(t *testing.T) {
	gate := NewStepUpGate(failingStepUpStore{}, DefaultStepUpTTL)
	reached, rec := serveStepUp(gate, "session-a")
	if reached || rec.Code != http.StatusForbidden {
		t.Fatalf("Redis outage reached=%v status=%d, want false/403", reached, rec.Code)
	}
}

// TestStepUpGate_BoundaryIsExclusive proves a verification exactly at the TTL
// boundary is treated as stale (the window is now-verified < ttl, strict).
func TestStepUpGate_BoundaryIsExclusive(t *testing.T) {
	now := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)
	// Verified exactly DefaultStepUpTTL ago → boundary, must be denied.
	gate, reqID := newStepUpFixture(t, now, DefaultStepUpTTL, "user-1", now.Add(-DefaultStepUpTTL))

	reached, rec := serveStepUp(gate, reqID)

	if reached {
		t.Error("next handler must NOT be reached exactly at the TTL boundary")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

// TestStepUpGate_DenyResponseIsUniform proves the deny path sets the
// step_up_required hint so a client can drive an MFA challenge and retry.
func TestStepUpGate_DenyResponseIsUniform(t *testing.T) {
	now := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)
	gate, reqID := newStepUpFixture(t, now, DefaultStepUpTTL, "user-1", time.Time{})

	_, rec := serveStepUp(gate, reqID)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if got := rec.Header().Get("WWW-Authenticate"); got == "" {
		t.Error("expected a WWW-Authenticate header hinting step_up_required")
	}
}

func TestNewStepUpGate_DefaultsTTL(t *testing.T) {
	store := NewInMemoryBFFSessionStore()
	// A non-positive ttl must fall back to DefaultStepUpTTL.
	if gate := NewStepUpGate(store, 0); gate.ttl != DefaultStepUpTTL {
		t.Errorf("ttl = %v, want %v (zero should default)", gate.ttl, DefaultStepUpTTL)
	}
	if gate := NewStepUpGate(store, -1*time.Second); gate.ttl != DefaultStepUpTTL {
		t.Errorf("ttl = %v, want %v (negative should default)", gate.ttl, DefaultStepUpTTL)
	}
	custom := 90 * time.Second
	if gate := NewStepUpGate(store, custom); gate.ttl != custom {
		t.Errorf("ttl = %v, want %v (positive should be kept)", gate.ttl, custom)
	}
}

// TestStepUpGate_CustomTTL proves a caller-supplied TTL is honoured: a
// verification fresh for the default window but stale for a tighter custom
// window is denied.
func TestStepUpGate_CustomTTL(t *testing.T) {
	now := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)
	// Verified 90s ago; passes under the 5-min default but fails under a 60s TTL.
	gate, reqID := newStepUpFixture(t, now, 60*time.Second, "user-1", now.Add(-90*time.Second))

	reached, rec := serveStepUp(gate, reqID)

	if reached {
		t.Error("next handler must NOT be reached: verification is stale under the custom TTL")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

// --- SetMFAVerified store method ---

func TestInMemoryBFFSessionStore_SetMFAVerified(t *testing.T) {
	store := NewInMemoryBFFSessionStore()
	ctx := context.Background()

	record := BFFSessionRecord{
		RequestID: "req-123",
		UserID:    "user-1",
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
	if err := store.Create(ctx, record); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	verifiedAt := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)
	if err := store.SetMFAVerified(ctx, "req-123", verifiedAt); err != nil {
		t.Fatalf("SetMFAVerified failed: %v", err)
	}

	got, err := store.Get(ctx, "req-123")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if !got.MFAVerifiedAt.Equal(verifiedAt) {
		t.Errorf("MFAVerifiedAt = %v, want %v", got.MFAVerifiedAt, verifiedAt)
	}
}

func TestInMemoryBFFSessionStore_SetMFAVerified_NotFound(t *testing.T) {
	store := NewInMemoryBFFSessionStore()
	err := store.SetMFAVerified(context.Background(), "nonexistent", time.Now())
	if !errors.Is(err, ErrBFFSessionNotFound) {
		t.Errorf("SetMFAVerified(nonexistent) = %v, want ErrBFFSessionNotFound", err)
	}
}

func TestInMemoryBFFSessionStore_SetMFAVerified_Expired(t *testing.T) {
	store := NewInMemoryBFFSessionStore()
	ctx := context.Background()

	pastTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	store.now = fixedNow(pastTime)

	record := BFFSessionRecord{
		RequestID: "req-123",
		UserID:    "user-1",
		ExpiresAt: pastTime.Add(-1 * time.Minute), // already expired
	}
	if err := store.Create(ctx, record); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	err := store.SetMFAVerified(ctx, "req-123", pastTime)
	if !errors.Is(err, ErrBFFSessionExpired) {
		t.Errorf("SetMFAVerified(expired) = %v, want ErrBFFSessionExpired", err)
	}
}

// TestRecordTOTPStepUp verifies that RecordTOTPStepUp stamps both MFAVerifiedAt
// (so the StepUpGate allows the session through) and AuthMethod=TOTP (so the
// correct ACR/AMR claims are emitted in the issued token).
func TestRecordTOTPStepUp(t *testing.T) {
	now := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)
	store := NewInMemoryBFFSessionStore()
	store.now = fixedNow(now)
	ctx := context.Background()

	const requestID = "req-totp"
	if err := store.Create(ctx, BFFSessionRecord{
		RequestID:        requestID,
		UserID:           "user-1",
		BrowserNonceHash: []byte("nonce-hash"),
		ExpiresAt:        now.Add(1 * time.Hour),
	}); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	if err := RecordTOTPStepUp(ctx, store, requestID, now); err != nil {
		t.Fatalf("RecordTOTPStepUp failed: %v", err)
	}

	got, err := store.Get(ctx, requestID)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if !got.MFAVerifiedAt.Equal(now) {
		t.Errorf("MFAVerifiedAt = %v, want %v", got.MFAVerifiedAt, now)
	}
	if got.AuthMethod != oidc.AuthMethodTOTP {
		t.Errorf("AuthMethod = %q, want %q", got.AuthMethod, oidc.AuthMethodTOTP)
	}
}

func TestRecordTOTPStepUp_SessionNotFound(t *testing.T) {
	store := NewInMemoryBFFSessionStore()
	err := RecordTOTPStepUp(context.Background(), store, "nonexistent", time.Now())
	if !errors.Is(err, ErrBFFSessionNotFound) {
		t.Errorf("RecordTOTPStepUp(nonexistent) = %v, want ErrBFFSessionNotFound", err)
	}
}

// TestRecordTOTPStepUp_RefusesFederatedSession is M3's core proof: the
// corporate-SSO handoff's session shape (AuthMethod=federated, no
// BrowserNonceHash — exactly what cmd/harbor-mgmt/sso.go's
// wireSSOLoginRoute mints) must never get a step-up verification recorded,
// however valid the TOTP code presented was. Without this, a federated
// session could self-enroll TOTP and use it to unlock
// StepUpGate-protected routes it was never meant to reach.
func TestRecordTOTPStepUp_RefusesFederatedSession(t *testing.T) {
	now := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)
	store := NewInMemoryBFFSessionStore()
	store.now = fixedNow(now)
	ctx := context.Background()

	const requestID = "req-federated"
	if err := store.Create(ctx, BFFSessionRecord{
		RequestID:  requestID,
		UserID:     "user-1",
		AuthMethod: oidc.AuthMethodFederated,
		// BrowserNonceHash deliberately nil, mirroring wireSSOLoginRoute.
		ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	err := RecordTOTPStepUp(ctx, store, requestID, now)
	if !errors.Is(err, ErrStepUpNotPermittedForSession) {
		t.Fatalf("RecordTOTPStepUp(federated session) error = %v, want ErrStepUpNotPermittedForSession", err)
	}

	got, getErr := store.Get(ctx, requestID)
	if getErr != nil {
		t.Fatalf("Get failed: %v", getErr)
	}
	if !got.MFAVerifiedAt.IsZero() {
		t.Errorf("MFAVerifiedAt = %v, want zero (never stamped)", got.MFAVerifiedAt)
	}

	// The step-up gate must therefore still deny this session.
	gate := NewStepUpGate(store, DefaultStepUpTTL)
	gate.now = fixedNow(now)
	if reached, rec := serveStepUp(gate, requestID); reached || rec.Code != http.StatusForbidden {
		t.Fatalf("federated session after failed RecordTOTPStepUp: reached=%v status=%d, want denied 403", reached, rec.Code)
	}
}

// TestRecordTOTPStepUp_RefusesNonceLessSession proves the SECOND, independent
// half of the M3 check: a session with no AuthMethod set at all (not even
// "federated") but ALSO no BrowserNonceHash is refused too — the check does
// not rely solely on AuthMethod being correctly labeled.
func TestRecordTOTPStepUp_RefusesNonceLessSession(t *testing.T) {
	now := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)
	store := NewInMemoryBFFSessionStore()
	store.now = fixedNow(now)
	ctx := context.Background()

	const requestID = "req-nonceless"
	if err := store.Create(ctx, BFFSessionRecord{
		RequestID: requestID,
		UserID:    "user-1",
		ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	if err := RecordTOTPStepUp(ctx, store, requestID, now); !errors.Is(err, ErrStepUpNotPermittedForSession) {
		t.Fatalf("RecordTOTPStepUp(nonce-less session) error = %v, want ErrStepUpNotPermittedForSession", err)
	}
}

// TestSessionEligibleForMFAStepUp exercises the exported predicate directly
// (internal/mgmtapi.MFAEnrollmentGuard's production adapter,
// cmd/harbor-mgmt's bffMFAEnrollmentGuard, relies on the exact same
// function).
func TestSessionEligibleForMFAStepUp(t *testing.T) {
	cases := []struct {
		name    string
		session BFFSessionRecord
		want    bool
	}{
		{"normal nonce-bound webauthn session", BFFSessionRecord{AuthMethod: oidc.AuthMethodWebAuthn, BrowserNonceHash: []byte("h")}, true},
		{"federated session with a nonce (shouldn't happen, still refused)", BFFSessionRecord{AuthMethod: oidc.AuthMethodFederated, BrowserNonceHash: []byte("h")}, false},
		{"non-federated session with no nonce", BFFSessionRecord{AuthMethod: oidc.AuthMethodWebAuthn}, false},
		{"federated, nonce-less (wireSSOLoginRoute's actual shape)", BFFSessionRecord{AuthMethod: oidc.AuthMethodFederated}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := SessionEligibleForMFAStepUp(tc.session); got != tc.want {
				t.Errorf("SessionEligibleForMFAStepUp(%+v) = %v, want %v", tc.session, got, tc.want)
			}
		})
	}
}

// TestStepUpGate_EndToEndAfterSetMFAVerified exercises the full happy path: a
// session with a user is stamped via SetMFAVerified and then passes the gate.
func TestStepUpGate_EndToEndAfterSetMFAVerified(t *testing.T) {
	now := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)
	store := NewInMemoryBFFSessionStore()
	store.now = fixedNow(now)
	ctx := context.Background()

	const requestID = "req-e2e"
	if err := store.Create(ctx, BFFSessionRecord{
		RequestID: requestID,
		UserID:    "user-1",
		ExpiresAt: now.Add(1 * time.Hour),
	}); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	gate := NewStepUpGate(store, DefaultStepUpTTL)
	gate.now = fixedNow(now)

	// Before verification: denied.
	if reached, rec := serveStepUp(gate, requestID); reached || rec.Code != http.StatusForbidden {
		t.Fatalf("pre-verify: reached=%v status=%d, want denied 403", reached, rec.Code)
	}

	// Stamp a step-up verification, then retry: allowed.
	if err := store.SetMFAVerified(ctx, requestID, now); err != nil {
		t.Fatalf("SetMFAVerified failed: %v", err)
	}
	if reached, rec := serveStepUp(gate, requestID); !reached || rec.Code != http.StatusOK {
		t.Fatalf("post-verify: reached=%v status=%d, want allowed 200", reached, rec.Code)
	}
}
