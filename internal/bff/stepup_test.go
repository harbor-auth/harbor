package bff

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
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
