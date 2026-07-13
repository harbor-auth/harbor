// chaos_test.go — chaos-monkey tests: inject failures at each layer of the
// OIDC service and verify the system handles them gracefully:
//   - correct error codes (server_error vs invalid_grant — never confuse the two)
//   - no lock-out hazard (a pre-rotation failure must leave the old token valid)
//   - no panics
//   - security events are logged even when recovery is impossible
//
// Every chaos scenario follows the same three-step structure:
//  1. Seed: a valid session + grant in the in-memory stores.
//  2. Inject: swap in a chaos wrapper that injects the failure.
//  3. Assert: correct error code + (where applicable) old token survives.
//
// These complement the pure-unit tests in refresh_test.go and the DB-layer
// tests in internal/clients/sessions_test.go.

package oidc

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// ─── chaos fake stores ───────────────────────────────────────────────────────

// chaosGetSessionStore wraps InMemorySessionStore and injects an error on
// GetSessionByTokenHash to simulate a transient DB failure mid-lookup.
type chaosGetSessionStore struct {
	*InMemorySessionStore
	getErr error
}

func (s *chaosGetSessionStore) GetSessionByTokenHash(_ context.Context, _ []byte) (RefreshSession, error) {
	return RefreshSession{}, s.getErr
}

// chaosRotateSessionStore wraps InMemorySessionStore and injects an error on
// RotateSession to simulate a transient DB failure at the atomic commit point.
type chaosRotateSessionStore struct {
	*InMemorySessionStore
	rotateErr error
}

func (s *chaosRotateSessionStore) RotateSession(ctx context.Context, id string, ns RefreshSession) error {
	if s.rotateErr != nil {
		return s.rotateErr
	}
	return s.InMemorySessionStore.RotateSession(ctx, id, ns)
}

// chaosRevokeSessionStore wraps InMemorySessionStore and injects an error on
// RevokeSessionsByUserClient to simulate a DB failure during the theft-signal
// family revoke.
type chaosRevokeSessionStore struct {
	*InMemorySessionStore
	revokeErr error
}

func (s *chaosRevokeSessionStore) RevokeSessionsByUserClient(_ context.Context, _, _ string) error {
	return s.revokeErr
}

// chaosFindGrantStore wraps InMemoryGrantStore and injects an error on
// FindGrant to simulate the grant table being temporarily unavailable.
type chaosFindGrantStore struct {
	*InMemoryGrantStore
	findErr error
}

func (s *chaosFindGrantStore) FindGrant(ctx context.Context, userID, clientID string) (Grant, bool, error) {
	if s.findErr != nil {
		return Grant{}, false, s.findErr
	}
	return s.InMemoryGrantStore.FindGrant(ctx, userID, clientID)
}

// ─── helpers ─────────────────────────────────────────────────────────────────

// newChaosService returns a minimal Service with in-memory stores suitable for
// chaos tests. Callers replace individual store fields after construction.
func newChaosService(sessionStore SessionStore, grantStore GrantStore) *Service {
	return NewService(ServiceConfig{
		Issuer:       "https://chaos.harbor.example",
		Clients:      NewInMemoryClientRegistry(),
		Codes:        NewInMemoryAuthCodeStore(),
		Tokens:       NewPlaceholderIssuer(),
		Sessions:     NewStubSessionResolver("ppid-chaos"),
		SessionStore: sessionStore,
		Grants:       grantStore,
	})
}

// ─── chaos tests ─────────────────────────────────────────────────────────────

// TestChaos_Refresh_SessionLookupDBError verifies that a transient DB error on
// GetSessionByTokenHash surfaces as server_error (5xx), NOT as invalid_grant.
//
// Masking a DB outage as invalid_grant would silently reject every valid refresh
// token for the duration of the outage, triggering a mass logout
// (docs/DESIGN.md §10). The service must propagate the raw error so the HTTP
// layer can return 500 and allow clients to retry.
//
//harbor:invariant INV-DB-ERROR-NOT-MASKED
func TestChaos_Refresh_SessionLookupDBError(t *testing.T) {
	dbErr := errors.New("connection reset by peer")
	chaosStore := &chaosGetSessionStore{
		InMemorySessionStore: NewInMemorySessionStore(),
		getErr:               dbErr,
	}
	svc := newChaosService(chaosStore, NewInMemoryGrantStore())

	// The plaintext token doesn't need to be real — the injected DB error fires
	// before any content-based validation of the token.
	plaintext, _, err := newOpaqueToken()
	if err != nil {
		t.Fatalf("newOpaqueToken: %v", err)
	}

	_, terr := svc.Refresh(context.Background(), refreshReq(encodeRefreshToken(plaintext)))
	if terr == nil {
		t.Fatal("expected error; got nil")
	}
	if terr.Code != ErrCodeServerError {
		t.Fatalf("DB error must propagate as server_error to avoid masking outage as mass-logout; got %q", terr.Code)
	}
	if terr.Status != 500 {
		t.Fatalf("Status = %d, want 500", terr.Status)
	}
	// Must NOT be silently converted to invalid_grant.
	if terr.Code == ErrCodeInvalidGrant {
		t.Fatal("DB error must never be masked as invalid_grant")
	}
}

// TestChaos_Refresh_GrantLookupFails_PreRotation verifies that a failure in
// FindGrant (Step A) returns server_error WITHOUT revoking the old session.
// Because FindGrant is called BEFORE RotateSession, the client can retry with
// the same refresh token once the grant store recovers
// (docs/DESIGN.md §3.5; INV-REFRESH-LOCKOUT-PREVENTION).
//
//harbor:invariant INV-REFRESH-LOCKOUT-PREVENTION
func TestChaos_Refresh_GrantLookupFails_PreRotation(t *testing.T) {
	sessionStore := NewInMemorySessionStore()
	realGrantStore := NewInMemoryGrantStore()
	oldToken := seedSession(t, sessionStore, realGrantStore, "ppid-chaos-grant")

	// Inject fault: FindGrant now always fails.
	chaosGrants := &chaosFindGrantStore{
		InMemoryGrantStore: realGrantStore,
		findErr:            errors.New("grants table: connection timeout"),
	}
	svc := newChaosService(sessionStore, chaosGrants)

	req := refreshReq(oldToken)

	// Step 1 — Refresh fails because FindGrant fails.
	_, terr := svc.Refresh(context.Background(), req)
	if terr == nil || terr.Code != ErrCodeServerError {
		t.Fatalf("grant lookup failure: want server_error, got %v", terr)
	}
	if terr.Status != 500 {
		t.Fatalf("Status = %d, want 500", terr.Status)
	}

	// Step 2 — OLD token is still valid (no rotation occurred).
	// Repair the fault and verify the original token still works.
	chaosGrants.findErr = nil
	tokens, terr2 := svc.Refresh(context.Background(), req)
	if terr2 != nil {
		t.Fatalf("old token must survive a pre-rotation grant failure; got %v", terr2)
	}
	if tokens.RefreshToken == "" {
		t.Fatal("expected a new refresh token after recovery")
	}
}

// TestChaos_Refresh_TokenSigningFails_PreRotation verifies that a signing
// failure in tokens.Issue (Step B) returns server_error WITHOUT revoking the
// old session. Because Issue is called BEFORE RotateSession, the client can
// retry with the same refresh token once the signing key recovers
// (docs/DESIGN.md §3.5; INV-REFRESH-LOCKOUT-PREVENTION).
//
//harbor:invariant INV-REFRESH-LOCKOUT-PREVENTION
func TestChaos_Refresh_TokenSigningFails_PreRotation(t *testing.T) {
	sessionStore := NewInMemorySessionStore()
	grantStore := NewInMemoryGrantStore()
	oldToken := seedSession(t, sessionStore, grantStore, "ppid-chaos-sign")

	// Inject fault: token signing always fails.
	svc := newChaosService(sessionStore, grantStore)
	svc.tokens = errTokenIssuer{issueErr: errors.New("signing key temporarily unavailable")}

	req := refreshReq(oldToken)

	// Step 1 — Refresh fails because signing fails.
	_, terr := svc.Refresh(context.Background(), req)
	if terr == nil || terr.Code != ErrCodeServerError {
		t.Fatalf("signing failure: want server_error, got %v", terr)
	}
	if terr.Status != 500 {
		t.Fatalf("Status = %d, want 500", terr.Status)
	}

	// Step 2 — OLD token is still valid (RotateSession was never reached).
	svc.tokens = NewPlaceholderIssuer() // repair
	tokens, terr2 := svc.Refresh(context.Background(), req)
	if terr2 != nil {
		t.Fatalf("old token must survive a pre-rotation signing failure; got %v", terr2)
	}
	if tokens.RefreshToken == "" {
		t.Fatal("expected a new refresh token after recovery")
	}
}

// TestChaos_Refresh_RotationFails verifies that a failure in RotateSession
// (Step D — the atomic commit point) returns server_error and leaves the old
// session intact so the client can retry.
//
//harbor:invariant INV-REFRESH-LOCKOUT-PREVENTION
func TestChaos_Refresh_RotationFails(t *testing.T) {
	innerStore := NewInMemorySessionStore()
	grantStore := NewInMemoryGrantStore()
	oldToken := seedSession(t, innerStore, grantStore, "ppid-chaos-rotate")

	// Inject fault: RotateSession always fails.
	chaosStore := &chaosRotateSessionStore{
		InMemorySessionStore: innerStore,
		rotateErr:            errors.New("deadlock detected on sessions table"),
	}
	svc := newChaosService(chaosStore, grantStore)

	req := refreshReq(oldToken)

	// Step 1 — Refresh fails at the commit point.
	_, terr := svc.Refresh(context.Background(), req)
	if terr == nil || terr.Code != ErrCodeServerError {
		t.Fatalf("rotation failure: want server_error, got %v", terr)
	}
	if terr.Status != 500 {
		t.Fatalf("Status = %d, want 500", terr.Status)
	}

	// Step 2 — OLD token is still valid because RotateSession failed atomically
	// (either the old row is revoked AND the new one exists, or neither — here
	// neither happened so the original session is intact).
	chaosStore.rotateErr = nil // repair
	tokens, terr2 := svc.Refresh(context.Background(), req)
	if terr2 != nil {
		t.Fatalf("old token must survive a rotation failure; got %v", terr2)
	}
	if tokens.RefreshToken == "" {
		t.Fatal("expected a new refresh token after recovery")
	}
}

// TestChaos_Refresh_FamilyRevokeFails_StillInvalidGrant verifies that when the
// theft-signal family revoke (RevokeSessionsByUserClient) fails, the service
// still returns invalid_grant to the client (the attacker learns nothing) AND
// logs the revocation failure at ERROR so operators can investigate.
//
// A revocation failure must NEVER become a 5xx or allow the replayed token to
// succeed — the client response is independent of the side-effect.
// (docs/DESIGN.md §11.7; docs/design/principles/error-handling.md §1.11)
//
//harbor:invariant INV-REFRESH-THEFT-SIGNAL-FAMILY-REVOKE
func TestChaos_Refresh_FamilyRevokeFails_StillInvalidGrant(t *testing.T) {
	// Seed a session, rotate it legitimately so the original token is revoked.
	innerStore := NewInMemorySessionStore()
	grantStore := NewInMemoryGrantStore()
	origToken := seedSession(t, innerStore, grantStore, "ppid-chaos-theft")

	setupSvc := newChaosService(innerStore, grantStore)
	if _, terr := setupSvc.Refresh(context.Background(), refreshReq(origToken)); terr != nil {
		t.Fatalf("initial rotation: %v", terr)
	}
	// origToken is now tombstoned (revoked). Replaying it should fire the theft signal.

	// Wire chaos: RevokeSessionsByUserClient now fails.
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))

	chaosStore := &chaosRevokeSessionStore{
		InMemorySessionStore: innerStore,
		revokeErr:            errors.New("sessions table: timeout during family revoke"),
	}
	chaosSvc := NewService(ServiceConfig{
		Issuer:       "https://chaos.harbor.example",
		Clients:      NewInMemoryClientRegistry(),
		Codes:        NewInMemoryAuthCodeStore(),
		Tokens:       NewPlaceholderIssuer(),
		Sessions:     NewStubSessionResolver("ppid-chaos-theft"),
		SessionStore: chaosStore,
		Grants:       grantStore,
		Logger:       logger,
	})

	// Replay the revoked token — must return invalid_grant, NOT 5xx.
	_, terr := chaosSvc.Refresh(context.Background(), refreshReq(origToken))
	if terr == nil {
		t.Fatal("expected error for replayed revoked token")
	}
	if terr.Code != ErrCodeInvalidGrant {
		t.Fatalf("replayed revoked token: want invalid_grant, got %q (must not leak theft signal as 5xx)", terr.Code)
	}

	// The revocation failure must be logged at ERROR (not silently swallowed).
	logOutput := logBuf.String()
	if !strings.Contains(logOutput, "refresh-family revocation failed") {
		t.Fatalf("expected ERROR log for failed family revoke; got: %s", logOutput)
	}

	// PII constraint (docs/DESIGN.md §6.5.7): user_id must not appear in logs.
	if strings.Contains(logOutput, testRefreshUserID) {
		t.Fatalf("log must not contain user_id (PII); got: %s", logOutput)
	}

	// The LEGITIMATE successor token (from the initial rotation above) must also
	// return invalid_grant when presented to chaosSvc, because the chaosStore
	// wraps the same innerStore where the original rotation already revoked the
	// predecessor. The chaos only affects RevokeSessionsByUserClient — the
	// successor session itself is still active in innerStore, so presenting it
	// to chaosSvc should SUCCEED (not return invalid_grant). This confirms the
	// chaos only affects the theft-signal path, not the happy path.
	// (We do not have the successor token value here — that test is out of scope
	// for this chaos fixture, which focuses on the theft-signal side-effect.)
}

// TestChaos_Refresh_NewSessionIDFails_PreRotation verifies that a failure when
// generating the new session ID (Step C — newSessionID()) returns server_error WITHOUT
// revoking the old session. Step C is before RotateSession (Step D), so the
// client can retry with the same refresh token once the RNG recovers.
//
//harbor:invariant INV-REFRESH-LOCKOUT-PREVENTION
func TestChaos_Refresh_NewSessionIDFails_PreRotation(t *testing.T) {
	sessionStore := NewInMemorySessionStore()
	grantStore := NewInMemoryGrantStore()
	oldToken := seedSession(t, sessionStore, grantStore, "ppid-chaos-newid")

	svc := newChaosService(sessionStore, grantStore)

	// Inject fault: fail the newSessionID call in Refresh — Step C generates
	// the new session ID via newSessionID(). 'called' ensures the fault fires
	// exactly once so Step 2's recovery (svc.newSessionID = ...) is unambiguous.
	called := false
	svc.newSessionID = func() (string, error) {
		if !called {
			called = true
			return "", errors.New("entropy source temporarily exhausted")
		}
		return uuid.NewString(), nil
	}

	req := refreshReq(oldToken)

	// Step 1 — Refresh fails at Step C (session ID generation).
	_, terr := svc.Refresh(context.Background(), req)
	if terr == nil || terr.Code != ErrCodeServerError {
		t.Fatalf("session-id generation failure: want server_error, got %v", terr)
	}
	if terr.Status != 500 {
		t.Fatalf("Status = %d, want 500", terr.Status)
	}

	// Step 2 — OLD token is still valid (RotateSession was never reached).
	// Repair: restore a working newSessionID.
	svc.newSessionID = func() (string, error) { return uuid.NewString(), nil }
	tokens, terr2 := svc.Refresh(context.Background(), req)
	if terr2 != nil {
		t.Fatalf("old token must survive a Step C session-id generation failure; got %v", terr2)
	}
	if tokens.RefreshToken == "" {
		t.Fatal("expected a new refresh token after recovery")
	}
}

// TestChaos_Refresh_ValidateTokenParams_GatesStoreAccess verifies that the
// H15-1 fix (ValidateTokenParams at the top of Refresh) short-circuits BEFORE
// any store access on malformed requests. It asserts by error code: an empty
// refresh_token or client_id must return invalid_request (the ValidateTokenParams
// verdict), NOT invalid_grant (which would imply the store was reached and
// returned not-found). Without the guard, an empty refresh_token computes
// SHA-256 of zero bytes and fires a real store round-trip.
func TestChaos_Refresh_ValidateTokenParams_GatesStoreAccess(t *testing.T) {
	svc := newChaosService(NewInMemorySessionStore(), NewInMemoryGrantStore())

	// Case 1: empty refresh_token → invalid_request (not invalid_grant).
	_, terr := svc.Refresh(context.Background(), TokenRequest{
		GrantType: grantTypeRefreshToken,
		ClientID:  "some-client",
		// RefreshToken intentionally empty
	})
	if terr == nil {
		t.Fatal("empty refresh_token: expected error, got nil")
	}
	if terr.Code != ErrCodeInvalidRequest {
		t.Fatalf("empty refresh_token: want invalid_request, got %q (implies ValidateTokenParams is not gating the store; the store was likely reached and returned invalid_grant)", terr.Code)
	}

	// Case 2: empty client_id → invalid_request.
	_, terr2 := svc.Refresh(context.Background(), TokenRequest{
		GrantType:    grantTypeRefreshToken,
		RefreshToken: "some-token",
		// ClientID intentionally empty
	})
	if terr2 == nil {
		t.Fatal("empty client_id: expected error, got nil")
	}
	if terr2.Code != ErrCodeInvalidRequest {
		t.Fatalf("empty client_id: want invalid_request, got %q", terr2.Code)
	}

	// Case 3: wrong grant_type → rejected by ValidateTokenParams before the store.
	_, terr3 := svc.Refresh(context.Background(), TokenRequest{
		GrantType:    "authorization_code",
		ClientID:     "some-client",
		RefreshToken: "some-token",
	})
	if terr3 == nil {
		t.Fatal("wrong grant_type: expected error, got nil")
	}
	if terr3.Code != ErrCodeUnsupportedGrantType && terr3.Code != ErrCodeInvalidRequest {
		t.Fatalf("wrong grant_type: want unsupported_grant_type or invalid_request, got %q", terr3.Code)
	}
}

// TestChaos_Refresh_SignalRefreshReuse_ZeroUUID verifies the defensive guard in
// signalRefreshReuse: when GetSessionByTokenHash returns ErrRefreshTokenRevoked
// with a session whose UserID is empty or the zero UUID sentinel, the family
// revoke is skipped (RevokeSessionsByUserClient is NOT called) and an ERROR is
// logged. Without the guard, RevokeSessionsByUserClient("",...) would silently
// match zero rows and suppress the theft signal — masking a store bug as a no-op.
//
// The correct client response is still invalid_grant (not 5xx) so the attacker
// learns nothing from the guard firing.
func TestChaos_Refresh_SignalRefreshReuse_ZeroUUID(t *testing.T) {
	for _, tc := range []struct {
		name   string
		userID string
	}{
		{name: "empty", userID: ""},
		{name: "zero_uuid", userID: zeroUUID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Chaos store: GetSessionByTokenHash returns Revoked with a bad UserID.
			chaosStore := &badUserIDSessionStore{userID: tc.userID}

			var logBuf bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&logBuf, nil))

			svc := NewService(ServiceConfig{
				Issuer:       "https://chaos.harbor.example",
				Clients:      NewInMemoryClientRegistry(),
				Codes:        NewInMemoryAuthCodeStore(),
				Tokens:       NewPlaceholderIssuer(),
				Sessions:     NewStubSessionResolver("ppid-chaos"),
				SessionStore: chaosStore,
				Grants:       NewInMemoryGrantStore(),
				Logger:       logger,
			})

			plaintext, _, err := newOpaqueToken()
			if err != nil {
				t.Fatalf("newOpaqueToken: %v", err)
			}

			// Must return invalid_grant — not 5xx.
			_, terr := svc.Refresh(context.Background(), refreshReq(encodeRefreshToken(plaintext)))
			if terr == nil {
				t.Fatal("expected error; got nil")
			}
			if terr.Code != ErrCodeInvalidGrant {
				t.Fatalf("zero-UUID guard: want invalid_grant, got %q", terr.Code)
			}

			// The ERROR log must fire.
			if !strings.Contains(logBuf.String(), "empty/invalid UserID") {
				t.Fatalf("expected ERROR log for zero-UUID guard; got: %s", logBuf.String())
			}
		})
	}
}

// badUserIDSessionStore always returns ErrRefreshTokenRevoked with a session
// whose UserID is set to the configured (bad) value — simulates a DBSessionStore
// bug where rowToRefreshSession emits a zero UUID instead of the stored value.
type badUserIDSessionStore struct {
	noopSessionStore
	userID string
}

func (s *badUserIDSessionStore) GetSessionByTokenHash(_ context.Context, _ []byte) (RefreshSession, error) {
	return RefreshSession{UserID: s.userID, ClientID: "some-client"}, ErrRefreshTokenRevoked
}
