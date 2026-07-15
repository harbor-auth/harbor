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
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

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

// recordingOutbox records every Enqueue call so chaos tests can assert that the
// durable revocation signal was persisted to the outbox EVEN WHEN the inline
// best-effort revoke fails. This is the whole point of the transactional-outbox
// pattern: a downstream (RevokeSessionsByUserClient / RevokeCodeFamily) outage
// must not drop the theft signal — it survives in the outbox for the worker.
type recordingOutbox struct {
	mu       sync.Mutex
	entries  []OutboxEntry
	enqueErr error // when set, Enqueue returns this error (simulates outbox DB failure)
}

func (o *recordingOutbox) Enqueue(_ context.Context, entry OutboxEntry) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.entries = append(o.entries, entry)
	return o.enqueErr
}

func (o *recordingOutbox) recorded() []OutboxEntry {
	o.mu.Lock()
	defer o.mu.Unlock()
	out := make([]OutboxEntry, len(o.entries))
	copy(out, o.entries)
	return out
}

// chaosRevocationSink always fails RevokeCodeFamily — used to prove the outbox
// still captures the code-reuse signal when the inline sink is unavailable.
type chaosRevocationSink struct{ err error }

func (s chaosRevocationSink) RevokeCodeFamily(context.Context, AuthCode) error { return s.err }

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
	clientReg := NewInMemoryClientRegistry()
	clientReg.Put(Client{
		ID:            testRefreshClientID,
		SectorID:      "test.example.com",
		RedirectURIs:  []string{"http://localhost/cb"},
		ScopesAllowed: []string{"openid", "offline_access"},
	})
	return NewService(ServiceConfig{
		Issuer:       "https://chaos.harbor.example",
		Clients:      clientReg,
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
	// chaosSvc intentionally uses an empty client registry: this test only
	// presents origToken (which is revoked), so the flow exits early at the
	// ErrRefreshTokenRevoked → signalRefreshReuse path — before the H20-2
	// client-existence check (which runs after ValidateRefreshParams, only
	// reached for valid sessions). If this test is extended to also verify
	// the successor-token path, register testRefreshClientID here.
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

// TestChaos_Refresh_CancelledContextBeforeLookup verifies H22-1: if the request
// context is already cancelled when Refresh() reaches the client-registry check,
// the service returns server_error (not invalid_client) so a client disconnect
// does not produce a false "client deregistered" permanent error.
//
// Mechanism: DBClientRegistry.Lookup swallows context errors and returns
// (Client{}, false), which is indistinguishable from genuine deregistration.
// The ctx.Err() pre-check (H22-1) catches an already-cancelled context BEFORE
// Lookup is called and returns server_error instead.
//
// Note: the InMemorySessionStore and InMemoryGrantStore used here do not check
// context cancellation, so the flow proceeds normally through GetSessionByTokenHash,
// ValidateRefreshParams, and FindGrant — only the H22-1 check fires.
//
//harbor:invariant INV-REFRESH-CLIENT-EXISTS
func TestChaos_Refresh_CancelledContextBeforeLookup(t *testing.T) {
	sessionStore := NewInMemorySessionStore()
	grantStore := NewInMemoryGrantStore()
	oldToken := seedSession(t, sessionStore, grantStore, "ppid-cancelled-ctx")

	svc := newChaosService(sessionStore, grantStore)

	// Cancel the context before calling Refresh to simulate a client disconnect
	// that arrives after the session lookup but before the client registry check.
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // ctx.Err() != nil immediately

	_, terr := svc.Refresh(ctx, refreshReq(oldToken))
	if terr == nil {
		t.Fatal("expected error for cancelled context")
	}
	// H22-1 guard: must be server_error (transient), NOT invalid_client (permanent).
	// invalid_client would cause well-behaved client SDKs (e.g. AppAuth) to restart
	// the entire authorization flow, logging out the user unnecessarily.
	if terr.Code != ErrCodeServerError {
		t.Fatalf("cancelled context: want server_error, got %q (H22-1 guard may be missing or misplaced)", terr.Code)
	}
	if terr.Status != 500 {
		t.Fatalf("cancelled context: want HTTP 500, got %d", terr.Status)
	}

	// No-lockout: the H22-1 pre-check fires before RotateSession, so the rejection
	// must NOT consume the session. Call Refresh with a non-cancelled context and
	// verify the same token still works — proves RotateSession was never reached.
	tokens, terr2 := svc.Refresh(context.Background(), refreshReq(oldToken))
	if terr2 != nil {
		t.Fatalf("after cancelled-ctx rejection: old token must still be valid (no lockout); got %v", terr2)
	}
	if tokens == nil || tokens.RefreshToken == "" {
		t.Fatal("after cancelled-ctx rejection: expected non-empty new refresh token")
	}
}

// TestChaos_Refresh_ValidateTokenParams_GatesStoreAccess verifies that the
// H15-1 fix (ValidateTokenParams at the top of Refresh) short-circuits BEFORE
// any store access on malformed requests. It asserts by error code: an empty
// refresh_token or client_id must return invalid_request (the ValidateTokenParams
// verdict), NOT invalid_grant (which would imply the store was reached and
// returned not-found). Without the guard, an empty refresh_token computes
// SHA-256 of zero bytes and fires a real store round-trip.
//
//harbor:invariant INV-VALIDATE-TOKEN-PARAMS-GATE
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

	// Case 3: unknown grant_type → hits the default branch in ValidateTokenParams
	// and returns unsupported_grant_type, confirming the gate fires before store.
	// Note: "authorization_code" is a *recognized* grant type in ValidateTokenParams
	// (it has its own case), so using it here would trigger invalid_request (missing
	// params), not unsupported_grant_type. Use a truly unknown type instead.
	_, terr3 := svc.Refresh(context.Background(), TokenRequest{
		GrantType:    "urn:ietf:params:oauth:grant-type:device_code",
		ClientID:     "some-client",
		RefreshToken: "some-token",
	})
	if terr3 == nil {
		t.Fatal("unknown grant_type: expected error, got nil")
	}
	if terr3.Code != ErrCodeUnsupportedGrantType {
		t.Fatalf("unknown grant_type: want unsupported_grant_type, got %q (ValidateTokenParams should reject unknown grant_type)", terr3.Code)
	}
}

// TestChaos_Token_ValidateTokenParams_GatesStoreAccess verifies that the
// ValidateTokenParams gate at the top of Token() short-circuits BEFORE any code
// store access on malformed authorization_code requests. Parity with
// TestChaos_Refresh_ValidateTokenParams_GatesStoreAccess for the Token() path.
//
//harbor:invariant INV-VALIDATE-TOKEN-PARAMS-GATE
func TestChaos_Token_ValidateTokenParams_GatesStoreAccess(t *testing.T) {
	// Use a store that panics on any access — if ValidateTokenParams does NOT
	// gate the store, the panic fires and makes the gap unmissable.
	panicCodes := &panicOnAccessAuthCodeStore{}
	svc := NewService(ServiceConfig{
		Issuer:   "https://chaos.harbor.example",
		Clients:  NewInMemoryClientRegistry(),
		Codes:    panicCodes,
		Tokens:   NewPlaceholderIssuer(),
		Sessions: NewStubSessionResolver("ppid-chaos"),
	})

	// Case 1: empty code → invalid_request (ValidateTokenParams gate).
	_, terr := svc.Token(context.Background(), TokenRequest{
		GrantType:    "authorization_code",
		ClientID:     "some-client",
		RedirectURI:  "http://localhost/cb",
		CodeVerifier: "some-verifier",
		// Code intentionally empty
	})
	if terr == nil {
		t.Fatal("empty code: expected error, got nil")
	}
	if terr.Code != ErrCodeInvalidRequest {
		t.Fatalf("empty code: want invalid_request, got %q", terr.Code)
	}

	// Case 2: empty client_id → invalid_request.
	_, terr2 := svc.Token(context.Background(), TokenRequest{
		GrantType:    "authorization_code",
		Code:         "some-code",
		RedirectURI:  "http://localhost/cb",
		CodeVerifier: "some-verifier",
		// ClientID intentionally empty
	})
	if terr2 == nil {
		t.Fatal("empty client_id: expected error, got nil")
	}
	if terr2.Code != ErrCodeInvalidRequest {
		t.Fatalf("empty client_id: want invalid_request, got %q", terr2.Code)
	}

	// Case 3: empty redirect_uri → invalid_request.
	_, terr3 := svc.Token(context.Background(), TokenRequest{
		GrantType:    "authorization_code",
		Code:         "some-code",
		ClientID:     "some-client",
		CodeVerifier: "some-verifier",
		// RedirectURI intentionally empty
	})
	if terr3 == nil {
		t.Fatal("empty redirect_uri: expected error, got nil")
	}
	if terr3.Code != ErrCodeInvalidRequest {
		t.Fatalf("empty redirect_uri: want invalid_request, got %q", terr3.Code)
	}

	// Case 4: empty code_verifier → invalid_request (ValidateTokenParams gate).
	// Note: for authorization_code, ValidateTokenParams requires all four fields
	// (code, client_id, redirect_uri, code_verifier); missing any one returns
	// invalid_request before any store access.
	_, terr4 := svc.Token(context.Background(), TokenRequest{
		GrantType:   "authorization_code",
		Code:        "some-code",
		ClientID:    "some-client",
		RedirectURI: "http://localhost/cb",
		// CodeVerifier intentionally empty
	})
	if terr4 == nil {
		t.Fatal("empty code_verifier: expected error, got nil")
	}
	if terr4.Code != ErrCodeInvalidRequest {
		t.Fatalf("empty code_verifier: want invalid_request, got %q", terr4.Code)
	}

	// Case 5: unknown grant_type → unsupported_grant_type (symmetry with
	// TestChaos_Refresh_ValidateTokenParams_GatesStoreAccess Case 3). Using a
	// device_code grant type that ValidateTokenParams does not handle.
	_, terr5 := svc.Token(context.Background(), TokenRequest{
		GrantType:    "urn:ietf:params:oauth:grant-type:device_code",
		Code:         "some-code",
		ClientID:     "some-client",
		RedirectURI:  "http://localhost/cb",
		CodeVerifier: "some-verifier",
	})
	if terr5 == nil {
		t.Fatal("unknown grant_type: expected error, got nil")
	}
	if terr5.Code != ErrCodeUnsupportedGrantType {
		t.Fatalf("unknown grant_type: want unsupported_grant_type, got %q (ValidateTokenParams should reject unknown grant_type before any store access)", terr5.Code)
	}
}

// TestChaos_Refresh_OutboxEnqueuesWhenDownstreamFails verifies that when a
// revoked refresh token is replayed AND the inline family revoke fails
// (RevokeSessionsByUserClient errors), the theft signal is still durably
// persisted to the outbox. The background worker (RevocationWorker) will then
// retry delivery, so the revocation is never silently dropped
// (docs/plans/revocation-outbox.md, DESIGN §3.5).
//
// The client response must remain invalid_grant regardless — the durability of
// the side-effect is independent of what the attacker sees.
//
//harbor:invariant INV-DURABLE-REVOCATION
func TestChaos_Refresh_OutboxEnqueuesWhenDownstreamFails(t *testing.T) {
	// Seed a session and rotate it legitimately so the original token is revoked.
	innerStore := NewInMemorySessionStore()
	grantStore := NewInMemoryGrantStore()
	origToken := seedSession(t, innerStore, grantStore, "ppid-outbox-refresh")

	setupSvc := newChaosService(innerStore, grantStore)
	if _, terr := setupSvc.Refresh(context.Background(), refreshReq(origToken)); terr != nil {
		t.Fatalf("initial rotation: %v", terr)
	}
	// origToken is now tombstoned — replaying it fires the theft signal.

	// Inline revoke fails; outbox records the enqueue.
	chaosStore := &chaosRevokeSessionStore{
		InMemorySessionStore: innerStore,
		revokeErr:            errors.New("sessions table: timeout during family revoke"),
	}
	outbox := &recordingOutbox{}

	var logBuf bytes.Buffer
	chaosSvc := NewService(ServiceConfig{
		Issuer:       "https://chaos.harbor.example",
		Clients:      NewInMemoryClientRegistry(),
		Codes:        NewInMemoryAuthCodeStore(),
		Tokens:       NewPlaceholderIssuer(),
		Sessions:     NewStubSessionResolver("ppid-outbox-refresh"),
		SessionStore: chaosStore,
		Grants:       grantStore,
		Outbox:       outbox,
		Logger:       slog.New(slog.NewTextHandler(&logBuf, nil)),
	})

	_, terr := chaosSvc.Refresh(context.Background(), refreshReq(origToken))
	if terr == nil {
		t.Fatal("expected error for replayed revoked token")
	}
	if terr.Code != ErrCodeInvalidGrant {
		t.Fatalf("replayed revoked token: want invalid_grant, got %q", terr.Code)
	}

	// The durable signal MUST have been enqueued despite the inline revoke failing.
	recorded := outbox.recorded()
	if len(recorded) != 1 {
		t.Fatalf("expected 1 outbox enqueue after inline revoke failure, got %d", len(recorded))
	}
	if recorded[0].Reason != "refresh_reuse" {
		t.Fatalf("enqueued Reason = %q, want \"refresh_reuse\"", recorded[0].Reason)
	}
	if recorded[0].ClientID != testRefreshClientID {
		t.Fatalf("enqueued ClientID = %q, want %q", recorded[0].ClientID, testRefreshClientID)
	}

	// The inline revoke failure must still be logged at ERROR (not swallowed).
	if !strings.Contains(logBuf.String(), "refresh-family revocation failed") {
		t.Fatalf("expected ERROR log for failed inline family revoke; got: %s", logBuf.String())
	}
	// PII constraint (§6.5.7): user_id must not appear in logs.
	if strings.Contains(logBuf.String(), testRefreshUserID) {
		t.Fatalf("log must not contain user_id (PII); got: %s", logBuf.String())
	}
}

// TestChaos_Token_OutboxEnqueuesWhenDownstreamFails verifies the code-reuse
// parity of TestChaos_Refresh_OutboxEnqueuesWhenDownstreamFails: when a consumed
// authorization code is replayed AND the inline RevokeCodeFamily fails, the
// code-reuse signal is still durably enqueued to the outbox for worker retry.
//
//harbor:invariant INV-DURABLE-REVOCATION
func TestChaos_Token_OutboxEnqueuesWhenDownstreamFails(t *testing.T) {
	const codeVal = "chaos-outbox-code-reuse"

	// Seed a consumed code that carries a real UserID + ClientID so the
	// signalCodeReuse enqueue guard (code.UserID != "") passes.
	codeStore := NewInMemoryAuthCodeStore()
	if err := codeStore.Save(context.Background(), AuthCode{
		Code:     codeVal,
		ClientID: testRefreshClientID,
		UserID:   testRefreshUserID,
	}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := codeStore.Consume(context.Background(), codeVal); err != nil {
		t.Fatalf("seed Consume: %v", err)
	}

	outbox := &recordingOutbox{}
	var logBuf bytes.Buffer
	svc := NewService(ServiceConfig{
		Issuer:      "https://chaos.harbor.example",
		Clients:     NewInMemoryClientRegistry(),
		Codes:       codeStore,
		Tokens:      NewPlaceholderIssuer(),
		Sessions:    NewStubSessionResolver("ppid-chaos"),
		Revocations: chaosRevocationSink{err: errors.New("code-family revoke: DB unavailable")},
		Outbox:      outbox,
		Logger:      slog.New(slog.NewTextHandler(&logBuf, nil)),
	})

	// Peek returns consumed=true → signalCodeReuse fires before ValidateTokenExchange.
	_, terr := svc.Token(context.Background(), TokenRequest{
		GrantType:    "authorization_code",
		Code:         codeVal,
		ClientID:     testRefreshClientID,
		RedirectURI:  "http://localhost/cb",
		CodeVerifier: "any-verifier",
	})
	if terr == nil {
		t.Fatal("expected error (code already consumed), got nil")
	}
	if terr.Code != ErrCodeInvalidGrant {
		t.Fatalf("want invalid_grant, got %q", terr.Code)
	}

	// The durable code-reuse signal MUST have been enqueued despite the inline
	// RevokeCodeFamily failing.
	recorded := outbox.recorded()
	if len(recorded) != 1 {
		t.Fatalf("expected 1 outbox enqueue after inline revoke failure, got %d", len(recorded))
	}
	if recorded[0].Reason != "code_reuse" {
		t.Fatalf("enqueued Reason = %q, want \"code_reuse\"", recorded[0].Reason)
	}
	if recorded[0].ClientID != testRefreshClientID {
		t.Fatalf("enqueued ClientID = %q, want %q", recorded[0].ClientID, testRefreshClientID)
	}

	// The inline revoke failure must still be logged at ERROR.
	if !strings.Contains(logBuf.String(), "code-family revocation failed") {
		t.Fatalf("expected ERROR log for failed inline code-family revoke; got: %s", logBuf.String())
	}
}

// panicOnAccessAuthCodeStore panics on any method call. Used by
// TestChaos_Token_ValidateTokenParams_GatesStoreAccess to prove that
// ValidateTokenParams fires before any store access.
type panicOnAccessAuthCodeStore struct{}

func (panicOnAccessAuthCodeStore) Save(_ context.Context, _ AuthCode) error {
	panic("Save called: ValidateTokenParams gate is missing")
}
func (panicOnAccessAuthCodeStore) Peek(_ context.Context, _ string) (AuthCode, bool, bool, error) {
	panic("Peek called: ValidateTokenParams gate is missing")
}
func (panicOnAccessAuthCodeStore) Consume(_ context.Context, _ string) (ConsumeResult, error) {
	panic("Consume called: ValidateTokenParams gate is missing")
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
//
//harbor:invariant INV-REFRESH-THEFT-SIGNAL-ZERO-UUID-GUARD
func TestChaos_Refresh_SignalRefreshReuse_ZeroUUID(t *testing.T) {
	for _, tc := range []struct {
		name     string
		userID   string
		clientID string
		wantLog  string
	}{
		{name: "empty_user_id", userID: "", clientID: "some-client", wantLog: "empty/zero UserID"},
		{name: "zero_uuid", userID: zeroUUID, clientID: "some-client", wantLog: "empty/zero UserID"},
		{name: "empty_client_id", userID: "valid-user-id", clientID: "", wantLog: "empty ClientID"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Chaos store: GetSessionByTokenHash returns Revoked with a bad field.
			chaosStore := &badSessionFieldsStore{userID: tc.userID, clientID: tc.clientID}

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
			if !strings.Contains(logBuf.String(), tc.wantLog) {
				t.Fatalf("expected ERROR log containing %q; got: %s", tc.wantLog, logBuf.String())
			}

			// NEGATIVE assertion: the guard must prevent RevokeSessionsByUserClient
			// from being called. Without the guard, a bad UserID/ClientID would
			// silently match zero rows — the call counter proves it was skipped.
			chaosStore.mu.Lock()
			count := chaosStore.revokeCallCount
			chaosStore.mu.Unlock()
			if count != 0 {
				t.Fatalf("guard must prevent RevokeSessionsByUserClient; got %d call(s)", count)
			}
		})
	}
}

// badSessionFieldsStore always returns ErrRefreshTokenRevoked with a session
// whose fields are set to the configured (bad) values — simulates a DBSessionStore
// bug where rowToRefreshSession emits a zero/empty field instead of the stored value.
// mu protects revokeCallCount, which records how many times RevokeSessionsByUserClient
// was called so tests can verify the guard prevented the call (negative assertion).
type badSessionFieldsStore struct {
	noopSessionStore
	mu              sync.Mutex
	userID          string
	clientID        string
	revokeCallCount int
}

// GetSessionByTokenHash returns ErrRefreshTokenRevoked with a session whose
// fields reflect the configured (bad) values. userID and clientID are
// write-once at struct literal construction and never mutated — no lock is
// needed here (mu protects only revokeCallCount).
func (s *badSessionFieldsStore) GetSessionByTokenHash(_ context.Context, _ []byte) (RefreshSession, error) {
	return RefreshSession{UserID: s.userID, ClientID: s.clientID}, ErrRefreshTokenRevoked
}

func (s *badSessionFieldsStore) RevokeSessionsByUserClient(_ context.Context, _, _ string) error {
	s.mu.Lock()
	s.revokeCallCount++
	s.mu.Unlock()
	return nil
}

// TestChaos_Token_SignalCodeReuse_EmptyClientID verifies the defensive guard in
// signalCodeReuse: when a replayed authorization code has an empty ClientID
// (simulating a DBAuthCodeStore bug where rowToAuthCode emits an empty client_id),
// RevokeCodeFamily is skipped and an ERROR is logged rather than silently
// suppressing the code-theft signal.
//
// The client response is still invalid_grant so the attacker learns nothing.
// This is the auth-code-path parity of TestChaos_Refresh_SignalRefreshReuse_ZeroUUID.
//
//harbor:invariant INV-CODE-THEFT-SIGNAL-EMPTY-CLIENT-GUARD
func TestChaos_Token_SignalCodeReuse_EmptyClientID(t *testing.T) {
	const codeVal = "chaos-replay-empty-client"

	// Seed a consumed code with ClientID "" — simulates a store bug where
	// rowToAuthCode emits an empty client_id instead of the stored value.
	codeStore := NewInMemoryAuthCodeStore()
	if err := codeStore.Save(context.Background(), AuthCode{Code: codeVal, ClientID: ""}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	// First Consume marks the entry consumed; the next Peek in Token() returns
	// (stored, found=true, consumed=true, nil), triggering signalCodeReuse.
	if _, err := codeStore.Consume(context.Background(), codeVal); err != nil {
		t.Fatalf("seed Consume: %v", err)
	}

	sink := NewRecordingRevocationSink()
	var logBuf bytes.Buffer
	svc := NewService(ServiceConfig{
		Issuer:      "https://chaos.harbor.example",
		Clients:     NewInMemoryClientRegistry(),
		Codes:       codeStore,
		Tokens:      NewPlaceholderIssuer(),
		Sessions:    NewStubSessionResolver("ppid-chaos"),
		Revocations: sink,
		Logger:      slog.New(slog.NewTextHandler(&logBuf, nil)),
	})

	// Peek fires BEFORE ValidateTokenExchange, so the consumed path short-circuits
	// with stored.ClientID="" before any ClientID-binding or PKCE check.
	_, terr := svc.Token(context.Background(), TokenRequest{
		GrantType:    "authorization_code",
		Code:         codeVal,
		ClientID:     "any-client", // ValidateTokenParams requires non-empty; binding check never reached
		RedirectURI:  "http://localhost/cb",
		CodeVerifier: "any-verifier",
	})
	if terr == nil {
		t.Fatal("expected error (code already consumed), got nil")
	}
	if terr.Code != ErrCodeInvalidGrant {
		t.Fatalf("want invalid_grant, got %q", terr.Code)
	}

	// The empty-ClientID guard must fire and suppress RevokeCodeFamily.
	if !strings.Contains(logBuf.String(), "empty ClientID") {
		t.Fatalf("expected ERROR log for empty-ClientID guard; got: %s", logBuf.String())
	}
	if r := sink.Revoked(); len(r) != 0 {
		t.Fatalf("empty-ClientID guard must skip RevokeCodeFamily; got %d call(s)", len(r))
	}
}

// chaosConsumePathCodeStore implements AuthCodeStore for testing the Consume-reuse
// path in Token(). Peek returns found=true, consumed=false so Token() proceeds
// through ValidateTokenExchange. Consume then returns ConsumeReused with a code
// whose ClientID is empty, simulating a DBAuthCodeStore bug in the row returned
// by the consume query. Save is a no-op since Token() never calls codes.Save.
type chaosConsumePathCodeStore struct {
	peekCode  AuthCode // returned by Peek; must pass ValidateTokenExchange
	reuseCode AuthCode // returned by Consume as ConsumeReused (empty ClientID)
}

func (s *chaosConsumePathCodeStore) Save(_ context.Context, _ AuthCode) error { return nil }

func (s *chaosConsumePathCodeStore) Peek(_ context.Context, _ string) (AuthCode, bool, bool, error) {
	// The code parameter is deliberately ignored: this store is seeded with a
	// single peekCode and a single reuseCode, so it returns the correct result
	// regardless of which code string Token() passes. Both Peek and Consume
	// receive the same req.Code, so there is no param-mismatch risk here.
	return s.peekCode, true, false, nil // found, not consumed — drives Consume-reuse path
}

func (s *chaosConsumePathCodeStore) Consume(_ context.Context, _ string) (ConsumeResult, error) {
	return ConsumeResult{Status: ConsumeReused, Code: s.reuseCode}, nil
}

// TestChaos_Token_SignalCodeReuse_ConsumePathEmptyClientID verifies the defensive
// guard in signalCodeReuse for Path 2 (the Consume call in Token()). In the race
// scenario, Peek finds the code unconsumed (so ValidateTokenExchange runs and
// passes), but Consume discovers the code was already consumed — returning
// ConsumeReused with a code whose ClientID is empty (simulating a store bug in
// the consume query's row mapping). The guard must suppress RevokeCodeFamily and
// log an ERROR; the client response must still be invalid_grant.
//
// Complements TestChaos_Token_SignalCodeReuse_EmptyClientID (which covers the
// Peek consumed=true short-circuit) for full guard coverage across both call
// sites of signalCodeReuse in Token().
//
//harbor:invariant INV-CODE-THEFT-SIGNAL-EMPTY-CLIENT-GUARD
func TestChaos_Token_SignalCodeReuse_ConsumePathEmptyClientID(t *testing.T) {
	const codeVal = "chaos-consume-path-empty-client"
	const clientID = "consume-path-client"
	const redirectURI = "http://localhost/cb"

	// Compute a valid S256 PKCE challenge for a 43-char verifier so that
	// ValidateTokenExchange passes and the flow reaches codes.Consume.
	verifier := strings.Repeat("a", 43)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	// Peek returns a valid code that passes ValidateTokenExchange.
	peekCode := AuthCode{
		Code:                codeVal,
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		ExpiresAt:           time.Now().Add(60 * time.Second),
	}
	// Consume returns ConsumeReused with an empty ClientID — the store bug.
	reuseCode := AuthCode{Code: codeVal, ClientID: ""}

	sink := NewRecordingRevocationSink()
	var logBuf bytes.Buffer
	svc := NewService(ServiceConfig{
		Issuer:      "https://chaos.harbor.example",
		Clients:     NewInMemoryClientRegistry(),
		Codes:       &chaosConsumePathCodeStore{peekCode: peekCode, reuseCode: reuseCode},
		Tokens:      NewPlaceholderIssuer(),
		Sessions:    NewStubSessionResolver("ppid-chaos"),
		Revocations: sink,
		Logger:      slog.New(slog.NewTextHandler(&logBuf, nil)),
	})

	_, terr := svc.Token(context.Background(), TokenRequest{
		GrantType:    "authorization_code",
		Code:         codeVal,
		ClientID:     clientID,
		RedirectURI:  redirectURI,
		CodeVerifier: verifier,
	})
	if terr == nil {
		t.Fatal("expected error (ConsumeReused), got nil")
	}
	if terr.Code != ErrCodeInvalidGrant {
		t.Fatalf("want invalid_grant, got %q", terr.Code)
	}

	// The empty-ClientID guard must fire (Consume-reuse path).
	if !strings.Contains(logBuf.String(), "empty ClientID") {
		t.Fatalf("expected ERROR log for empty-ClientID guard (Consume path); got: %s", logBuf.String())
	}
	// RevokeCodeFamily must NOT be called — the guard skips it.
	if r := sink.Revoked(); len(r) != 0 {
		t.Fatalf("empty-ClientID guard must skip RevokeCodeFamily; got %d call(s)", len(r))
	}
}
