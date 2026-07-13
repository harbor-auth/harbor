package oidc

import (
	"context"
	"errors"
	"testing"
	"time"
)

const (
	testRefreshUserID   = "00000000-0000-0000-0000-000000000001"
	testRefreshClientID = "rp-test"
)

// newTestServiceWithSessions builds a minimal Service with in-memory session +
// grant stores for refresh-token tests.
func newTestServiceWithSessions(t *testing.T) (*Service, *InMemorySessionStore, *InMemoryGrantStore) {
	t.Helper()
	sessionStore := NewInMemorySessionStore()
	grantStore := NewInMemoryGrantStore()
	svc := NewService(ServiceConfig{
		Issuer:       "https://test.harbor.example",
		Clients:      NewInMemoryClientRegistry(),
		Codes:        NewInMemoryAuthCodeStore(),
		Tokens:       NewPlaceholderIssuer(),
		Sessions:     NewStubSessionResolver("stub-ppid"),
		Grants:       grantStore,
		SessionStore: sessionStore,
	})
	return svc, sessionStore, grantStore
}

//harbor:invariant INV-REFRESH-ROTATION-INVALIDATES-OLD
func TestRefreshRotationInvalidatesOldToken(t *testing.T) {
	svc, sessionStore, grantStore := newTestServiceWithSessions(t)
	oldToken := seedSession(t, sessionStore, grantStore, "ppid-rotation")

	req := TokenRequest{
		GrantType:    grantTypeRefreshToken,
		RefreshToken: oldToken,
		ClientID:     testRefreshClientID,
	}
	tokens, terr := svc.Refresh(context.Background(), req)
	if terr != nil {
		t.Fatalf("Refresh: %v", terr)
	}
	if tokens.RefreshToken == "" {
		t.Fatal("expected a new refresh token")
	}
	if tokens.RefreshToken == oldToken {
		t.Fatal("new token must differ from old")
	}

	// Presenting the OLD token again must fail.
	_, terr2 := svc.Refresh(context.Background(), req)
	if terr2 == nil {
		t.Fatal("expected error on old token replay")
	}
	if terr2.Code != ErrCodeInvalidGrant {
		t.Fatalf("expected invalid_grant, got %q", terr2.Code)
	}
}

//harbor:invariant INV-REFRESH-THEFT-SIGNAL-FAMILY-REVOKE
func TestRefreshReuseFiresTheftSignal(t *testing.T) {
	svc, sessionStore, grantStore := newTestServiceWithSessions(t)
	origToken := seedSession(t, sessionStore, grantStore, "ppid-theft")

	req := TokenRequest{
		GrantType:    grantTypeRefreshToken,
		RefreshToken: origToken,
		ClientID:     testRefreshClientID,
	}
	// First use: rotate legitimately.
	tokens, terr := svc.Refresh(context.Background(), req)
	if terr != nil {
		t.Fatalf("first Refresh: %v", terr)
	}

	// Attacker replays the original (now-revoked) token -> family revoke.
	_, terr2 := svc.Refresh(context.Background(), req)
	if terr2 == nil || terr2.Code != ErrCodeInvalidGrant {
		t.Fatalf("expected invalid_grant on replay, got %v", terr2)
	}

	// The new token from the legitimate rotate must ALSO be revoked now.
	req2 := TokenRequest{
		GrantType:    grantTypeRefreshToken,
		RefreshToken: tokens.RefreshToken,
		ClientID:     testRefreshClientID,
	}
	_, terr3 := svc.Refresh(context.Background(), req2)
	if terr3 == nil || terr3.Code != ErrCodeInvalidGrant {
		t.Fatalf("expected family to be revoked: got %v", terr3)
	}
}

//harbor:invariant INV-REFRESH-EXPIRY-ENFORCED
func TestRefreshExpiredTokenRejected(t *testing.T) {
	svc, sessionStore, grantStore := newTestServiceWithSessions(t)

	if _, err := grantStore.CreateGrant(context.Background(), NewGrant{
		Region: "us", UserID: testRefreshUserID, ClientID: testRefreshClientID,
		PairwiseSub: "ppid-expired", Scopes: []string{"openid", "offline_access"},
	}); err != nil {
		t.Fatal(err)
	}
	plaintext, hash, err := newOpaqueToken()
	if err != nil {
		t.Fatalf("newOpaqueToken: %v", err)
	}
	if err := sessionStore.CreateSession(context.Background(), RefreshSession{
		ID: "expired-session", Region: "us", UserID: testRefreshUserID,
		ClientID: testRefreshClientID, TokenHash: hash,
		ExpiresAt: time.Now().Add(-time.Hour), // already expired
	}); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	_, terr := svc.Refresh(context.Background(), TokenRequest{
		GrantType:    grantTypeRefreshToken,
		RefreshToken: encodeRefreshToken(plaintext),
		ClientID:     testRefreshClientID,
	})
	if terr == nil || terr.Code != ErrCodeInvalidGrant {
		t.Fatalf("expected invalid_grant for expired token, got %v", terr)
	}
}

//harbor:invariant INV-REFRESH-HASH-LOOKUP
func TestRefreshHashLookup(t *testing.T) {
	// Verify that the store is keyed on SHA-256(plaintext), not the plaintext
	// itself. An attacker with only DB read access holds base64url(hash) — they
	// cannot use that as a token because the service hashes again before lookup:
	// sha256(hash) ≠ hash (with overwhelming probability), so the lookup misses.
	svc, sessionStore, grantStore := newTestServiceWithSessions(t)
	realToken := seedSession(t, sessionStore, grantStore, "ppid-hash-lookup")

	// Decode the plaintext so we can construct the DB-attacker's token.
	plaintext, err := decodeRefreshToken(realToken)
	if err != nil {
		t.Fatalf("decodeRefreshToken: %v", err)
	}
	hash := hashRefreshToken(plaintext)

	// Present base64url(hash) as the token — the attacker's best guess from the DB.
	// The service will compute sha256(hash) ≠ original hash → lookup miss → invalid_grant.
	hashAsToken := encodeRefreshToken(hash)
	_, terr := svc.Refresh(context.Background(), TokenRequest{
		GrantType:    grantTypeRefreshToken,
		RefreshToken: hashAsToken,
		ClientID:     testRefreshClientID,
	})
	if terr == nil || terr.Code != ErrCodeInvalidGrant {
		t.Fatalf("expected invalid_grant when presenting hash-as-token, got %v", terr)
	}

	// Sanity check: the real plaintext token is unaffected by the failed attempt.
	_, terr2 := svc.Refresh(context.Background(), TokenRequest{
		GrantType:    grantTypeRefreshToken,
		RefreshToken: realToken,
		ClientID:     testRefreshClientID,
	})
	if terr2 != nil {
		t.Fatalf("expected real plaintext token to work, got %v", terr2)
	}
}

//harbor:invariant INV-REFRESH-HASH-AT-REST
func TestRefreshHashAtRest(t *testing.T) {
	plaintext, hash, err := newOpaqueToken()
	if err != nil {
		t.Fatalf("newOpaqueToken: %v", err)
	}
	encoded := encodeRefreshToken(plaintext)
	// The stored hash must not be the presentable (plaintext) token in any encoding.
	if encoded == encodeRefreshToken(hash) {
		t.Fatal("stored hash must not equal the presentable plaintext token — hash-at-rest violated")
	}
	// Re-hashing the plaintext must reproduce the same hash (deterministic).
	rehash := hashRefreshToken(plaintext)
	if string(rehash) != string(hash) {
		t.Fatal("hashRefreshToken must be deterministic")
	}
	// A hash-only holder cannot reconstruct the plaintext (different length/value).
	if string(hash) == string(plaintext) {
		t.Fatal("hash must differ from plaintext")
	}
}

// TestRefreshConsentRevoked verifies that when a user revokes consent after a
// refresh token was issued, the next Refresh() returns invalid_grant (not
// server_error). A server_error would cause well-behaved OAuth clients to retry
// indefinitely, never prompting re-authentication; invalid_grant causes them to
// re-initiate the authorization flow (§RFC 6749 §5.2).
//
//harbor:invariant INV-REFRESH-CONSENT-REVOKED
func TestRefreshConsentRevoked(t *testing.T) {
	svc, sessionStore, grantStore := newTestServiceWithSessions(t)
	oldToken := seedSession(t, sessionStore, grantStore, "ppid-revoked-consent")

	// Revoke the consent grant — simulates user clicking "revoke access".
	grants, err := grantStore.ListGrantsByUser(context.Background(), testRefreshUserID)
	if err != nil {
		t.Fatalf("ListGrantsByUser: %v", err)
	}
	if len(grants) == 0 {
		t.Fatal("seedSession must have created at least one grant — none found (seedSession or CreateGrant bug)")
	}
	for _, g := range grants {
		if err := grantStore.RevokeGrant(context.Background(), g.ID); err != nil {
			t.Fatalf("RevokeGrant: %v", err)
		}
	}

	_, terr := svc.Refresh(context.Background(), refreshReq(oldToken))
	if terr == nil {
		t.Fatal("expected error when grant has been revoked")
	}
	if terr.Code != ErrCodeInvalidGrant {
		t.Fatalf("revoked grant must return invalid_grant (not %q); a server_error here would cause clients to retry indefinitely instead of re-consenting", terr.Code)
	}
}

// TestRefreshTokenRegionPropagated verifies that the RefreshSession created
// by issueRefreshToken (called from Token during code exchange) carries the
// user's home region from the consent grant, and that RotateSession preserves
// it through rotation — satisfying the user-owned-row contract
// (docs/DESIGN.md §10). An empty Region would propagate forever.
//
//harbor:invariant INV-REFRESH-REGION-PROPAGATED
func TestRefreshTokenRegionPropagated(t *testing.T) {
	const wantRegion = "eu-west-1"

	// Build stores.
	sessionStore := NewInMemorySessionStore()
	grantStore := NewInMemoryGrantStore()

	// Build a PPIDSessionResolver wired to the same grantStore so the grant
	// created by Resolve is visible to issueRefreshToken's FindGrant call.
	secretLoader := NewInMemorySecretLoader()
	secretLoader.Put(testRefreshUserID, UserSecret{
		Region: wantRegion,
		Secret: []byte("32-byte-test-secret-for-ppid-der"),
	})
	resolver := NewPPIDSessionResolver(PPIDSessionResolverConfig{
		Auth:   NewFixedAuthSource(testRefreshUserID),
		Loader: secretLoader,
		Grants: grantStore,
	})

	clientReg := NewInMemoryClientRegistry()
	clientReg.Put(Client{
		ID:            testRefreshClientID,
		SectorID:      "test.example.com",
		RedirectURIs:  []string{"http://localhost/cb"},
		ScopesAllowed: []string{"openid", "offline_access"},
	})

	svc := NewService(ServiceConfig{
		Issuer:       "https://test.harbor.example",
		Clients:      clientReg,
		Codes:        NewInMemoryAuthCodeStore(),
		Tokens:       NewPlaceholderIssuer(),
		Sessions:     resolver,
		SessionStore: sessionStore,
		Grants:       grantStore,
	})

	// Step 1: Authorize to get a code.
	result, aerr := svc.Authorize(context.Background(), AuthorizeRequest{
		ClientID:            testRefreshClientID,
		RedirectURI:         "http://localhost/cb",
		ResponseType:        "code",
		Scope:               "openid offline_access",
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: "S256",
		State:               "st",
	})
	if aerr != nil {
		t.Fatalf("Authorize: %v", aerr)
	}

	// Step 2: Exchange the code for tokens — issueRefreshToken is called here.
	tokens, terr := svc.Token(context.Background(), TokenRequest{
		GrantType:    grantTypeAuthorizationCode,
		Code:         result.Code,
		RedirectURI:  "http://localhost/cb",
		ClientID:     testRefreshClientID,
		CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
	})
	if terr != nil {
		t.Fatalf("Token: %v", terr)
	}
	if tokens.RefreshToken == "" {
		t.Fatal("expected a refresh token to be issued")
	}

	// Step 3: Decode the refresh token and look up the session to verify region.
	plaintext, err := decodeRefreshToken(tokens.RefreshToken)
	if err != nil {
		t.Fatalf("decodeRefreshToken: %v", err)
	}
	hash := hashRefreshToken(plaintext)
	session, err := sessionStore.GetSessionByTokenHash(context.Background(), hash)
	if err != nil {
		t.Fatalf("GetSessionByTokenHash: %v", err)
	}
	if session.Region != wantRegion {
		t.Fatalf("session.Region = %q, want %q — issueRefreshToken did not propagate region from grant", session.Region, wantRegion)
	}

	// Step 4: Rotate the refresh token and verify region is preserved by RotateSession.
	tokens2, terr2 := svc.Refresh(context.Background(), TokenRequest{
		GrantType:    grantTypeRefreshToken,
		RefreshToken: tokens.RefreshToken,
		ClientID:     testRefreshClientID,
	})
	if terr2 != nil {
		t.Fatalf("Refresh (rotation): %v", terr2)
	}
	if tokens2.RefreshToken == "" {
		t.Fatal("expected a new refresh token after rotation")
	}
	plaintext2, err2 := decodeRefreshToken(tokens2.RefreshToken)
	if err2 != nil {
		t.Fatalf("decodeRefreshToken (rotated): %v", err2)
	}
	hash2 := hashRefreshToken(plaintext2)
	session2, err2 := sessionStore.GetSessionByTokenHash(context.Background(), hash2)
	if err2 != nil {
		t.Fatalf("GetSessionByTokenHash (rotated): %v", err2)
	}
	if session2.Region != wantRegion {
		t.Fatalf("rotated session.Region = %q, want %q — RotateSession did not preserve region", session2.Region, wantRegion)
	}
}

//harbor:invariant INV-REFRESH-OFFLINE-ACCESS-GATE
//harbor:invariant INV-REFRESH-ROTATION-REQUIRES-OFFLINE-ACCESS
func TestRefreshOfflineAccessGate(t *testing.T) {
	// Sub-test 4 (tested via TestRefreshRotationRequiresOfflineAccess below):
	// The Refresh() rotation path also gates on offline_access — see that test.
	// A code exchange WITHOUT offline_access must NOT produce a refresh token.
	svc, _, _ := newTestServiceWithSessions(t)
	clientReg := NewInMemoryClientRegistry()
	clientReg.Put(Client{
		ID:            testRefreshClientID,
		SectorID:      "test.example.com",
		RedirectURIs:  []string{"http://localhost/cb"},
		ScopesAllowed: []string{"openid", "profile"},
	})
	svc.clients = clientReg

	code := AuthCode{
		Code:                "test-code-no-offline",
		ClientID:            testRefreshClientID,
		RedirectURI:         "http://localhost/cb",
		Scope:               "openid profile",
		Subject:             "ppid-no-offline",
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: "S256",
		ExpiresAt:           time.Now().Add(60 * time.Second),
		UserID:              "", // no userID -> won't issue refresh token
	}
	if err := svc.codes.Save(context.Background(), code); err != nil {
		t.Fatalf("Save code: %v", err)
	}

	tokens, terr := svc.Token(context.Background(), TokenRequest{
		GrantType:    grantTypeAuthorizationCode,
		Code:         "test-code-no-offline",
		RedirectURI:  "http://localhost/cb",
		ClientID:     testRefreshClientID,
		CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
	})
	if terr != nil {
		t.Fatalf("Token: %v", terr)
	}
	if tokens.RefreshToken != "" {
		t.Fatal("expected no refresh token when offline_access is not granted")
	}

	// Sub-test: offline_access IS present but UserID is empty — still no refresh token.
	// Both conditions (offline_access scope AND non-empty UserID) are required.
	code2 := AuthCode{
		Code:                "test-code-offline-no-userid",
		ClientID:            testRefreshClientID,
		RedirectURI:         "http://localhost/cb",
		Scope:               "openid offline_access",
		Subject:             "ppid-offline-no-userid",
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: "S256",
		ExpiresAt:           time.Now().Add(60 * time.Second),
		UserID:              "", // offline_access present but UserID empty → no refresh token
	}
	if err := svc.codes.Save(context.Background(), code2); err != nil {
		t.Fatalf("Save code2: %v", err)
	}
	tokens2, terr2 := svc.Token(context.Background(), TokenRequest{
		GrantType:    grantTypeAuthorizationCode,
		Code:         "test-code-offline-no-userid",
		RedirectURI:  "http://localhost/cb",
		ClientID:     testRefreshClientID,
		CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
	})
	if terr2 != nil {
		t.Fatalf("Token (offline+no-userid): %v", terr2)
	}
	if tokens2.RefreshToken != "" {
		t.Fatal("expected no refresh token when UserID is empty, even with offline_access")
	}

	// Sub-test 3: offline_access present, UserID non-empty, but no active grant exists
	// (simulates consent revoked between /authorize and /token, or noopGrantStore
	// dev wiring with a real UserID). issueRefreshToken must skip gracefully — the
	// access token exchange still succeeds but no refresh token is emitted.
	// svc's grantStore (from newTestServiceWithSessions) is empty, so FindGrant
	// returns found=false — exactly the fail-closed path under test.
	code3 := AuthCode{
		Code:                "test-code-offline-userid-nogrant",
		ClientID:            testRefreshClientID,
		RedirectURI:         "http://localhost/cb",
		Scope:               "openid offline_access",
		Subject:             "ppid-offline-userid-nogrant",
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: "S256",
		ExpiresAt:           time.Now().Add(60 * time.Second),
		UserID:              testRefreshUserID, // non-empty — triggers issueRefreshToken — but no grant exists
	}
	if err := svc.codes.Save(context.Background(), code3); err != nil {
		t.Fatalf("Save code3: %v", err)
	}
	tokens3, terr3 := svc.Token(context.Background(), TokenRequest{
		GrantType:    grantTypeAuthorizationCode,
		Code:         "test-code-offline-userid-nogrant",
		RedirectURI:  "http://localhost/cb",
		ClientID:     testRefreshClientID,
		CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
	})
	if terr3 != nil {
		t.Fatalf("Token (offline+userid+nogrant): %v", terr3)
	}
	if tokens3.RefreshToken != "" {
		t.Fatal("expected no refresh token when grant is absent even with offline_access+UserID (fail-closed on missing grant)")
	}
}

// TestRefreshRotationRequiresOfflineAccess verifies the H14-2 fix: Refresh()
// re-checks that the frozen grant still contains offline_access before Steps C/D
// (rotation + new refresh token issuance). A grant scope downgrade after
// issuance must be handled fail-closed: freshly-signed access/ID tokens are
// returned, no new refresh token is issued, and the old session is NOT revoked
// so the client is not locked out.
//
//harbor:invariant INV-REFRESH-ROTATION-REQUIRES-OFFLINE-ACCESS
func TestRefreshRotationRequiresOfflineAccess(t *testing.T) {
	svc, sessionStore, grantStore := newTestServiceWithSessions(t)

	// Create a grant that does NOT contain offline_access (simulating a scope
	// downgrade after the refresh session was originally issued).
	if _, err := grantStore.CreateGrant(context.Background(), NewGrant{
		Region:      "us",
		UserID:      testRefreshUserID,
		ClientID:    testRefreshClientID,
		PairwiseSub: "ppid-rotation-no-offline",
		Scopes:      []string{"openid"}, // offline_access deliberately absent
	}); err != nil {
		t.Fatalf("CreateGrant: %v", err)
	}

	// Seed a session directly (bypassing issueRefreshToken which would itself
	// gate on offline_access — we want to test only the Refresh() re-check).
	plaintext, hash, err := newOpaqueToken()
	if err != nil {
		t.Fatalf("newOpaqueToken: %v", err)
	}
	if err := sessionStore.CreateSession(context.Background(), RefreshSession{
		ID:        "session-rotation-no-offline",
		Region:    "us",
		UserID:    testRefreshUserID,
		ClientID:  testRefreshClientID,
		TokenHash: hash,
		ExpiresAt: svc.now().Add(defaultRefreshTTL),
	}); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	token := encodeRefreshToken(plaintext)

	// Refresh() must return access/ID tokens but NO refresh token (offline_access
	// guard fires before Steps C+D).
	tokens, terr := svc.Refresh(context.Background(), refreshReq(token))
	if terr != nil {
		t.Fatalf("Refresh: expected success (access token), got error: %v", terr)
	}
	if tokens.RefreshToken != "" {
		t.Fatal("expected no refresh token when grant scopes no longer contain offline_access")
	}

	// The old session must NOT have been revoked — client is not locked out
	// and can retry once the scope issue is resolved (or simply use access token).
	_, err = sessionStore.GetSessionByTokenHash(context.Background(), hash)
	if err != nil {
		t.Fatalf("old session must still be valid (not revoked) after offline_access guard fires: %v", err)
	}
}

// TestRefreshRevokedAndExpiredReturnsRevoked verifies that a session that is
// both revoked AND past its ExpiresAt returns ErrRefreshTokenRevoked (not
// ErrRefreshTokenNotFound). This ensures the theft signal fires even when an
// attacker replays an expired-but-revoked token — parity with the DB store's
// ordering guarantee (TestDBSessionStoreGetByTokenHash_RevokedAndExpired).
//
//harbor:invariant INV-REFRESH-THEFT-SIGNAL-FAMILY-REVOKE
func TestRefreshRevokedAndExpiredReturnsRevoked(t *testing.T) {
	store := NewInMemorySessionStore()
	plaintext, hash, err := newOpaqueToken()
	if err != nil {
		t.Fatalf("newOpaqueToken: %v", err)
	}
	if err := store.CreateSession(context.Background(), RefreshSession{
		ID:        "revoked-and-expired",
		Region:    "us",
		UserID:    testRefreshUserID,
		ClientID:  testRefreshClientID,
		TokenHash: hash,
		ExpiresAt: time.Now().Add(-time.Hour), // already expired
	}); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if err := store.RevokeSession(context.Background(), "revoked-and-expired"); err != nil {
		t.Fatalf("RevokeSession: %v", err)
	}
	// A token that is both revoked and expired must surface as Revoked so the
	// theft detector can act — not as NotFound (which would silently discard it).
	_, err = store.GetSessionByTokenHash(context.Background(), hashRefreshToken(plaintext))
	if err == nil {
		t.Fatal("expected error for revoked+expired session")
	}
	if !errors.Is(err, ErrRefreshTokenRevoked) {
		t.Fatalf("revoked+expired: want ErrRefreshTokenRevoked, got %v", err)
	}
}

// TestRefreshWrongClientRejected verifies that a refresh token may only be
// redeemed by the client_id it was originally issued to. Presenting a valid
// token with a different client_id returns invalid_grant — this prevents
// a compromised RP from using another RP's refresh tokens.
//
//harbor:invariant INV-REFRESH-CLIENT-BINDING
func TestRefreshWrongClientRejected(t *testing.T) {
	svc, sessionStore, grantStore := newTestServiceWithSessions(t)
	oldToken := seedSession(t, sessionStore, grantStore, "ppid-client-binding")
	_, terr := svc.Refresh(context.Background(), TokenRequest{
		GrantType:    grantTypeRefreshToken,
		RefreshToken: oldToken,
		ClientID:     "different-client", // wrong client
	})
	if terr == nil {
		t.Fatal("expected error when presenting token to wrong client")
	}
	if terr.Code != ErrCodeInvalidGrant {
		t.Fatalf("wrong client: want invalid_grant, got %q", terr.Code)
	}
}
