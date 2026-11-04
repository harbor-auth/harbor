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
	clientReg := NewInMemoryClientRegistry()
	clientReg.Put(Client{
		ID:            testRefreshClientID,
		SectorID:      "test.example.com",
		RedirectURIs:  []string{"http://localhost/cb"},
		ScopesAllowed: []string{"openid", "offline_access", "profile"},
	})
	svc := mustNewService(t, ServiceConfig{
		Issuer:       "https://test.harbor.example",
		Clients:      clientReg,
		Codes:        newRedisAuthCodeStore(t),
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

	svc := mustNewService(t, ServiceConfig{
		Issuer:       "https://test.harbor.example",
		Clients:      clientReg,
		Codes:        newRedisAuthCodeStore(t),
		Tokens:       NewPlaceholderIssuer(),
		Sessions:     resolver,
		SessionStore: sessionStore,
		Grants:       grantStore,
	})

	if err := svc.ApproveConsent(t.Context(), testRefreshUserID, testRefreshClientID, "openid offline_access"); err != nil {
		t.Fatal(err)
	}
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
	svc, _, grants := newTestServiceWithSessions(t)
	grant, err := grants.CreateGrant(t.Context(), NewGrant{Region: "EU", UserID: testRefreshUserID, ClientID: testRefreshClientID, PairwiseSub: "gate-ppid", Scopes: []string{"openid"}})
	if err != nil {
		t.Fatal(err)
	}
	code := AuthCode{Code: "no-offline", UserID: testRefreshUserID, GrantID: grant.ID, ClientID: testRefreshClientID, RedirectURI: "http://localhost/cb", Scope: "openid", Subject: grant.PairwiseSub, CodeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", CodeChallengeMethod: "S256", ExpiresAt: time.Now().Add(time.Minute)}
	if err = svc.codes.Save(t.Context(), code); err != nil {
		t.Fatal(err)
	}
	req := TokenRequest{GrantType: grantTypeAuthorizationCode, Code: code.Code, ClientID: code.ClientID, RedirectURI: code.RedirectURI, CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"}
	tokens, terr := svc.Token(t.Context(), req)
	if terr != nil {
		t.Fatal(terr)
	}
	if tokens.RefreshToken != "" {
		t.Fatal("issued refresh without offline_access")
	}
	for _, kind := range []string{"missing-user", "revoked-grant"} {
		code.Code = kind
		code.Scope = "openid offline_access"
		if kind == "missing-user" {
			code.UserID = ""
		} else {
			code.UserID = testRefreshUserID
			if err = grants.RevokeGrant(t.Context(), grant.ID); err != nil {
				t.Fatal(err)
			}
		}
		if err = svc.codes.Save(t.Context(), code); err != nil {
			t.Fatal(err)
		}
		req.Code = code.Code
		if _, terr := svc.Token(t.Context(), req); terr == nil || terr.Code != ErrCodeInvalidGrant {
			t.Fatalf("unbound/revoked code accepted: %v", terr)
		}
	}
}

//harbor:invariant INV-REFRESH-ROTATION-REQUIRES-OFFLINE-ACCESS
//harbor:invariant INV-REFRESH-SCOPE-REFLECTS-GRANT
func TestRefreshRotationRequiresOfflineAccess(t *testing.T) {
	svc, sessions, grants := newTestServiceWithSessions(t)
	grant, err := grants.CreateGrant(t.Context(), NewGrant{Region: "EU", UserID: testRefreshUserID, ClientID: testRefreshClientID, PairwiseSub: "no-offline", Scopes: []string{"openid"}})
	if err != nil {
		t.Fatal(err)
	}
	plaintext, hash, err := newOpaqueToken()
	if err != nil {
		t.Fatal(err)
	}
	if err = sessions.CreateSession(t.Context(), RefreshSession{ID: "no-offline-session", Region: grant.Region, UserID: grant.UserID, ClientID: grant.ClientID, GrantID: grant.ID, Scopes: []string{"openid", "offline_access"}, TokenHash: hash, ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if _, terr := svc.Refresh(t.Context(), refreshReq(encodeRefreshToken(plaintext))); terr == nil || terr.Code != ErrCodeInvalidGrant {
		t.Fatalf("refresh without live offline consent accepted: %v", terr)
	}
}

func TestDecodeRefreshTokenTrimSpace(t *testing.T) {
	plaintext, _, err := newOpaqueToken()
	if err != nil {
		t.Fatalf("newOpaqueToken: %v", err)
	}
	encoded := encodeRefreshToken(plaintext)

	// Trailing newline (common from HTTP form parsers).
	decoded, err := decodeRefreshToken(encoded + "\n")
	if err != nil {
		t.Fatalf("trailing newline: decodeRefreshToken failed: %v", err)
	}
	if string(decoded) != string(plaintext) {
		t.Fatal("trailing newline: decoded bytes do not match plaintext")
	}

	// Leading space.
	decoded2, err := decodeRefreshToken(" " + encoded)
	if err != nil {
		t.Fatalf("leading space: decodeRefreshToken failed: %v", err)
	}
	if string(decoded2) != string(plaintext) {
		t.Fatal("leading space: decoded bytes do not match plaintext")
	}

	// Interior whitespace is NOT trimmed — still rejected.
	_, err = decodeRefreshToken(encoded[:10] + " " + encoded[10:])
	if err == nil {
		t.Fatal("interior whitespace: expected decode error, got nil")
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

// TestRefreshDeregisteredClientRejected verifies that a valid refresh token
// becomes unredeemable when its client is removed from the registry (H20-2).
// Without this gate, a deregistered client's tokens would remain redeemable
// for their full 14-day TTL. Also verifies that the rejection does NOT consume
// the token (no lockout): after re-registration the same token succeeds.
//
//harbor:invariant INV-REFRESH-CLIENT-EXISTS
func TestRefreshDeregisteredClientRejected(t *testing.T) {
	svc, sessionStore, grantStore := newTestServiceWithSessions(t)
	originalClients := svc.clients // save for re-registration step
	oldToken := seedSession(t, sessionStore, grantStore, "ppid-deregistered")

	// Remove the client from the registry (simulate deregistration).
	svc.clients = NewInMemoryClientRegistry() // empty — no clients registered

	_, terr := svc.Refresh(context.Background(), refreshReq(oldToken))
	if terr == nil {
		t.Fatal("expected error for deregistered client; got nil")
	}
	if terr.Code != ErrCodeInvalidClient {
		t.Fatalf("deregistered client: want invalid_client, got %q", terr.Code)
	}
	if terr.Status != 401 {
		t.Fatalf("deregistered client: want HTTP 401, got %d", terr.Status)
	}

	// Verify no lockout: after re-registration the original token is still valid.
	// The H20-2 check runs BEFORE RotateSession, so the rejection must NOT
	// consume or revoke the session.
	svc.clients = originalClients
	tokens, terr2 := svc.Refresh(context.Background(), refreshReq(oldToken))
	if terr2 != nil {
		t.Fatalf("after re-registration, old token should be usable: %v", terr2)
	}
	if tokens == nil || tokens.AccessToken == "" {
		t.Fatal("after re-registration, expected non-empty access token")
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

// TestRefreshTokenGrantIDPropagated verifies that the RefreshSession created
// by issueRefreshToken (called from Token during code exchange) carries the
// grant.ID, and that RotateSession preserves it through rotation — enabling
// per-grant revocation (§11.3). An empty GrantID would break grant-scoped revocation.
//
//harbor:invariant INV-REFRESH-GRANT-ID-PROPAGATED
func TestRefreshTokenGrantIDPropagated(t *testing.T) {
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

	svc := mustNewService(t, ServiceConfig{
		Issuer:       "https://test.harbor.example",
		Clients:      clientReg,
		Codes:        newRedisAuthCodeStore(t),
		Tokens:       NewPlaceholderIssuer(),
		Sessions:     resolver,
		SessionStore: sessionStore,
		Grants:       grantStore,
	})

	if err := svc.ApproveConsent(t.Context(), testRefreshUserID, testRefreshClientID, "openid offline_access"); err != nil {
		t.Fatal(err)
	}
	// Step 1: Authorize to get a code (also creates the grant via PPIDSessionResolver).
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

	// Step 3: Decode the refresh token and look up the session to verify GrantID.
	plaintext, err := decodeRefreshToken(tokens.RefreshToken)
	if err != nil {
		t.Fatalf("decodeRefreshToken: %v", err)
	}
	hash := hashRefreshToken(plaintext)
	session, err := sessionStore.GetSessionByTokenHash(context.Background(), hash)
	if err != nil {
		t.Fatalf("GetSessionByTokenHash: %v", err)
	}

	// GrantID must be non-empty and match the grant created by PPIDSessionResolver.
	if session.GrantID == "" {
		t.Fatal("session.GrantID is empty — issueRefreshToken did not populate GrantID from grant")
	}

	// Verify the GrantID matches the actual grant in the store.
	grant, found, err := grantStore.FindGrant(context.Background(), testRefreshUserID, testRefreshClientID)
	if err != nil {
		t.Fatalf("FindGrant: %v", err)
	}
	if !found {
		t.Fatal("grant should exist after Authorize")
	}
	if session.GrantID != grant.ID {
		t.Fatalf("session.GrantID = %q, want %q (grant.ID)", session.GrantID, grant.ID)
	}

	// Step 4: Rotate the refresh token and verify GrantID is preserved.
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
	if session2.GrantID != grant.ID {
		t.Fatalf("rotated session.GrantID = %q, want %q — RotateSession did not preserve GrantID", session2.GrantID, grant.ID)
	}
}
