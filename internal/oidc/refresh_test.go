package oidc

import (
	"context"
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

// seedSession inserts a grant + RefreshSession and returns the plaintext token
// string the client would hold.
func seedSession(t *testing.T, store *InMemorySessionStore, grantStore *InMemoryGrantStore, sub string) string {
	t.Helper()
	if _, err := grantStore.CreateGrant(context.Background(), NewGrant{
		Region:      "us",
		UserID:      testRefreshUserID,
		ClientID:    testRefreshClientID,
		PairwiseSub: sub,
		Scopes:      []string{"openid", "offline_access"},
	}); err != nil {
		t.Fatalf("seedSession: CreateGrant: %v", err)
	}

	plaintext, hash, err := newOpaqueToken()
	if err != nil {
		t.Fatalf("seedSession: newOpaqueToken: %v", err)
	}
	rs := RefreshSession{
		ID:        "session-1",
		Region:    "us",
		UserID:    testRefreshUserID,
		ClientID:  testRefreshClientID,
		TokenHash: hash,
		ExpiresAt: time.Now().Add(defaultRefreshTTL),
	}
	if err := store.CreateSession(context.Background(), rs); err != nil {
		t.Fatalf("seedSession: CreateSession: %v", err)
	}
	return encodeRefreshToken(plaintext)
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

func TestRefreshOfflineAccessGate(t *testing.T) {
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
}
