package oidc

import (
	"context"
	"testing"
	"time"
)

// seedSession inserts a grant + RefreshSession into the given stores and returns
// the plaintext token string the client would hold. The session ID
// ("session-"+sub) is a simple string, not a UUID — safe for InMemorySessionStore
// but NOT for DBSessionStore, which requires a valid UUID in the id column.
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
		ID:        "session-" + sub,
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

// refreshReq builds a minimal refresh_token TokenRequest for testRefreshClientID.
func refreshReq(token string) TokenRequest {
	return TokenRequest{
		GrantType:    grantTypeRefreshToken,
		RefreshToken: token,
		ClientID:     testRefreshClientID,
	}
}
