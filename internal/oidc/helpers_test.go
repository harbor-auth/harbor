package oidc

import (
	"context"
	"testing"
	"time"
)

// mustNewService supplies isolated test collaborators for fields a test does
// not exercise and fails the test if construction is rejected.
func mustNewService(cfg ServiceConfig) *Service {
	if cfg.Clients == nil {
		cfg.Clients = NewInMemoryClientRegistry()
	}
	if cfg.Codes == nil {
		cfg.Codes = NewInMemoryAuthCodeStore()
	}
	if cfg.Tokens == nil {
		cfg.Tokens = NewPlaceholderIssuer()
	}
	if cfg.Sessions == nil {
		cfg.Sessions = NewStubSessionResolver("test-subject")
	}
	if cfg.SessionStore == nil {
		cfg.SessionStore = NewInMemorySessionStore()
	}
	if cfg.Grants == nil {
		cfg.Grants = NewInMemoryGrantStore()
	}
	if cfg.Consents == nil {
		cfg.Consents = NewInMemoryConsentStore()
	}
	if cfg.Revocations == nil {
		cfg.Revocations = NewRecordingRevocationSink()
	}
	if cfg.Outbox == nil {
		cfg.Outbox = &recordingOutbox{}
	}
	svc, err := NewService(cfg)
	if err != nil {
		panic("NewService: " + err.Error())
	}
	return svc
}

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

// errTokenIssuer returns a fixed error from Issue. Defined here (shared test
// helpers) because it is used by both service_test.go (TestService_Token_IssueError)
// and chaos_test.go (TestChaos_Refresh_TokenSigningFails_PreRotation). All three
// files are in package oidc, so the type is visible across the test build.
type errTokenIssuer struct {
	issueErr error
}

func (i errTokenIssuer) Issue(_ context.Context, _ IssueParams) (IssuedTokens, error) {
	return IssuedTokens{}, i.issueErr
}
