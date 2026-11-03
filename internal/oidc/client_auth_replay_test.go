package oidc

import (
	"errors"
	"testing"
	"time"
)

func TestConsumedCodeCannotRevokeWithoutBindingPKCEAndClientAuthentication(t *testing.T) {
	const secret = "confidential-backend-secret"
	client := testClient()
	client.TokenEndpointAuthMethod = ClientAuthSecretBasic
	client.SecretHash = clientSecretHash(secret)
	svc := clientAuthService(t, client)
	req := validTokenReq()
	if _, err := svc.codes.Consume(t.Context(), req.Code); err != nil {
		t.Fatal(err)
	}
	sink := NewRecordingRevocationSink()
	svc.revocations = sink
	for _, attack := range []struct{ name, clientID, method, secret, verifier string }{
		{"missing auth", req.ClientID, ClientAuthNone, "", req.CodeVerifier},
		{"wrong secret", req.ClientID, ClientAuthSecretBasic, "wrong", req.CodeVerifier},
		{"wrong method", req.ClientID, ClientAuthSecretPost, secret, req.CodeVerifier},
		{"wrong client", "other", ClientAuthSecretBasic, secret, req.CodeVerifier},
		{"wrong PKCE", req.ClientID, ClientAuthSecretBasic, secret, "wrong-verifier"},
	} {
		t.Run(attack.name, func(t *testing.T) {
			bad := req
			bad.ClientID, bad.ClientAuthMethod, bad.ClientSecret, bad.CodeVerifier = attack.clientID, attack.method, attack.secret, attack.verifier
			if _, err := svc.Token(t.Context(), bad); err == nil {
				t.Fatal("replay accepted")
			}
			if len(sink.Revoked()) != 0 {
				t.Fatal("untrusted replay revoked a token family")
			}
		})
	}
	req.ClientAuthMethod, req.ClientSecret = ClientAuthSecretBasic, secret
	if _, err := svc.Token(t.Context(), req); err == nil || err.Code != ErrCodeInvalidGrant {
		t.Fatal("authenticated replay accepted")
	}
	if len(sink.Revoked()) != 1 {
		t.Fatal("authenticated replay did not revoke the family")
	}
}

func TestConfidentialRefreshAuthenticationProtectsRotationAndReplayRevocation(t *testing.T) {
	const secret = "confidential-refresh-secret"
	svc, sessions, grants := newTestServiceWithSessions(t)
	registry := NewInMemoryClientRegistry()
	registry.Put(Client{ID: testRefreshClientID, TokenEndpointAuthMethod: ClientAuthSecretBasic, SecretHash: clientSecretHash(secret)})
	svc.clients = registry
	oldToken := seedSession(t, sessions, grants, "confidential-refresh")
	req := refreshReq(oldToken)
	for _, credentials := range []struct{ method, secret string }{
		{ClientAuthNone, ""}, {ClientAuthSecretBasic, "wrong"}, {ClientAuthSecretPost, secret},
	} {
		bad := req
		bad.ClientAuthMethod, bad.ClientSecret = credentials.method, credentials.secret
		if _, err := svc.Refresh(t.Context(), bad); err == nil || err.Code != ErrCodeInvalidClient {
			t.Fatal("confidential refresh accepted invalid authentication")
		}
	}
	req.ClientAuthMethod, req.ClientSecret = ClientAuthSecretBasic, secret
	rotated, err := svc.Refresh(t.Context(), req)
	if err != nil {
		t.Fatal(err)
	}
	raw, decodeErr := decodeRefreshToken(rotated.RefreshToken)
	if decodeErr != nil {
		t.Fatal(decodeErr)
	}
	hash := hashRefreshToken(raw)
	bad := req
	bad.ClientSecret = "wrong"
	if _, err := svc.Refresh(t.Context(), bad); err == nil || err.Code != ErrCodeInvalidClient {
		t.Fatal("spent refresh accepted invalid authentication")
	}
	bad.ClientID = "other-client"
	if _, err := svc.Refresh(t.Context(), bad); err == nil {
		t.Fatal("cross-client replay accepted")
	}
	if _, err := sessions.GetSessionByTokenHash(t.Context(), hash); err != nil {
		t.Fatal("unauthenticated replay revoked successor")
	}
	if _, err := svc.Refresh(t.Context(), req); err == nil || err.Code != ErrCodeInvalidGrant {
		t.Fatal("authenticated spent refresh accepted")
	}
	if _, err := sessions.GetSessionByTokenHash(t.Context(), hash); !errors.Is(err, ErrRefreshTokenRevoked) {
		t.Fatal("authenticated replay did not revoke successor")
	}
}

func TestExpiredConsumedCodeStillRevokesOnlyForAuthenticatedBoundReplay(t *testing.T) {
	const secret = "confidential-expired-replay-secret"
	client := testClient()
	client.TokenEndpointAuthMethod, client.SecretHash = ClientAuthSecretBasic, clientSecretHash(secret)
	svc := clientAuthService(t, client)
	// Use actual Redis expiry, rather than advancing only the service clock.
	store := newRedisAuthCodeStore(t)
	store.codeTTL = 2 * time.Second
	code := validAuthCode(time.Now())
	code.ExpiresAt = time.Now().Add(store.codeTTL)
	svc.now = time.Now
	if err := store.Save(t.Context(), code); err != nil {
		t.Fatal(err)
	}
	svc.codes = store
	req := validTokenReq()
	if _, err := svc.codes.Consume(t.Context(), req.Code); err != nil {
		t.Fatal(err)
	}
	time.Sleep(store.codeTTL + 100*time.Millisecond)

	sink := NewRecordingRevocationSink()
	svc.revocations = sink
	req.ClientAuthMethod, req.ClientSecret = ClientAuthSecretBasic, secret
	for _, attack := range []string{"wrong secret", "missing secret", "wrong PKCE", "wrong client", "wrong redirect"} {
		bad := req
		switch attack {
		case "wrong secret":
			bad.ClientSecret = "wrong"
		case "missing secret":
			bad.ClientSecret = ""
		case "wrong PKCE":
			bad.CodeVerifier = "wrong-verifier"
		case "wrong client":
			bad.ClientID = "other-client"
		case "wrong redirect":
			bad.RedirectURI = "https://other.example/cb"
		}
		if _, err := svc.Token(t.Context(), bad); err == nil {
			t.Fatalf("%s accepted", attack)
		}
		if len(sink.Revoked()) != 0 {
			t.Fatalf("%s revoked the family", attack)
		}
	}
	if _, err := svc.Token(t.Context(), req); err == nil || err.Code != ErrCodeInvalidGrant {
		t.Fatal("expired replay accepted")
	}
	if len(sink.Revoked()) != 1 {
		t.Fatal("correctly authenticated expired replay failed to revoke the family")
	}
}

func TestExpiredUnspentCodeCannotIssueOrRevoke(t *testing.T) {
	const secret = "confidential-expired-fresh-secret"
	client := testClient()
	client.TokenEndpointAuthMethod, client.SecretHash = ClientAuthSecretBasic, clientSecretHash(secret)
	svc := clientAuthService(t, client)
	svc.now = func() time.Time { return time.Unix(1_700_000_000, 0).Add(2 * time.Minute) }
	sink := NewRecordingRevocationSink()
	svc.revocations = sink
	req := validTokenReq()
	req.ClientAuthMethod, req.ClientSecret = ClientAuthSecretBasic, secret
	if _, err := svc.Token(t.Context(), req); err == nil || err.Code != ErrCodeInvalidGrant {
		t.Fatal("expired fresh code accepted")
	}
	_, found, consumed, err := svc.codes.Peek(t.Context(), req.Code)
	if err != nil || !found || consumed || len(sink.Revoked()) != 0 {
		t.Fatal("expired unspent code mutated token state")
	}
}
