package oidc

import (
	"errors"
	"testing"
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
