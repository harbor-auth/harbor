package oidc

import (
	"context"
	"crypto/sha256"
	"reflect"
	"testing"
	"time"
)

func TestMapAuthMethodToACRAMR(t *testing.T) {
	tests := []struct {
		method  AuthMethod
		wantACR string
		wantAMR []string
	}{
		{
			method:  AuthMethodWebAuthn,
			wantACR: "urn:harbor:ac:webauthn",
			wantAMR: []string{"hwk", "user"},
		},
		{
			method:  AuthMethodTOTP,
			wantACR: "urn:harbor:ac:webauthn+totp",
			wantAMR: []string{"hwk", "otp", "user"},
		},
		{
			method:  AuthMethodRecoveryCode,
			wantACR: "urn:harbor:ac:recovery",
			wantAMR: []string{"rc"},
		},
		// Fail-closed: unknown method must produce no claims rather than a lie.
		{
			method:  AuthMethod("unknown"),
			wantACR: "",
			wantAMR: nil,
		},
		// Fail-closed: empty method must produce no claims rather than a lie.
		{
			method:  AuthMethod(""),
			wantACR: "",
			wantAMR: nil,
		},
	}

	for _, tt := range tests {
		t.Run(string(tt.method), func(t *testing.T) {
			gotACR, gotAMR := MapAuthMethodToACRAMR(tt.method)
			if gotACR != tt.wantACR {
				t.Errorf("MapAuthMethodToACRAMR(%q) ACR = %q, want %q", tt.method, gotACR, tt.wantACR)
			}
			if !reflect.DeepEqual(gotAMR, tt.wantAMR) {
				t.Errorf("MapAuthMethodToACRAMR(%q) AMR = %v, want %v", tt.method, gotAMR, tt.wantAMR)
			}
		})
	}
}

func clientSecretHash(secret string) []byte {
	sum := sha256.Sum256([]byte(secret))
	return sum[:]
}

func clientAuthService(t *testing.T, client Client) *Service {
	t.Helper()
	clients := NewInMemoryClientRegistry()
	clients.Put(client)
	now := time.Unix(1_700_000_000, 0)
	codes := NewInMemoryAuthCodeStore()
	if err := codes.Save(t.Context(), validAuthCode(now)); err != nil {
		t.Fatalf("Save auth code: %v", err)
	}
	return mustNewService(ServiceConfig{
		Issuer:   "https://eu.harbor.id",
		Clients:  clients,
		Codes:    codes,
		Tokens:   NewPlaceholderIssuer(),
		Sessions: NewStubSessionResolver("demo-subject-ppid"),
		Now:      func() time.Time { return now },
	})
}

func TestClientAuthenticationMethods(t *testing.T) {
	const secret = "high-entropy-client-secret"
	tests := []struct {
		name       string
		method     string
		secretHash []byte
		presented  string
		wantCode   string
	}{
		{name: "public client without secret", method: "none"},
		{name: "confidential basic", method: "client_secret_basic", secretHash: clientSecretHash(secret), presented: secret},
		{name: "confidential post", method: "client_secret_post", secretHash: clientSecretHash(secret), presented: secret},
		{name: "missing confidential secret", method: "client_secret_basic", secretHash: clientSecretHash(secret), wantCode: ErrCodeInvalidClient},
		{name: "wrong confidential secret", method: "client_secret_basic", secretHash: clientSecretHash(secret), presented: "wrong-secret", wantCode: ErrCodeInvalidClient},
		{name: "unsupported method", method: "private_key_jwt", secretHash: clientSecretHash(secret), presented: secret, wantCode: ErrCodeInvalidClient},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := testClient()
			client.TokenEndpointAuthMethod = tt.method
			client.SecretHash = tt.secretHash
			svc := clientAuthService(t, client)
			req := validTokenReq()
			req.ClientSecret = tt.presented
			req.ClientAuthMethod = tt.method

			_, terr := svc.Token(context.Background(), req)
			if tt.wantCode == "" {
				if terr != nil {
					t.Fatalf("Token = %v, want success", terr)
				}
				return
			}
			if terr == nil || terr.Code != tt.wantCode || terr.Status != 401 {
				t.Fatalf("Token error = %+v, want 401 %s", terr, tt.wantCode)
			}
		})
	}
}

func TestClientSecretMismatchIsUniformAndDoesNotConsumeCode(t *testing.T) {
	const secret = "high-entropy-client-secret"
	client := testClient()
	client.TokenEndpointAuthMethod = "client_secret_basic"
	client.SecretHash = clientSecretHash(secret)
	svc := clientAuthService(t, client)

	for _, wrong := range []string{
		"Xigh-entropy-client-secret",
		"high-entropy-client-secreX",
	} {
		req := validTokenReq()
		req.ClientSecret = wrong
		req.ClientAuthMethod = "client_secret_basic"
		_, terr := svc.Token(t.Context(), req)
		if terr == nil || terr.Code != ErrCodeInvalidClient || terr.Status != 401 {
			t.Fatalf("near mismatch error = %+v, want uniform 401 invalid_client", terr)
		}
	}

	retry := validTokenReq()
	retry.ClientSecret = secret
	retry.ClientAuthMethod = "client_secret_basic"
	if _, terr := svc.Token(t.Context(), retry); terr != nil {
		t.Fatalf("retry with correct secret = %v, want success (bad auth must not consume code)", terr)
	}
}
