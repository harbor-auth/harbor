package oidc

import (
	"testing"
	"time"
)

func validTokenReq() TokenRequest {
	return TokenRequest{
		GrantType:    "authorization_code",
		Code:         "the-code",
		RedirectURI:  testRedirectURI,
		ClientID:     "demo-client",
		CodeVerifier: rfc7636Verifier,
	}
}

func validAuthCode(now time.Time) AuthCode {
	return AuthCode{
		Code:                "the-code",
		ClientID:            "demo-client",
		RedirectURI:         testRedirectURI,
		Scope:               "openid profile",
		Subject:             "demo-subject-ppid",
		CodeChallenge:       rfc7636Challenge,
		CodeChallengeMethod: "S256",
		ExpiresAt:           now.Add(time.Minute),
	}
}

func TestValidateTokenParams(t *testing.T) {
	if terr := ValidateTokenParams(validTokenReq()); terr != nil {
		t.Fatalf("valid params = %v, want nil", terr)
	}

	bad := validTokenReq()
	bad.GrantType = "client_credentials"
	if terr := ValidateTokenParams(bad); terr == nil || terr.Code != ErrCodeUnsupportedGrantType {
		t.Fatalf("wrong grant_type = %v, want unsupported_grant_type", terr)
	}

	for _, field := range []string{"code", "redirect_uri", "client_id", "code_verifier"} {
		req := validTokenReq()
		switch field {
		case "code":
			req.Code = ""
		case "redirect_uri":
			req.RedirectURI = ""
		case "client_id":
			req.ClientID = ""
		case "code_verifier":
			req.CodeVerifier = ""
		}
		if terr := ValidateTokenParams(req); terr == nil || terr.Code != ErrCodeInvalidRequest {
			t.Fatalf("missing %s = %v, want invalid_request", field, terr)
		}
	}
}

func TestValidateTokenExchange(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)

	if terr := ValidateTokenExchange(validTokenReq(), validAuthCode(now), now); terr != nil {
		t.Fatalf("valid exchange = %v, want nil", terr)
	}

	cases := []struct {
		name   string
		mutate func(*TokenRequest, *AuthCode)
	}{
		{"client mismatch", func(r *TokenRequest, _ *AuthCode) { r.ClientID = "other-client" }},
		{"redirect mismatch", func(r *TokenRequest, _ *AuthCode) { r.RedirectURI = "http://evil.example/cb" }},
		{"expired code", func(_ *TokenRequest, c *AuthCode) { c.ExpiresAt = now.Add(-time.Second) }},
		{"PKCE mismatch", func(r *TokenRequest, _ *AuthCode) {
			// A well-formed (43-char) but wrong verifier.
			r.CodeVerifier = "WRONGftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"[:43]
		}},
		{"PKCE malformed length", func(r *TokenRequest, _ *AuthCode) { r.CodeVerifier = "too-short" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := validTokenReq()
			code := validAuthCode(now)
			tc.mutate(&req, &code)
			terr := ValidateTokenExchange(req, code, now)
			// Every exchange failure collapses to invalid_grant (no leak of which
			// check failed).
			if terr == nil || terr.Code != ErrCodeInvalidGrant {
				t.Fatalf("%s = %v, want invalid_grant", tc.name, terr)
			}
			if terr.Status != 400 {
				t.Fatalf("%s status = %d, want 400", tc.name, terr.Status)
			}
		})
	}
}

// The reuse path: a code works exactly once; a second exchange is invalid_grant
// AND fires the revocation signal (docs/DESIGN.md §11.7, §3.5).
func TestService_Token_ReuseRevokesCodeFamily(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	codes := NewInMemoryAuthCodeStore()
	_ = codes.Save(t.Context(), validAuthCode(now))
	revocations := NewRecordingRevocationSink()

	svc := NewService(ServiceConfig{
		Issuer:      "https://eu.harbor.id",
		Clients:     NewInMemoryClientRegistry(),
		Codes:       codes,
		Tokens:      NewPlaceholderIssuer(),
		Sessions:    NewStubSessionResolver("demo-subject-ppid"),
		Revocations: revocations,
		Now:         func() time.Time { return now },
	})

	// First exchange succeeds.
	tokens, terr := svc.Token(t.Context(), validTokenReq())
	if terr != nil {
		t.Fatalf("first exchange = %v, want success", terr)
	}
	if tokens.AccessToken == "" || tokens.IDToken == "" {
		t.Fatalf("first exchange returned empty tokens: %+v", tokens)
	}

	// Second exchange (reuse) → invalid_grant + revocation recorded.
	_, terr = svc.Token(t.Context(), validTokenReq())
	if terr == nil || terr.Code != ErrCodeInvalidGrant {
		t.Fatalf("reuse = %v, want invalid_grant", terr)
	}
	if got := revocations.Revoked(); len(got) != 1 || got[0].Code != "the-code" {
		t.Fatalf("revoked = %+v, want the reused code family", got)
	}
}

// CRITICAL: a failed exchange (wrong client/redirect/verifier) must NOT burn the
// one-time code — the legitimate owner can still redeem it afterwards
// (docs/DESIGN.md §11.7 auth-code-DoS defense).
func TestService_Token_FailedExchangeDoesNotBurnCode(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	clients := NewInMemoryClientRegistry()
	clients.Put(Client{ID: "demo-client", RedirectURIs: []string{testRedirectURI}, ScopesAllowed: []string{"openid"}})

	// A fresh sink + code store per subcase keeps them fully isolated.
	newSvc := func() (*Service, *RecordingRevocationSink) {
		codes := NewInMemoryAuthCodeStore()
		_ = codes.Save(t.Context(), validAuthCode(now))
		revocations := NewRecordingRevocationSink()
		return NewService(ServiceConfig{
			Issuer:      "https://eu.harbor.id",
			Clients:     clients,
			Codes:       codes,
			Tokens:      NewPlaceholderIssuer(),
			Sessions:    NewStubSessionResolver("demo-subject-ppid"),
			Revocations: revocations,
			Now:         func() time.Time { return now },
		}), revocations
	}

	badCases := map[string]func(*TokenRequest){
		"wrong client":   func(r *TokenRequest) { r.ClientID = "other-client" },
		"wrong redirect": func(r *TokenRequest) { r.RedirectURI = "http://evil.example/cb" },
		"wrong verifier": func(r *TokenRequest) { r.CodeVerifier = "WRONGftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"[:43] },
	}
	for name, mutate := range badCases {
		t.Run(name, func(t *testing.T) {
			svc, revocations := newSvc()

			// The malicious/malformed exchange fails with invalid_grant...
			bad := validTokenReq()
			mutate(&bad)
			if _, terr := svc.Token(t.Context(), bad); terr == nil || terr.Code != ErrCodeInvalidGrant {
				t.Fatalf("bad exchange = %v, want invalid_grant", terr)
			}
			// ...and does NOT fire the theft signal (the code was never consumed).
			if got := revocations.Revoked(); len(got) != 0 {
				t.Fatalf("failed exchange revoked a code family: %+v", got)
			}

			// The legitimate owner can still redeem the untouched code.
			tokens, terr := svc.Token(t.Context(), validTokenReq())
			if terr != nil {
				t.Fatalf("legit exchange after failed attempt = %v, want success", terr)
			}
			if tokens.AccessToken == "" {
				t.Fatal("legit exchange returned empty tokens")
			}
		})
	}
}

func TestService_Token_UnknownCode(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	svc := NewService(ServiceConfig{
		Issuer:   "https://eu.harbor.id",
		Clients:  NewInMemoryClientRegistry(),
		Codes:    NewInMemoryAuthCodeStore(),
		Tokens:   NewPlaceholderIssuer(),
		Sessions: NewStubSessionResolver("demo-subject-ppid"),
		Now:      func() time.Time { return now },
	})
	_, terr := svc.Token(t.Context(), validTokenReq())
	if terr == nil || terr.Code != ErrCodeInvalidGrant {
		t.Fatalf("unknown code = %v, want invalid_grant", terr)
	}
}
