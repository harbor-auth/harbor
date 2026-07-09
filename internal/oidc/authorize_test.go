package oidc

import "testing"

const testRedirectURI = "http://localhost:3000/callback"

func testClient() Client {
	return Client{
		ID:            "demo-client",
		RedirectURIs:  []string{testRedirectURI},
		ScopesAllowed: []string{"openid", "profile", "email"},
	}
}

// validAuthorizeReq returns a request that passes every check, so each test can
// mutate exactly one field to isolate a single failure.
func validAuthorizeReq() AuthorizeRequest {
	return AuthorizeRequest{
		ResponseType:        "code",
		ClientID:            "demo-client",
		RedirectURI:         testRedirectURI,
		Scope:               "openid profile",
		State:               "xyz789",
		Nonce:               "n-9f2c",
		CodeChallenge:       rfc7636Challenge,
		CodeChallengeMethod: "S256",
	}
}

func TestValidateAuthorize_Valid(t *testing.T) {
	client := testClient()
	v, err := ValidateAuthorize(validAuthorizeReq(), &client)
	if err != nil {
		t.Fatalf("ValidateAuthorize(valid) error = %v, want nil", err)
	}
	if v.RedirectURI != testRedirectURI || v.State != "xyz789" || v.CodeChallenge != rfc7636Challenge {
		t.Fatalf("validated fields not carried through: %+v", v)
	}
}

// Open-redirect defense: unknown client and redirect mismatch must NOT redirect.
func TestValidateAuthorize_UnknownClient_ErrorPage(t *testing.T) {
	_, err := ValidateAuthorize(validAuthorizeReq(), nil)
	if err == nil || err.Channel != ChannelErrorPage {
		t.Fatalf("unknown client: err=%v, want ChannelErrorPage", err)
	}
	if err.Code != ErrCodeUnauthorizedClient {
		t.Fatalf("unknown client code = %q, want %q", err.Code, ErrCodeUnauthorizedClient)
	}
}

func TestValidateAuthorize_RedirectMismatch_ErrorPage(t *testing.T) {
	client := testClient()
	cases := map[string]string{
		"trailing slash":   testRedirectURI + "/",
		"different path":   "http://localhost:3000/callback2",
		"different scheme": "https://localhost:3000/callback",
		"attacker host":    "http://evil.example/callback",
		"absent":           "",
	}
	for name, uri := range cases {
		t.Run(name, func(t *testing.T) {
			req := validAuthorizeReq()
			req.RedirectURI = uri
			_, err := ValidateAuthorize(req, &client)
			if err == nil || err.Channel != ChannelErrorPage {
				t.Fatalf("redirect %q: err=%v, want ChannelErrorPage (no redirect)", uri, err)
			}
		})
	}
}

func TestValidateAuthorize_RedirectChannelErrors(t *testing.T) {
	client := testClient()
	cases := []struct {
		name     string
		mutate   func(*AuthorizeRequest)
		wantCode string
	}{
		{"wrong response_type", func(r *AuthorizeRequest) { r.ResponseType = "token" }, ErrCodeUnsupportedResponseType},
		{"empty response_type", func(r *AuthorizeRequest) { r.ResponseType = "" }, ErrCodeUnsupportedResponseType},
		{"missing openid scope", func(r *AuthorizeRequest) { r.Scope = "profile" }, ErrCodeInvalidScope},
		{"disallowed scope", func(r *AuthorizeRequest) { r.Scope = "openid admin" }, ErrCodeInvalidScope},
		{"plain PKCE method", func(r *AuthorizeRequest) { r.CodeChallengeMethod = "plain" }, ErrCodeInvalidRequest},
		{"missing PKCE method", func(r *AuthorizeRequest) { r.CodeChallengeMethod = "" }, ErrCodeInvalidRequest},
		{"missing code_challenge", func(r *AuthorizeRequest) { r.CodeChallenge = "" }, ErrCodeInvalidRequest},
		{"missing state", func(r *AuthorizeRequest) { r.State = "" }, ErrCodeInvalidRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := validAuthorizeReq()
			tc.mutate(&req)
			_, err := ValidateAuthorize(req, &client)
			if err == nil {
				t.Fatalf("%s: expected an error", tc.name)
			}
			if err.Channel != ChannelRedirect {
				t.Fatalf("%s: channel = %v, want ChannelRedirect", tc.name, err.Channel)
			}
			if err.Code != tc.wantCode {
				t.Fatalf("%s: code = %q, want %q", tc.name, err.Code, tc.wantCode)
			}
		})
	}
}
