package oidc

import (
	"context"
	"strings"
	"testing"
)

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

// testServiceWithConsent creates a Service with consent store for testing.
func testServiceWithConsent(consents ConsentStore) *Service {
	clients := NewInMemoryClientRegistry()
	clients.Put(testClient())
	return NewService(ServiceConfig{
		Issuer:   "https://test.example",
		Clients:  clients,
		Codes:    NewInMemoryAuthCodeStore(),
		Tokens:   &stubTokenIssuer{},
		Sessions: &userIDSessionResolver{subject: "ppid-123", userID: "user-456"},
		Consents: consents,
	})
}

// userIDSessionResolver returns a fixed subject and userID for consent testing.
type userIDSessionResolver struct {
	subject string
	userID  string
}

func (r *userIDSessionResolver) Resolve(_ context.Context, _ Client, _ string) (string, string, bool, error) {
	return r.subject, r.userID, true, nil
}

// stubTokenIssuer is a minimal TokenIssuer for authorize tests.
type stubTokenIssuer struct{}

func (s *stubTokenIssuer) Issue(_ context.Context, _ IssueParams) (IssuedTokens, error) {
	return IssuedTokens{AccessToken: "access-token", IDToken: "id-token", ExpiresIn: 3600}, nil
}

func TestAuthorize_ConsentSkip_CoveringGrant(t *testing.T) {
	// Setup: user already has a covering consent grant
	consents := NewInMemoryConsentStore()
	if _, err := consents.Upsert(context.Background(), "user-456", "demo-client", []string{"openid", "profile"}); err != nil {
		t.Fatalf("Upsert failed: %v", err)
	}

	svc := testServiceWithConsent(consents)
	req := validAuthorizeReq()

	result, err := svc.Authorize(context.Background(), req)
	if err != nil {
		t.Fatalf("Authorize() error = %v, want nil", err)
	}
	if result.Code == "" {
		t.Error("expected authorization code to be issued")
	}
}

func TestAuthorize_ConsentPromptNone_NoGrant_InteractionRequired(t *testing.T) {
	// No existing consent grant, prompt=none should fail
	consents := NewInMemoryConsentStore()
	svc := testServiceWithConsent(consents)

	req := validAuthorizeReq()
	req.Prompt = "none"

	_, err := svc.Authorize(context.Background(), req)
	if err == nil {
		t.Fatal("expected interaction_required error")
	}
	if !strings.Contains(err.Code, "interaction_required") {
		t.Errorf("error code = %q, want interaction_required", err.Code)
	}
}

func TestAuthorize_ConsentPromptNone_CoveringGrant_Success(t *testing.T) {
	// Existing covering grant with prompt=none should succeed
	consents := NewInMemoryConsentStore()
	if _, err := consents.Upsert(context.Background(), "user-456", "demo-client", []string{"openid", "profile"}); err != nil {
		t.Fatalf("Upsert failed: %v", err)
	}

	svc := testServiceWithConsent(consents)
	req := validAuthorizeReq()
	req.Prompt = "none"

	result, err := svc.Authorize(context.Background(), req)
	if err != nil {
		t.Fatalf("Authorize() error = %v, want nil", err)
	}
	if result.Code == "" {
		t.Error("expected authorization code to be issued")
	}
}

func TestAuthorize_ConsentPromptNone_ScopeEscalation_InteractionRequired(t *testing.T) {
	// Existing grant doesn't cover all requested scopes, prompt=none should fail
	consents := NewInMemoryConsentStore()
	if _, err := consents.Upsert(context.Background(), "user-456", "demo-client", []string{"openid"}); err != nil {
		t.Fatalf("Upsert failed: %v", err)
	}

	svc := testServiceWithConsent(consents)
	req := validAuthorizeReq()
	req.Prompt = "none"
	req.Scope = "openid profile" // requesting more than granted

	_, err := svc.Authorize(context.Background(), req)
	if err == nil {
		t.Fatal("expected interaction_required error")
	}
	if !strings.Contains(err.Code, "interaction_required") {
		t.Errorf("error code = %q, want interaction_required", err.Code)
	}
}

// TestAuthorize_FirstConsentRequiresExplicitApproval is a red security test for
// the live consent ceremony. Authentication is not consent: resolving an
// authenticated user must not mint a code or persist a grant until a separate,
// explicit approval decision is consumed.
func TestAuthorize_FirstConsentRequiresExplicitApproval(t *testing.T) {
	consents := NewInMemoryConsentStore()
	svc := testServiceWithConsent(consents)

	result, err := svc.Authorize(context.Background(), validAuthorizeReq())
	if err == nil {
		t.Fatalf("Authorize() result = %+v, want interaction_required pending explicit approval", result)
	}
	if err.Code != "interaction_required" {
		t.Fatalf("Authorize() error code = %q, want interaction_required", err.Code)
	}
	if _, found, getErr := consents.Get(context.Background(), "user-456", "demo-client"); getErr != nil {
		t.Fatalf("Get consent: %v", getErr)
	} else if found {
		t.Fatal("consent grant persisted before explicit user approval")
	}
}

// TestAuthorize_ScopeEscalationRequiresExplicitApproval proves an existing
// grant cannot be silently widened merely because the user authenticated.
func TestAuthorize_ScopeEscalationRequiresExplicitApproval(t *testing.T) {
	consents := NewInMemoryConsentStore()
	if _, err := consents.Upsert(context.Background(), "user-456", "demo-client", []string{"openid"}); err != nil {
		t.Fatalf("seed consent: %v", err)
	}
	svc := testServiceWithConsent(consents)

	result, err := svc.Authorize(context.Background(), validAuthorizeReq())
	if err == nil {
		t.Fatalf("Authorize() result = %+v, want interaction_required for scope escalation", result)
	}
	grant, found, getErr := consents.Get(context.Background(), "user-456", "demo-client")
	if getErr != nil || !found {
		t.Fatalf("Get existing consent: found=%v err=%v", found, getErr)
	}
	if strings.Join(grant.Scopes, " ") != "openid" {
		t.Fatalf("grant scopes = %v, want unchanged [openid] before approval", grant.Scopes)
	}
}

// TestAuthorize_PromptConsentAlwaysRequiresExplicitApproval pins OIDC
// prompt=consent: even a covering grant must show and consume a fresh consent
// decision rather than immediately issuing another code.
func TestAuthorize_PromptConsentAlwaysRequiresExplicitApproval(t *testing.T) {
	consents := NewInMemoryConsentStore()
	if _, err := consents.Upsert(context.Background(), "user-456", "demo-client", []string{"openid", "profile"}); err != nil {
		t.Fatalf("seed consent: %v", err)
	}
	svc := testServiceWithConsent(consents)
	req := validAuthorizeReq()
	req.Prompt = "consent"

	result, err := svc.Authorize(context.Background(), req)
	if err == nil {
		t.Fatalf("Authorize(prompt=consent) result = %+v, want interaction_required pending explicit approval", result)
	}
	if err.Code != "interaction_required" {
		t.Fatalf("Authorize(prompt=consent) code = %q, want interaction_required", err.Code)
	}
}
