package oidc

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// newTestAuthorizeService returns a Service configured for /authorize tests with
// an in-memory client registry seeded with a demo client.
func newTestAuthorizeService(t *testing.T) (*Service, *InMemoryClientRegistry) {
	t.Helper()
	clients := NewInMemoryClientRegistry()
	clients.Put(testClient())

	svc := NewService(ServiceConfig{
		Issuer:   "https://eu.harbor.id",
		Clients:  clients,
		Codes:    NewInMemoryAuthCodeStore(),
		Tokens:   NewPlaceholderIssuer(),
		Sessions: NewStubSessionResolver("demo-subject-ppid"),
		NewCode:  func() (string, error) { return "test-code-12345", nil },
		Now:      func() time.Time { return time.Unix(1_700_000_000, 0) },
	})
	return svc, clients
}

func TestService_Authorize_Success(t *testing.T) {
	svc, _ := newTestAuthorizeService(t)

	result, aerr := svc.Authorize(context.Background(), validAuthorizeReq())
	if aerr != nil {
		t.Fatalf("Authorize = %v, want success", aerr)
	}
	if result.Code != "test-code-12345" {
		t.Fatalf("Code = %q, want %q", result.Code, "test-code-12345")
	}
	if result.RedirectURI != testRedirectURI {
		t.Fatalf("RedirectURI = %q, want %q", result.RedirectURI, testRedirectURI)
	}
	if result.State != "xyz789" {
		t.Fatalf("State = %q, want %q", result.State, "xyz789")
	}
}

func TestService_Authorize_UnknownClient(t *testing.T) {
	svc, _ := newTestAuthorizeService(t)

	req := validAuthorizeReq()
	req.ClientID = "unknown-client"
	_, aerr := svc.Authorize(context.Background(), req)
	if aerr == nil {
		t.Fatal("expected error for unknown client")
	}
	if aerr.Code != ErrCodeUnauthorizedClient {
		t.Fatalf("Code = %q, want %q", aerr.Code, ErrCodeUnauthorizedClient)
	}
	if aerr.Channel != ChannelErrorPage {
		t.Fatalf("Channel = %v, want ChannelErrorPage", aerr.Channel)
	}
}

func TestService_Authorize_InvalidRedirectURI(t *testing.T) {
	svc, _ := newTestAuthorizeService(t)

	req := validAuthorizeReq()
	req.RedirectURI = "http://evil.example/callback"
	_, aerr := svc.Authorize(context.Background(), req)
	if aerr == nil {
		t.Fatal("expected error for invalid redirect_uri")
	}
	if aerr.Code != ErrCodeInvalidRequest {
		t.Fatalf("Code = %q, want %q", aerr.Code, ErrCodeInvalidRequest)
	}
	if aerr.Channel != ChannelErrorPage {
		t.Fatalf("Channel = %v, want ChannelErrorPage", aerr.Channel)
	}
}

func TestService_Authorize_ValidationErrors(t *testing.T) {
	svc, _ := newTestAuthorizeService(t)

	cases := []struct {
		name     string
		mutate   func(*AuthorizeRequest)
		wantCode string
	}{
		{"missing state", func(r *AuthorizeRequest) { r.State = "" }, ErrCodeInvalidRequest},
		{"missing code_challenge", func(r *AuthorizeRequest) { r.CodeChallenge = "" }, ErrCodeInvalidRequest},
		{"invalid response_type", func(r *AuthorizeRequest) { r.ResponseType = "token" }, ErrCodeUnsupportedResponseType},
		{"missing openid scope", func(r *AuthorizeRequest) { r.Scope = "profile" }, ErrCodeInvalidScope},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := validAuthorizeReq()
			tc.mutate(&req)
			_, aerr := svc.Authorize(context.Background(), req)
			if aerr == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
			if aerr.Code != tc.wantCode {
				t.Fatalf("Code = %q, want %q", aerr.Code, tc.wantCode)
			}
			if aerr.Channel != ChannelRedirect {
				t.Fatalf("Channel = %v, want ChannelRedirect", aerr.Channel)
			}
		})
	}
}

// errSessionResolver returns a fixed error from Resolve.
type errSessionResolver struct{ err error }

func (r errSessionResolver) Resolve(_ context.Context, _ Client, _ string) (string, string, bool, error) {
	return "", "", false, r.err
}

func TestService_Authorize_SessionResolutionError(t *testing.T) {
	clients := NewInMemoryClientRegistry()
	clients.Put(testClient())

	svc := NewService(ServiceConfig{
		Issuer:   "https://eu.harbor.id",
		Clients:  clients,
		Codes:    NewInMemoryAuthCodeStore(),
		Tokens:   NewPlaceholderIssuer(),
		Sessions: errSessionResolver{err: errors.New("session resolution failed")},
		Now:      func() time.Time { return time.Unix(1_700_000_000, 0) },
	})

	_, aerr := svc.Authorize(context.Background(), validAuthorizeReq())
	if aerr == nil {
		t.Fatal("expected error for session resolution failure")
	}
	if aerr.Code != ErrCodeServerError {
		t.Fatalf("Code = %q, want %q", aerr.Code, ErrCodeServerError)
	}
	if aerr.Channel != ChannelRedirect {
		t.Fatalf("Channel = %v, want ChannelRedirect", aerr.Channel)
	}
}

// denyingSessionResolver always denies consent.
type denyingSessionResolver struct{}

func (r denyingSessionResolver) Resolve(_ context.Context, _ Client, _ string) (string, string, bool, error) {
	return "", "", false, nil
}

func TestService_Authorize_ConsentDenied(t *testing.T) {
	clients := NewInMemoryClientRegistry()
	clients.Put(testClient())

	svc := NewService(ServiceConfig{
		Issuer:   "https://eu.harbor.id",
		Clients:  clients,
		Codes:    NewInMemoryAuthCodeStore(),
		Tokens:   NewPlaceholderIssuer(),
		Sessions: denyingSessionResolver{},
		Now:      func() time.Time { return time.Unix(1_700_000_000, 0) },
	})

	_, aerr := svc.Authorize(context.Background(), validAuthorizeReq())
	if aerr == nil {
		t.Fatal("expected error for consent denial")
	}
	if aerr.Code != ErrCodeAccessDenied {
		t.Fatalf("Code = %q, want %q", aerr.Code, ErrCodeAccessDenied)
	}
	if aerr.Channel != ChannelRedirect {
		t.Fatalf("Channel = %v, want ChannelRedirect", aerr.Channel)
	}
}

func TestService_Authorize_CodeGenerationError(t *testing.T) {
	clients := NewInMemoryClientRegistry()
	clients.Put(testClient())

	svc := NewService(ServiceConfig{
		Issuer:   "https://eu.harbor.id",
		Clients:  clients,
		Codes:    NewInMemoryAuthCodeStore(),
		Tokens:   NewPlaceholderIssuer(),
		Sessions: NewStubSessionResolver("demo-subject-ppid"),
		NewCode:  func() (string, error) { return "", errors.New("code generation failed") },
		Now:      func() time.Time { return time.Unix(1_700_000_000, 0) },
	})

	_, aerr := svc.Authorize(context.Background(), validAuthorizeReq())
	if aerr == nil {
		t.Fatal("expected error for code generation failure")
	}
	if aerr.Code != ErrCodeServerError {
		t.Fatalf("Code = %q, want %q", aerr.Code, ErrCodeServerError)
	}
	if aerr.Channel != ChannelRedirect {
		t.Fatalf("Channel = %v, want ChannelRedirect", aerr.Channel)
	}
}

// errAuthCodeStore returns a fixed error from Save.
type errAuthCodeStore struct {
	saveErr error
}

func (s errAuthCodeStore) Save(_ context.Context, _ AuthCode) error {
	return s.saveErr
}

func (s errAuthCodeStore) Peek(_ context.Context, _ string) (AuthCode, bool, bool, error) {
	return AuthCode{}, false, false, nil
}

func (s errAuthCodeStore) Consume(_ context.Context, _ string) (ConsumeResult, error) {
	return ConsumeResult{Status: ConsumeNotFound}, nil
}

func TestService_Authorize_CodeStorageError(t *testing.T) {
	clients := NewInMemoryClientRegistry()
	clients.Put(testClient())

	svc := NewService(ServiceConfig{
		Issuer:   "https://eu.harbor.id",
		Clients:  clients,
		Codes:    errAuthCodeStore{saveErr: errors.New("storage failed")},
		Tokens:   NewPlaceholderIssuer(),
		Sessions: NewStubSessionResolver("demo-subject-ppid"),
		NewCode:  func() (string, error) { return "test-code-12345", nil },
		Now:      func() time.Time { return time.Unix(1_700_000_000, 0) },
	})

	_, aerr := svc.Authorize(context.Background(), validAuthorizeReq())
	if aerr == nil {
		t.Fatal("expected error for code storage failure")
	}
	if aerr.Code != ErrCodeServerError {
		t.Fatalf("Code = %q, want %q", aerr.Code, ErrCodeServerError)
	}
	if aerr.Channel != ChannelRedirect {
		t.Fatalf("Channel = %v, want ChannelRedirect", aerr.Channel)
	}
}

// --- Service.Token additional tests ---

// peekErrAuthCodeStore returns a fixed error from Peek.
type peekErrAuthCodeStore struct {
	peekErr error
}

func (s peekErrAuthCodeStore) Save(_ context.Context, _ AuthCode) error {
	return nil
}

func (s peekErrAuthCodeStore) Peek(_ context.Context, _ string) (AuthCode, bool, bool, error) {
	return AuthCode{}, false, false, s.peekErr
}

func (s peekErrAuthCodeStore) Consume(_ context.Context, _ string) (ConsumeResult, error) {
	return ConsumeResult{Status: ConsumeNotFound}, nil
}

func TestService_Token_PeekError(t *testing.T) {
	svc := NewService(ServiceConfig{
		Issuer:   "https://eu.harbor.id",
		Clients:  NewInMemoryClientRegistry(),
		Codes:    peekErrAuthCodeStore{peekErr: errors.New("database connection failed")},
		Tokens:   NewPlaceholderIssuer(),
		Sessions: NewStubSessionResolver("demo-subject-ppid"),
		Now:      func() time.Time { return time.Unix(1_700_000_000, 0) },
	})

	_, terr := svc.Token(context.Background(), validTokenReq())
	if terr == nil {
		t.Fatal("expected error for Peek failure")
	}
	if terr.Code != ErrCodeServerError {
		t.Fatalf("Code = %q, want %q", terr.Code, ErrCodeServerError)
	}
	if terr.Status != 500 {
		t.Fatalf("Status = %d, want 500", terr.Status)
	}
}

// consumeErrAuthCodeStore returns a valid code from Peek but errors on Consume.
type consumeErrAuthCodeStore struct {
	code       AuthCode
	consumeErr error
}

func (s consumeErrAuthCodeStore) Save(_ context.Context, _ AuthCode) error {
	return nil
}

func (s consumeErrAuthCodeStore) Peek(_ context.Context, _ string) (AuthCode, bool, bool, error) {
	return s.code, true, false, nil
}

func (s consumeErrAuthCodeStore) Consume(_ context.Context, _ string) (ConsumeResult, error) {
	return ConsumeResult{}, s.consumeErr
}

func TestService_Token_ConsumeError(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	svc := NewService(ServiceConfig{
		Issuer:  "https://eu.harbor.id",
		Clients: NewInMemoryClientRegistry(),
		Codes: consumeErrAuthCodeStore{
			code:       validAuthCode(now),
			consumeErr: errors.New("consume transaction failed"),
		},
		Tokens:   NewPlaceholderIssuer(),
		Sessions: NewStubSessionResolver("demo-subject-ppid"),
		Now:      func() time.Time { return now },
	})

	_, terr := svc.Token(context.Background(), validTokenReq())
	if terr == nil {
		t.Fatal("expected error for Consume failure")
	}
	if terr.Code != ErrCodeServerError {
		t.Fatalf("Code = %q, want %q", terr.Code, ErrCodeServerError)
	}
	if terr.Status != 500 {
		t.Fatalf("Status = %d, want 500", terr.Status)
	}
}

// errTokenIssuer returns a fixed error from Issue.
type errTokenIssuer struct {
	issueErr error
}

func (i errTokenIssuer) Issue(_ context.Context, _ IssueParams) (IssuedTokens, error) {
	return IssuedTokens{}, i.issueErr
}

func TestService_Token_IssueError(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	codes := NewInMemoryAuthCodeStore()
	if err := codes.Save(context.Background(), validAuthCode(now)); err != nil {
		t.Fatalf("Save: %v", err)
	}

	svc := NewService(ServiceConfig{
		Issuer:   "https://eu.harbor.id",
		Clients:  NewInMemoryClientRegistry(),
		Codes:    codes,
		Tokens:   errTokenIssuer{issueErr: errors.New("signing key unavailable")},
		Sessions: NewStubSessionResolver("demo-subject-ppid"),
		Now:      func() time.Time { return now },
	})

	_, terr := svc.Token(context.Background(), validTokenReq())
	if terr == nil {
		t.Fatal("expected error for token issuance failure")
	}
	if terr.Code != ErrCodeServerError {
		t.Fatalf("Code = %q, want %q", terr.Code, ErrCodeServerError)
	}
	if terr.Status != 500 {
		t.Fatalf("Status = %d, want 500", terr.Status)
	}
}

func TestService_Token_InvalidGrantType(t *testing.T) {
	svc := NewService(ServiceConfig{
		Issuer:   "https://eu.harbor.id",
		Clients:  NewInMemoryClientRegistry(),
		Codes:    NewInMemoryAuthCodeStore(),
		Tokens:   NewPlaceholderIssuer(),
		Sessions: NewStubSessionResolver("demo-subject-ppid"),
		Now:      func() time.Time { return time.Unix(1_700_000_000, 0) },
	})

	req := validTokenReq()
	req.GrantType = "client_credentials"
	_, terr := svc.Token(context.Background(), req)
	if terr == nil {
		t.Fatal("expected error for invalid grant_type")
	}
	if terr.Code != ErrCodeUnsupportedGrantType {
		t.Fatalf("Code = %q, want %q", terr.Code, ErrCodeUnsupportedGrantType)
	}
}

func TestService_Token_MissingParams(t *testing.T) {
	svc := NewService(ServiceConfig{
		Issuer:   "https://eu.harbor.id",
		Clients:  NewInMemoryClientRegistry(),
		Codes:    NewInMemoryAuthCodeStore(),
		Tokens:   NewPlaceholderIssuer(),
		Sessions: NewStubSessionResolver("demo-subject-ppid"),
		Now:      func() time.Time { return time.Unix(1_700_000_000, 0) },
	})

	cases := []struct {
		name   string
		mutate func(*TokenRequest)
	}{
		{"missing code", func(r *TokenRequest) { r.Code = "" }},
		{"missing redirect_uri", func(r *TokenRequest) { r.RedirectURI = "" }},
		{"missing client_id", func(r *TokenRequest) { r.ClientID = "" }},
		{"missing code_verifier", func(r *TokenRequest) { r.CodeVerifier = "" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := validTokenReq()
			tc.mutate(&req)
			_, terr := svc.Token(context.Background(), req)
			if terr == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
			if terr.Code != ErrCodeInvalidRequest {
				t.Fatalf("Code = %q, want %q", terr.Code, ErrCodeInvalidRequest)
			}
		})
	}
}

// --- signalCodeReuse tests ---

// errRevocationSink returns a fixed error from RevokeCodeFamily.
type errRevocationSink struct {
	err error
}

func (s errRevocationSink) RevokeCodeFamily(_ context.Context, _ AuthCode) error {
	return s.err
}

// consumedCodeStore returns a code that has already been consumed (for triggering
// signalCodeReuse via the Peek path).
type consumedCodeStore struct {
	code AuthCode
}

func (s consumedCodeStore) Save(_ context.Context, _ AuthCode) error {
	return nil
}

func (s consumedCodeStore) Peek(_ context.Context, _ string) (AuthCode, bool, bool, error) {
	// Return found=true, consumed=true to trigger the theft signal path.
	return s.code, true, true, nil
}

func (s consumedCodeStore) Consume(_ context.Context, _ string) (ConsumeResult, error) {
	return ConsumeResult{Status: ConsumeReused, Code: s.code}, nil
}

func TestService_signalCodeReuse_LogsRevocationError(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	code := validAuthCode(now)

	// Capture log output.
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))

	svc := NewService(ServiceConfig{
		Issuer:      "https://eu.harbor.id",
		Clients:     NewInMemoryClientRegistry(),
		Codes:       consumedCodeStore{code: code},
		Tokens:      NewPlaceholderIssuer(),
		Sessions:    NewStubSessionResolver("demo-subject-ppid"),
		Revocations: errRevocationSink{err: errors.New("revocation service unavailable")},
		Logger:      logger,
		Now:         func() time.Time { return now },
	})

	// Trigger the code reuse path via Token exchange with an already-consumed code.
	_, terr := svc.Token(context.Background(), validTokenReq())
	if terr == nil || terr.Code != ErrCodeInvalidGrant {
		t.Fatalf("Token = %v, want invalid_grant", terr)
	}

	// Verify the error was logged.
	logOutput := logBuf.String()
	if !strings.Contains(logOutput, "code-family revocation failed") {
		t.Fatalf("expected log message about revocation failure, got: %s", logOutput)
	}
	if !strings.Contains(logOutput, "revocation service unavailable") {
		t.Fatalf("expected log to contain error message, got: %s", logOutput)
	}
	if !strings.Contains(logOutput, code.ClientID) {
		t.Fatalf("expected log to contain client_id, got: %s", logOutput)
	}
}

func TestService_signalCodeReuse_NoLogOnSuccess(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	code := validAuthCode(now)

	// Capture log output.
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))

	// Use RecordingRevocationSink which succeeds (returns nil).
	revocations := NewRecordingRevocationSink()

	svc := NewService(ServiceConfig{
		Issuer:      "https://eu.harbor.id",
		Clients:     NewInMemoryClientRegistry(),
		Codes:       consumedCodeStore{code: code},
		Tokens:      NewPlaceholderIssuer(),
		Sessions:    NewStubSessionResolver("demo-subject-ppid"),
		Revocations: revocations,
		Logger:      logger,
		Now:         func() time.Time { return now },
	})

	// Trigger the code reuse path.
	_, terr := svc.Token(context.Background(), validTokenReq())
	if terr == nil || terr.Code != ErrCodeInvalidGrant {
		t.Fatalf("Token = %v, want invalid_grant", terr)
	}

	// Verify revocation was called.
	if got := revocations.Revoked(); len(got) != 1 {
		t.Fatalf("expected 1 revoked code family, got %d", len(got))
	}

	// Verify NO error was logged (success path).
	logOutput := logBuf.String()
	if strings.Contains(logOutput, "revocation failed") {
		t.Fatalf("expected no error log on success, got: %s", logOutput)
	}
}

func TestService_signalCodeReuse_LogDoesNotContainPII(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	code := AuthCode{
		Code:                "secret-auth-code-12345",
		ClientID:            "demo-client",
		RedirectURI:         testRedirectURI,
		Scope:               "openid profile",
		Subject:             "sensitive-ppid-subject",
		Nonce:               "sensitive-nonce-value",
		CodeChallenge:       rfc7636Challenge,
		CodeChallengeMethod: "S256",
		ExpiresAt:           now.Add(time.Minute),
	}

	// Capture log output.
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))

	svc := NewService(ServiceConfig{
		Issuer:      "https://eu.harbor.id",
		Clients:     NewInMemoryClientRegistry(),
		Codes:       consumedCodeStore{code: code},
		Tokens:      NewPlaceholderIssuer(),
		Sessions:    NewStubSessionResolver("demo-subject-ppid"),
		Revocations: errRevocationSink{err: errors.New("revocation failed")},
		Logger:      logger,
		Now:         func() time.Time { return now },
	})

	// Trigger the code reuse path.
	_, terr := svc.Token(context.Background(), validTokenReq())
	if terr == nil || terr.Code != ErrCodeInvalidGrant {
		t.Fatalf("Token = %v, want invalid_grant", terr)
	}

	// Verify PII is NOT logged (docs/DESIGN.md §6.5.7).
	logOutput := logBuf.String()

	// The code (secret) must NOT appear.
	if strings.Contains(logOutput, "secret-auth-code") {
		t.Fatalf("log must not contain auth code, got: %s", logOutput)
	}
	// The subject (PPID) must NOT appear.
	if strings.Contains(logOutput, "sensitive-ppid-subject") {
		t.Fatalf("log must not contain subject/PPID, got: %s", logOutput)
	}
	// The nonce must NOT appear.
	if strings.Contains(logOutput, "sensitive-nonce-value") {
		t.Fatalf("log must not contain nonce, got: %s", logOutput)
	}
	// Client ID is allowed (and should be present).
	if !strings.Contains(logOutput, "demo-client") {
		t.Fatalf("log should contain client_id for debugging, got: %s", logOutput)
	}
}
