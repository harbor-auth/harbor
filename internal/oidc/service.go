package oidc

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"log/slog"
	"sync"
	"time"
)

// SessionResolver stands in for the passkey-login + consent step of the flow
// (docs/DESIGN.md §11.2). It returns the resolved subject (PPID) for the user
// authenticating to this client, and whether they approved consent.
//
// SCAFFOLD SEAM: the real implementation runs the hosted auth UI — WebAuthn
// login (internal/webauthn), MFA/step-up, and the consent screen — and derives
// the per-RP PPID (internal/identity). The stub below auto-approves a fixed demo
// subject so /authorize is exercisable before that UI exists.
type SessionResolver interface {
	Resolve(ctx context.Context, client Client) (subject string, approved bool, err error)
}

// stubSessionResolver auto-approves a fixed subject. SCAFFOLD only.
type stubSessionResolver struct{ subject string }

// NewStubSessionResolver returns a SessionResolver that always authenticates and
// consents as subject. SCAFFOLD — replace with real passkey login + consent.
func NewStubSessionResolver(subject string) SessionResolver {
	return stubSessionResolver{subject: subject}
}

func (r stubSessionResolver) Resolve(_ context.Context, _ Client) (string, bool, error) {
	return r.subject, true, nil
}

// RevocationSink receives the theft signal when an authorization code is reused:
// every token minted from that code must be revoked (docs/DESIGN.md §11.7, §3.5).
type RevocationSink interface {
	RevokeCodeFamily(ctx context.Context, code AuthCode) error
}

// noopRevocationSink is the default when no sink is wired.
type noopRevocationSink struct{}

func (noopRevocationSink) RevokeCodeFamily(context.Context, AuthCode) error { return nil }

// RecordingRevocationSink records revoked code families in memory. Useful for
// tests and dev wiring that want to assert the theft signal fired.
type RecordingRevocationSink struct {
	mu      sync.Mutex
	revoked []AuthCode
}

// NewRecordingRevocationSink returns an empty recorder.
func NewRecordingRevocationSink() *RecordingRevocationSink { return &RecordingRevocationSink{} }

// RevokeCodeFamily implements RevocationSink.
func (s *RecordingRevocationSink) RevokeCodeFamily(_ context.Context, code AuthCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revoked = append(s.revoked, code)
	return nil
}

// Revoked returns a copy of the revoked code families recorded so far.
func (s *RecordingRevocationSink) Revoked() []AuthCode {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]AuthCode, len(s.revoked))
	copy(out, s.revoked)
	return out
}

// defaultCodeTTL is the authorization-code lifetime (~30–60s; docs/DESIGN.md
// §11.7). Codes are single-use and short-lived.
const defaultCodeTTL = 60 * time.Second

// ServiceConfig wires the Service's collaborators. Clients, Codes, Tokens, and
// Sessions are required; Revocations, NewCode, Now, and CodeTTL default to
// sensible values (the last three are seams for deterministic tests).
// Logger defaults to slog.Default() — never nil, never a no-op discard
// (a silent default would re-introduce the error-swallow the field is here
// to prevent; see docs/design/principles/error-handling.md §1.11).
type ServiceConfig struct {
	Issuer      string
	Clients     ClientRegistry
	Codes       AuthCodeStore
	Tokens      TokenIssuer
	Sessions    SessionResolver
	Grants      GrantStore // optional; defaults to noopGrantStore
	Revocations RevocationSink
	Logger      *slog.Logger
	NewCode     func() (string, error)
	Now         func() time.Time
	CodeTTL     time.Duration
}

// Service coordinates the pure validators (authorize.go, token.go, pkce.go) with
// the stores and issuer. It holds no per-request state and performs no HTTP —
// the thin HTTP layer is internal/oidcapi.
type Service struct {
	issuer      string
	clients     ClientRegistry
	codes       AuthCodeStore
	tokens      TokenIssuer
	sessions    SessionResolver
	grants      GrantStore
	revocations RevocationSink
	logger      *slog.Logger
	newCode     func() (string, error)
	now         func() time.Time
	codeTTL     time.Duration
}

// NewService builds a Service, applying defaults for the optional config fields.
func NewService(cfg ServiceConfig) *Service {
	svc := &Service{
		issuer:      cfg.Issuer,
		clients:     cfg.Clients,
		codes:       cfg.Codes,
		tokens:      cfg.Tokens,
		sessions:    cfg.Sessions,
		grants:      cfg.Grants,
		revocations: cfg.Revocations,
		logger:      cfg.Logger,
		newCode:     cfg.NewCode,
		now:         cfg.Now,
		codeTTL:     cfg.CodeTTL,
	}
	if svc.grants == nil {
		svc.grants = noopGrantStore{}
	}
	if svc.revocations == nil {
		svc.revocations = noopRevocationSink{}
	}
	if svc.logger == nil {
		svc.logger = slog.Default()
	}
	if svc.newCode == nil {
		svc.newCode = defaultNewCode
	}
	if svc.now == nil {
		svc.now = time.Now
	}
	if svc.codeTTL == 0 {
		svc.codeTTL = defaultCodeTTL
	}
	return svc
}

// AuthorizeResult is a successful /authorize outcome: a redirect back to the RP
// carrying the freshly-issued code and echoed state.
type AuthorizeResult struct {
	RedirectURI string
	Code        string
	State       string
}

// Authorize validates the request, runs the (stubbed) login/consent step, then
// issues and stores a single-use authorization code. On any validation failure
// it returns an *AuthorizeError whose Channel tells the HTTP layer whether it is
// safe to redirect (docs/DESIGN.md §11.7).
func (s *Service) Authorize(ctx context.Context, req AuthorizeRequest) (*AuthorizeResult, *AuthorizeError) {
	var client *Client
	if c, ok := s.clients.Lookup(ctx, req.ClientID); ok {
		client = &c
	}

	validated, aerr := ValidateAuthorize(req, client)
	if aerr != nil {
		return nil, aerr
	}

	// Login + consent (SCAFFOLD: auto-approves a demo subject). A real rejection
	// here is access_denied, redirected back to the RP (docs/DESIGN.md §11.7).
	subject, approved, err := s.sessions.Resolve(ctx, validated.Client)
	if err != nil {
		return nil, redirectErr(ErrCodeServerError, "login could not be completed")
	}
	if !approved {
		return nil, redirectErr(ErrCodeAccessDenied, "the user did not grant consent")
	}

	codeStr, err := s.newCode()
	if err != nil {
		return nil, redirectErr(ErrCodeServerError, "could not issue authorization code")
	}

	code := AuthCode{
		Code:                codeStr,
		ClientID:            validated.Client.ID,
		RedirectURI:         validated.RedirectURI,
		Scope:               validated.Scope,
		Subject:             subject,
		Nonce:               validated.Nonce,
		CodeChallenge:       validated.CodeChallenge,
		CodeChallengeMethod: validated.CodeChallengeMethod,
		ExpiresAt:           s.now().Add(s.codeTTL),
	}
	if err := s.codes.Save(ctx, code); err != nil {
		return nil, redirectErr(ErrCodeServerError, "could not persist authorization code")
	}

	return &AuthorizeResult{
		RedirectURI: validated.RedirectURI,
		Code:        codeStr,
		State:       validated.State,
	}, nil
}

// Token exchanges an authorization code for tokens. The ordering is the
// auth-code-DoS defense (docs/DESIGN.md §11.7): a request that fails binding or
// PKCE must NOT burn a valid one-time code, or an attacker holding a stolen code
// could lock the legitimate user out. So we:
//
//  1. validate params (grant_type + presence);
//  2. PEEK the code (no mutation) — unknown → invalid_grant; already consumed →
//     theft signal (revoke the code family) + invalid_grant;
//  3. validate binding + expiry + PKCE against the peeked code — on failure
//     return WITHOUT consuming (the code stays valid for its real owner);
//  4. only on success CONSUME (single-use). A racing second exchange that wins
//     the tombstone here still surfaces as reuse (revoke + invalid_grant).
func (s *Service) Token(ctx context.Context, req TokenRequest) (*IssuedTokens, *TokenError) {
	if terr := ValidateTokenParams(req); terr != nil {
		return nil, terr
	}

	stored, found, consumed, err := s.codes.Peek(ctx, req.Code)
	if err != nil {
		return nil, &TokenError{Code: ErrCodeServerError, Description: "could not read authorization code", Status: 500}
	}
	if !found {
		return nil, invalidGrant("authorization code is invalid")
	}
	if consumed {
		// Assume theft: revoke everything minted from this code.
		s.signalCodeReuse(ctx, stored)
		return nil, invalidGrant("authorization code has already been used")
	}

	// Validate against the STORED code before burning it. A failure here leaves
	// the code intact for the legitimate owner.
	if terr := ValidateTokenExchange(req, stored, s.now()); terr != nil {
		return nil, terr
	}

	// Only now consume (single-use). Handle a lost race on the tombstone.
	result, err := s.codes.Consume(ctx, req.Code)
	if err != nil {
		return nil, &TokenError{Code: ErrCodeServerError, Description: "could not consume authorization code", Status: 500}
	}
	switch result.Status {
	case ConsumeNotFound:
		return nil, invalidGrant("authorization code is invalid")
	case ConsumeReused:
		s.signalCodeReuse(ctx, result.Code)
		return nil, invalidGrant("authorization code has already been used")
	}

	tokens, err := s.tokens.Issue(ctx, IssueParams{
		Issuer:   s.issuer,
		Subject:  result.Code.Subject,
		ClientID: result.Code.ClientID,
		Scope:    result.Code.Scope,
		Nonce:    result.Code.Nonce,
	})
	if err != nil {
		return nil, &TokenError{Code: ErrCodeServerError, Description: "could not issue tokens", Status: 500}
	}
	return &tokens, nil
}

// signalCodeReuse fires the theft signal when a code is presented twice: it
// attempts to revoke every token minted from the code family and logs any
// failure at ERROR level (docs/design/principles/error-handling.md §1.11,
// docs/DESIGN.md §11.7). The caller always returns invalid_grant regardless of
// whether revocation succeeds — the primary client response is independent of
// the side-effect — but the failure is NOT silently discarded.
//
// PII constraint (§6.5.7): only client_id + the error value are logged.
// Never log Subject (PPID), Code (a secret), or Nonce.
//
// TODO(security): route revocation through a durable outbox so a transient
// failure is retried, not merely alerted (the in-process best-effort signal
// is the correct interim handling, not the final design).
func (s *Service) signalCodeReuse(ctx context.Context, code AuthCode) {
	if err := s.revocations.RevokeCodeFamily(ctx, code); err != nil {
		s.logger.ErrorContext(ctx, "code-family revocation failed after reuse detected",
			slog.String("client_id", code.ClientID),
			slog.Any("error", err))
	}
}

// defaultNewCode returns a 256-bit random, URL-safe authorization code.
func defaultNewCode() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
