package oidc

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
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
	Resolve(ctx context.Context, client Client, scope string) (subject, userID string, approved bool, err error)
}

// stubSessionResolver auto-approves a fixed subject. SCAFFOLD only.
type stubSessionResolver struct{ subject string }

// NewStubSessionResolver returns a SessionResolver that always authenticates and
// consents as subject. SCAFFOLD — replace with real passkey login + consent.
func NewStubSessionResolver(subject string) SessionResolver {
	return stubSessionResolver{subject: subject}
}

// Resolve always returns userID="" (empty). This is intentional for unit-test
// simplicity — Token() gates issueRefreshToken on `result.Code.UserID != ""`
// (docs/DESIGN.md §3.5), so any test using stubSessionResolver will NEVER
// receive a refresh token through a full Authorize→Token flow. Use
// PPIDSessionResolver with a FixedAuthSource for refresh-token integration
// tests (see newRefreshFlowServerWithStore in refresh_rotation_test.go).
func (r stubSessionResolver) Resolve(_ context.Context, _ Client, _ string) (string, string, bool, error) {
	return r.subject, "", true, nil
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
	Issuer       string
	Clients      ClientRegistry
	Codes        AuthCodeStore
	Tokens       TokenIssuer
	Sessions     SessionResolver
	SessionStore SessionStore // optional; defaults to noopSessionStore (no refresh tokens)
	Grants       GrantStore   // optional; defaults to noopGrantStore
	Revocations  RevocationSink
	Logger       *slog.Logger
	NewCode      func() (string, error)
	NewSessionID func() (string, error) // optional; defaults to uuid.NewString
	Now          func() time.Time
	CodeTTL      time.Duration
}

// Service coordinates the pure validators (authorize.go, token.go, pkce.go) with
// the stores and issuer. It holds no per-request state and performs no HTTP —
// the thin HTTP layer is internal/oidcapi.
type Service struct {
	issuer       string
	clients      ClientRegistry
	codes        AuthCodeStore
	tokens       TokenIssuer
	sessions     SessionResolver
	sessionStore SessionStore
	grants       GrantStore
	revocations  RevocationSink
	logger       *slog.Logger
	newCode      func() (string, error)
	newSessionID func() (string, error)
	now          func() time.Time
	codeTTL      time.Duration
}

// NewService builds a Service, applying defaults for the optional config fields.
func NewService(cfg ServiceConfig) *Service {
	svc := &Service{
		issuer:       cfg.Issuer,
		clients:      cfg.Clients,
		codes:        cfg.Codes,
		tokens:       cfg.Tokens,
		sessions:     cfg.Sessions,
		sessionStore: cfg.SessionStore,
		grants:       cfg.Grants,
		revocations:  cfg.Revocations,
		logger:       cfg.Logger,
		newCode:      cfg.NewCode,
		newSessionID: cfg.NewSessionID,
		now:          cfg.Now,
		codeTTL:      cfg.CodeTTL,
	}
	if svc.grants == nil {
		svc.grants = noopGrantStore{}
	}
	if svc.sessionStore == nil {
		svc.sessionStore = noopSessionStore{}
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
	if svc.newSessionID == nil {
		// Session IDs must be valid UUIDs — DBSessionStore stores them in a
		// uuid column and rejects any non-UUID string. defaultNewCode returns
		// a base64url string, which would fail every DB CreateSession/Rotate.
		svc.newSessionID = func() (string, error) { return uuid.NewString(), nil }
	}
	if svc.now == nil {
		svc.now = time.Now
	}
	if svc.codeTTL == 0 {
		svc.codeTTL = defaultCodeTTL
	}
	// Misconfiguration guard (catches both cfg.Grants == nil and the typed-non-nil
	// bypass where the caller passes cfg.Grants = noopGrantStore{} explicitly).
	// A real SessionStore with noopGrantStore means every Refresh() returns
	// invalid_grant (noopGrantStore returns found=false for every lookup) — an
	// invisible production outage. Panic at construction so the bug surfaces at
	// startup rather than silently in production traffic.
	// The inverse (Grants without SessionStore) is legitimate: PPID resolution
	// uses grants; refresh tokens are independently optional.
	if cfg.SessionStore != nil {
		if _, isNoop := svc.grants.(noopGrantStore); isNoop {
			panic("oidc: ServiceConfig.SessionStore is set but Grants is noopGrantStore — " +
				"Refresh() will return invalid_grant for every valid token; " +
				"wire both or neither")
		}
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
	subject, userID, approved, err := s.sessions.Resolve(ctx, validated.Client, validated.Scope)
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
		UserID:              userID,
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

	// Issue an opaque, rotating refresh token ONLY when offline_access was
	// granted AND we captured a real user_id at consent time (docs/DESIGN.md
	// §3.5). A refresh-token store or generation failure must NOT fail the token
	// response — the access/ID tokens are already valid — but it is logged, never
	// silently swallowed.
	if scopeHasOfflineAccess(result.Code.Scope) && result.Code.UserID != "" {
		s.issueRefreshToken(ctx, &tokens, result.Code)
	}
	return &tokens, nil
}

// issueRefreshToken mints an opaque refresh token, stores only its hash, and
// (on success) attaches the plaintext + TTL to tokens. Best-effort: a failure is
// logged and leaves tokens without a refresh token rather than failing the
// whole exchange.
//
// The user's home region is recovered from the consent grant (just created by
// PPIDSessionResolver.Resolve) so the session satisfies the user-owned-row
// contract (DESIGN §10). Fail-closed on region: if the grant cannot be found
// (consent revoked in the ~60s code-TTL window, or noopGrantStore dev wiring)
// the refresh token is skipped — an unregioned session would propagate forever
// through RotateSession's `newSession.Region = session.Region` copy.
// The H9-2 panic guard ensures that in production (real SessionStore) a real
// GrantStore is always wired, so the not-found path is a genuine edge case.
func (s *Service) issueRefreshToken(ctx context.Context, tokens *IssuedTokens, code AuthCode) {
	// Recover the region from the consent grant. Fail-closed: if the grant is
	// gone (consent revoked between /authorize and /token, or noopGrantStore
	// dev wiring), skip the refresh token rather than creating an unregioned
	// session that propagates the empty region forever via RotateSession.
	grant, found, err := s.grants.FindGrant(ctx, code.UserID, code.ClientID)
	if err != nil {
		s.logger.ErrorContext(ctx, "failed to recover grant region for refresh session — skipping refresh token",
			slog.String("client_id", code.ClientID),
			slog.Any("error", err))
		return
	}
	if !found {
		// Consent was revoked between Authorize and Token (race), or this is a
		// noopGrantStore dev wiring (SessionStore also noop in that case per the
		// NewService panic guard). Either way, skip the refresh token.
		s.logger.WarnContext(ctx, "skipping refresh token: no active grant found — consent may have been revoked between /authorize and /token",
			slog.String("client_id", code.ClientID))
		return
	}

	plaintext, hash, err := newOpaqueToken()
	if err != nil {
		s.logger.ErrorContext(ctx, "failed to generate refresh token", slog.Any("error", err))
		return
	}
	sessionID, err := s.newSessionID()
	if err != nil {
		s.logger.ErrorContext(ctx, "failed to generate refresh session id", slog.Any("error", err))
		return
	}
	rs := RefreshSession{
		ID:        sessionID,
		Region:    grant.Region,
		UserID:    code.UserID,
		ClientID:  code.ClientID,
		TokenHash: hash,
		ExpiresAt: s.now().Add(defaultRefreshTTL),
	}
	if err := s.sessionStore.CreateSession(ctx, rs); err != nil {
		s.logger.ErrorContext(ctx, "failed to store refresh session",
			slog.String("client_id", code.ClientID),
			slog.Any("error", err))
		return
	}
	tokens.RefreshToken = encodeRefreshToken(plaintext)
	tokens.RefreshExpiresIn = int(defaultRefreshTTL.Seconds())
}

// scopeHasOfflineAccess reports whether the space-delimited scope string
// contains offline_access — the gate for issuing a refresh token (§3.5).
func scopeHasOfflineAccess(scope string) bool {
	for _, s := range strings.Fields(scope) {
		if s == "offline_access" {
			return true
		}
	}
	return false
}

// Refresh rotates a refresh token (grant_type=refresh_token; docs/DESIGN.md
// §3.5). The ordering mirrors the auth-code DoS/theft defense in Token():
//
//  1. Decode + hash the presented opaque token (never store/log the plaintext).
//  2. Look it up. Unknown/expired -> invalid_grant. Already-revoked -> THEFT
//     signal: revoke the whole (user, client) session family + invalid_grant.
//  3. Validate client binding + expiry against the stored session.
//  4. Rotate one-time: revoke old, create new (fresh opaque token), then mint a
//     fresh access/ID token from the frozen grant.
//
// Reuse of a rotated token is caught in step 2 because RevokeSession tombstones
// (rather than deletes) the old session.
func (s *Service) Refresh(ctx context.Context, req TokenRequest) (*IssuedTokens, *TokenError) {
	if terr := ValidateTokenParams(req); terr != nil {
		return nil, terr
	}
	raw, err := decodeRefreshToken(req.RefreshToken)
	if err != nil {
		return nil, invalidGrant("refresh token is invalid")
	}
	hash := hashRefreshToken(raw)

	session, err := s.sessionStore.GetSessionByTokenHash(ctx, hash)
	if err != nil {
		if errors.Is(err, ErrRefreshTokenRevoked) {
			// A rotated (revoked) token was replayed: assume theft, revoke family.
			s.signalRefreshReuse(ctx, session)
			return nil, invalidGrant("refresh token is invalid")
		}
		if errors.Is(err, ErrRefreshTokenNotFound) {
			return nil, invalidGrant("refresh token is invalid")
		}
		// Transient DB error — propagate as 5xx, not invalid_grant.
		// Masking a DB outage as invalid_grant would silently reject valid
		// tokens during an outage and trigger a mass-logout (docs/DESIGN.md §10).
		return nil, &TokenError{Code: ErrCodeServerError, Description: "could not look up session", Status: 500}
	}

	if terr := ValidateRefreshParams(req, session, s.now()); terr != nil {
		return nil, terr
	}

	// All fallible reads and computations happen BEFORE RotateSession so that
	// a failure at any of these steps still leaves the old refresh token valid
	// and the client can simply retry (docs/DESIGN.md §3.5).
	//
	// Step A: recover the frozen PPID + scopes from the consent grant.
	grant, found, err := s.grants.FindGrant(ctx, session.UserID, session.ClientID)
	if err != nil {
		s.logger.ErrorContext(ctx, "refresh: grant lookup failed",
			slog.String("client_id", session.ClientID),
			slog.Any("error", err))
		return nil, &TokenError{Code: ErrCodeServerError, Description: "could not recover grant for token issuance", Status: 500}
	}
	if !found {
		// The user revoked consent after the refresh token was issued. This is
		// invalid_grant (RFC 6749 §5.2) — the authorization is gone permanently.
		// Returning server_error here would cause well-behaved clients to retry
		// indefinitely, never learning that re-consent is required.
		return nil, invalidGrant("consent grant has been revoked")
	}

	// Step B: mint the new access/ID tokens — depends only on grant + session,
	// NOT on the new refresh session that RotateSession will create. Doing this
	// before rotation means that if signing fails the old token is still live.
	//
	// Scope-narrowing (RFC 6749 §6): TokenRequest has no Scope field, so a
	// client requesting a narrower scope on a refresh_token grant is currently
	// silently ignored — the full frozen grant scopes are always returned. This
	// is a known intentional omission: scope narrowing is NEVER broader than the
	// original grant (so it is not a security violation), and the DESIGN.md §3.5
	// does not require it. If scope-narrowing support is added in a future PR,
	// parse req.Scope here and intersect it against grant.Scopes, returning
	// invalid_scope on any requested scope not in the grant.
	scopeStr := strings.Join(grant.Scopes, " ")
	tokens, err := s.tokens.Issue(ctx, IssueParams{
		Issuer:   s.issuer,
		Subject:  grant.PairwiseSub,
		ClientID: session.ClientID,
		Scope:    scopeStr,
		// Nonce is intentionally omitted: OIDC Core §12.2 specifies that the
		// nonce claim is only required in the initial ID token (from /authorize)
		// and MUST NOT be included in tokens issued via refresh_token grant.
	})
	if err != nil {
		s.logger.ErrorContext(ctx, "refresh: token signing failed",
			slog.String("client_id", session.ClientID),
			slog.Any("error", err))
		return nil, &TokenError{Code: ErrCodeServerError, Description: "could not issue tokens", Status: 500}
	}

	// offline_access guard: only rotate and re-issue a refresh token when
	// offline_access is still present in the grant's frozen scopes.
	// A grant scope downgrade after issuance is handled conservatively:
	// the freshly-signed access/ID tokens are returned (so the request
	// succeeds) but no new refresh token is issued and the old session is
	// NOT revoked (so the client can retry on expiry without being locked
	// out). SECURITY NOTE: to stop a client from ever refreshing again,
	// operators must REVOKE the consent grant entirely — a partial scope
	// removal leaves the existing refresh session valid until its natural
	// TTL (up to 14 days). Matches the Token() gate (scopeHasOfflineAccess)
	// and prevents a refresh_token response whose scope omits offline_access
	// (RFC 6749 §3.3 protocol violation).
	//
	// NOTE: this path (grant exists but offline_access is absent) is currently
	// only reachable via direct DB manipulation — there is no grant-update API.
	// If a grant-update endpoint is ever added, this decision (leave the refresh
	// session live) should be revisited in that PR before merging.
	if !scopeHasOfflineAccess(scopeStr) {
		return &tokens, nil
	}

	// Step C: generate new opaque refresh-token material.
	newPlaintext, newHash, err := newOpaqueToken()
	if err != nil {
		s.logger.ErrorContext(ctx, "refresh: failed to generate refresh token material",
			slog.String("client_id", session.ClientID),
			slog.Any("error", err))
		return nil, &TokenError{Code: ErrCodeServerError, Description: "could not generate refresh token", Status: 500}
	}
	newSessionID, err := s.newSessionID()
	if err != nil {
		s.logger.ErrorContext(ctx, "refresh: failed to generate session id",
			slog.String("client_id", session.ClientID),
			slog.Any("error", err))
		return nil, &TokenError{Code: ErrCodeServerError, Description: "could not generate session id", Status: 500}
	}
	newSession := RefreshSession{
		ID:          newSessionID,
		Region:      session.Region,
		UserID:      session.UserID,
		ClientID:    session.ClientID,
		GrantID:     session.GrantID, // always copies "" (no DB column yet); see TODO(grant-fk) in buildCreateSessionParams
		DeviceLabel: session.DeviceLabel,
		TokenHash:   newHash,
		ExpiresAt:   s.now().Add(defaultRefreshTTL),
	}

	// Step D: RotateSession is the commit point — everything before here can
	// fail without locking the client out. After this call the old token is
	// revoked, so the only remaining operations are infallible assignments.
	// With a pool-wired DBSessionStore this is a single transaction; with
	// InMemorySessionStore it is atomic under the store's mutex.
	if err := s.sessionStore.RotateSession(ctx, session.ID, newSession); err != nil {
		s.logger.ErrorContext(ctx, "refresh: session rotation failed",
			slog.String("client_id", session.ClientID),
			slog.Any("error", err))
		return nil, &TokenError{Code: ErrCodeServerError, Description: "could not rotate session", Status: 500}
	}

	// After RotateSession the old token is gone. No more fallible operations.
	// ACCEPTED RISK (RFC 6749 §10.4): if the HTTP response write fails after
	// this point, the client loses the new token and cannot retry — presenting
	// the (now-revoked) old token fires the theft signal and revokes the family.
	// This is the standard refresh-rotation trade-off. A durable outbox pattern
	// (write pending→after-commit→send) would eliminate the window but adds
	// significant complexity. Documented in docs/DESIGN.md §3.5 for future
	// revisit when SLA requirements are known.
	tokens.RefreshToken = encodeRefreshToken(newPlaintext)
	tokens.RefreshExpiresIn = int(defaultRefreshTTL.Seconds())
	return &tokens, nil
}

// zeroUUID is the sentinel returned by uuidToString when pgtype.UUID.Valid is
// false. It must be treated the same as the empty string for the theft-signal
// guard: a zero-UUID UserID or ClientID would silently match zero rows in
// RevokeSessionsByUserClient, suppressing the family revoke.
const zeroUUID = "00000000-0000-0000-0000-000000000000"

// signalRefreshReuse fires the theft signal when a revoked refresh token is
// replayed: it revokes every active session in the same (user, client) family
// and logs the event. PII constraint (§6.5.7): only client_id + the error are
// logged — never UserID, GrantID, or the token/hash.
func (s *Service) signalRefreshReuse(ctx context.Context, session RefreshSession) {
	// Defensive guard: an empty or zero-UUID UserID/ClientID would make
	// RevokeSessionsByUserClient match zero rows and silently suppress the theft
	// signal. The empty-string case catches in-memory store bugs; the zero-UUID
	// case ("00000000-...") catches a NULL pgtype.UUID that survived rowToRefreshSession
	// via uuidToString. Both signal a latent store bug — surface loudly.
	//
	// Asymmetry note: the zero-UUID sentinel ("00000000-...") specifically
	// guards against a NULL pgtype.UUID surviving DBSessionStore.rowToRefreshSession
	// → uuidToString. ClientID is a plain VARCHAR column and is never routed
	// through uuidToString, so the empty-string check is sufficient for it.
	if session.UserID == "" || session.UserID == zeroUUID ||
		session.ClientID == "" {
		s.logger.ErrorContext(ctx, "refresh-reuse signal: session has empty/invalid UserID or ClientID — family revoke skipped (latent store bug)",
			slog.String("session_id", session.ID))
		return
	}
	if err := s.sessionStore.RevokeSessionsByUserClient(ctx, session.UserID, session.ClientID); err != nil {
		s.logger.ErrorContext(ctx, "refresh-family revocation failed after reuse detected",
			slog.String("client_id", session.ClientID),
			slog.Any("error", err))
	}
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
