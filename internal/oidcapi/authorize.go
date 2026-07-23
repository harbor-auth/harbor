package oidcapi

import (
	"net/http"
	"net/url"
	"time"

	"github.com/harbor-auth/harbor/internal/bff"
	"github.com/harbor-auth/harbor/internal/gen/openapi"
	"github.com/harbor-auth/harbor/internal/identity"
	"github.com/harbor-auth/harbor/internal/oidc"
	"github.com/harbor-auth/harbor/internal/telemetry"
)

// GetAuthorize serves the OIDC Authorization endpoint (GET /authorize).
//
// It delegates all validation to the pure core (internal/oidc) and then applies
// the two-channel error rule (docs/DESIGN.md §11.7): a ChannelErrorPage failure
// renders an HTML page with NO Location header (open-redirect defense), while a
// ChannelRedirect failure — and every success — 302-redirects back to the RP's
// already-validated redirect_uri.
func (s *Server) GetAuthorize(w http.ResponseWriter, r *http.Request, params openapi.GetAuthorizeParams) {
	req := authorizeRequestFromParams(params)

	// BFF flow: validate, create BFF session, redirect to login
	if s.bffSessions != nil {
		s.authorizeWithBFFSession(w, r, req)
		return
	}

	// Legacy flow: immediate code issuance via session resolver
	s.authorizeLegacy(w, r, req)
}

// authorizeWithBFFSession implements the BFF-backed authorize flow:
// 1. Validate the OIDC request
// 2. Generate a request_id (256-bit CSPRNG)
// 3. Create a BFF session record in the store
// 4. Redirect to loginURL?request_id=<id>
func (s *Server) authorizeWithBFFSession(w http.ResponseWriter, r *http.Request, req oidc.AuthorizeRequest) {
	start := time.Now()
	outcome := telemetry.OutcomeError
	defer func() { recordRequest(telemetry.EndpointAuthorize, outcome, start) }()

	validated, aerr := s.svc.ValidateAuthorizeRequest(r.Context(), req)
	if aerr != nil {
		recordError(telemetry.EndpointAuthorize, aerr.Code)
		if aerr.Channel == oidc.ChannelErrorPage {
			writeAuthorizeErrorPage(w)
			return
		}
		q := url.Values{}
		q.Set("error", aerr.Code)
		q.Set("error_description", aerr.Description)
		if req.State != "" {
			q.Set("state", req.State)
		}
		redirectWithQuery(w, r, req.RedirectURI, q)
		return
	}

	// Generate a 256-bit CSPRNG request ID
	requestID, err := bff.NewRequestID()
	if err != nil {
		// CSPRNG failure is catastrophic — fail closed with error page
		writeAuthorizeErrorPage(w)
		return
	}

	// Create BFF session record with all OIDC parameters needed for code issuance
	record := bff.BFFSessionRecord{
		RequestID:           requestID,
		State:               validated.State,
		ClientID:            validated.Client.ID,
		RedirectURI:         validated.RedirectURI,
		Scope:               validated.Scope,
		Nonce:               validated.Nonce,
		CodeChallenge:       validated.CodeChallenge,
		CodeChallengeMethod: validated.CodeChallengeMethod,
		// UserID is empty until passkey ceremony completes
		ExpiresAt: time.Now().Add(s.bffSessionTTL),
	}
	if err := s.bffSessions.Create(r.Context(), record); err != nil {
		// Session creation failure — redirect with server_error
		recordError(telemetry.EndpointAuthorize, oidc.ErrCodeServerError)
		q := url.Values{}
		q.Set("error", oidc.ErrCodeServerError)
		q.Set("error_description", "could not create session")
		if req.State != "" {
			q.Set("state", req.State)
		}
		redirectWithQuery(w, r, validated.RedirectURI, q)
		return
	}

	// Redirect to login UI with request_id
	// Clone the pre-parsed loginURL to avoid mutating the shared instance
	loginRedirect := *s.loginURL
	q := loginRedirect.Query()
	q.Set("request_id", requestID)
	loginRedirect.RawQuery = q.Encode()
	outcome = telemetry.OutcomeSuccess
	http.Redirect(w, r, loginRedirect.String(), http.StatusFound)
}

// authorizeLegacy implements the original authorize flow that immediately
// issues a code via the session resolver. This is used when BFF sessions
// are not configured.
func (s *Server) authorizeLegacy(w http.ResponseWriter, r *http.Request, req oidc.AuthorizeRequest) {
	start := time.Now()
	outcome := telemetry.OutcomeError
	defer func() { recordRequest(telemetry.EndpointAuthorize, outcome, start) }()

	result, aerr := s.svc.Authorize(r.Context(), req)
	if aerr != nil {
		recordError(telemetry.EndpointAuthorize, aerr.Code)
		if aerr.Channel == oidc.ChannelErrorPage {
			writeAuthorizeErrorPage(w)
			return
		}
		// Redirect channel: req.RedirectURI was proven to match a registered URI
		// before any redirect-channel error could be produced, so it is safe.
		q := url.Values{}
		q.Set("error", aerr.Code)
		q.Set("error_description", aerr.Description)
		if req.State != "" {
			q.Set("state", req.State)
		}
		redirectWithQuery(w, r, req.RedirectURI, q)
		return
	}

	q := url.Values{}
	q.Set("code", result.Code)
	if result.State != "" {
		q.Set("state", result.State)
	}
	// RFC 6749 §4.1.2: the authorization server MUST include the scope parameter
	// in the redirect if the granted scope differs from the requested scope.
	// Harbor currently rejects any disallowed scope with invalid_scope (strict
	// reject-not-narrow), so the returned scope always equals the requested scope
	// and inclusion is optional. If scope negotiation (granting a subset) is
	// added in a future PR, add Scope to AuthorizeResult and set it here.
	outcome = telemetry.OutcomeSuccess
	redirectWithQuery(w, r, result.RedirectURI, q)
}

// authorizeRequestFromParams maps the generated (all-optional, pointer) params
// onto the pure-core request value.
func authorizeRequestFromParams(p openapi.GetAuthorizeParams) oidc.AuthorizeRequest {
	method := ""
	if p.CodeChallengeMethod != nil {
		method = string(*p.CodeChallengeMethod)
	}
	return oidc.AuthorizeRequest{
		ResponseType:        deref(p.ResponseType),
		ClientID:            deref(p.ClientId),
		RedirectURI:         deref(p.RedirectUri),
		Scope:               deref(p.Scope),
		State:               deref(p.State),
		Nonce:               deref(p.Nonce),
		CodeChallenge:       deref(p.CodeChallenge),
		CodeChallengeMethod: method,
	}
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// redirectWithQuery 302-redirects to base with the given query parameters merged
// in (preserving any query already present on the registered redirect_uri).
func redirectWithQuery(w http.ResponseWriter, r *http.Request, base string, extra url.Values) {
	u, err := url.Parse(base)
	if err != nil {
		// base came from the registry (validated), so this is not expected; fail
		// closed with an error page rather than redirecting somewhere unsafe.
		writeAuthorizeErrorPage(w)
		return
	}
	q := u.Query()
	for k, vs := range extra {
		for _, v := range vs {
			q.Set(k, v)
		}
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// writeAuthorizeErrorPage renders the no-redirect error page. It carries a
// generic, PII-free message and MUST NOT set a Location header (docs/DESIGN.md
// §11.7 open-redirect exception).
func writeAuthorizeErrorPage(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusBadRequest)
	_, _ = w.Write([]byte("<!doctype html><html><head><title>Authorization error</title></head>" +
		"<body><h1>Authorization error</h1>" +
		"<p>This authorization request is invalid and cannot be completed. " +
		"Please return to the application and try again.</p></body></html>"))
}

// GetAuthorizeComplete resumes the OIDC flow after passkey authentication.
// It is called after /login/complete redirects here with request_id.
//
// Flow:
//  1. Read request_id from query param
//  2. Look up BFF session (must have user_id set from passkey auth)
//  3. Call oidc.Service.AuthorizeWithUser to derive PPID and issue code
//  4. Delete BFF session (one-time use)
//  5. Clear BFF cookie
//  6. Redirect to RP with auth code
func (s *Server) GetAuthorizeComplete(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	outcome := telemetry.OutcomeError
	defer func() { recordRequest(telemetry.EndpointAuthorize, outcome, start) }()

	requestID := r.URL.Query().Get("request_id")
	if requestID == "" {
		writeAuthorizeErrorPage(w)
		return
	}

	// Look up BFF session
	session, err := s.bffSessions.Get(r.Context(), requestID)
	if err != nil {
		// Session not found or expired — show error page (no safe redirect)
		writeAuthorizeErrorPage(w)
		return
	}

	// Verify user has authenticated (UserID must be set by /login/complete)
	if session.UserID == "" {
		writeAuthorizeErrorPage(w)
		return
	}

	// Inject the authenticated user_id into the context so the PPIDSessionResolver
	// (via BFFAuthSource) can read it. This is the critical link that connects the
	// BFF session's authenticated identity to the OIDC session resolver — without
	// it, the resolver cannot derive the per-RP PPID (audit blocker 1.1 fix).
	ctx := bff.ContextWithUserID(r.Context(), session.UserID)

	// Issue the authorization code using the authenticated user_id
	result, aerr := s.svc.AuthorizeWithUser(ctx, oidc.AuthorizeWithUserRequest{
		ClientID:            session.ClientID,
		RedirectURI:         session.RedirectURI,
		Scope:               session.Scope,
		State:               session.State,
		Nonce:               session.Nonce,
		CodeChallenge:       session.CodeChallenge,
		CodeChallengeMethod: session.CodeChallengeMethod,
		UserID:              session.UserID,
	})
	if aerr != nil {
		recordError(telemetry.EndpointAuthorize, aerr.Code)
		if aerr.Channel == oidc.ChannelErrorPage {
			writeAuthorizeErrorPage(w)
			return
		}
		// Redirect-channel error: send back to RP
		q := url.Values{}
		q.Set("error", aerr.Code)
		q.Set("error_description", aerr.Description)
		if session.State != "" {
			q.Set("state", session.State)
		}
		redirectWithQuery(w, r, session.RedirectURI, q)
		return
	}

	outcome = telemetry.OutcomeSuccess

	// Best-effort audit emission: auth.login marks a successful passkey
	// authentication + code issuance (BFF flow). RecordAsync is non-blocking
	// and detaches from the request context, so it never stalls the redirect.
	if s.auditRecorder != nil {
		cid := session.ClientID
		s.auditRecorder.RecordAsync(r.Context(), session.UserID, identity.EventAuthLogin, &cid, nil)
	}

	// Delete BFF session (one-time use)
	_ = s.bffSessions.Delete(r.Context(), requestID) //nolint:errcheck // best-effort: session expires via TTL anyway

	// Clear BFF cookie
	bff.ClearBFFCookie(w)

	// Redirect to RP with auth code
	q := url.Values{}
	q.Set("code", result.Code)
	if result.State != "" {
		q.Set("state", result.State)
	}
	redirectWithQuery(w, r, result.RedirectURI, q)
}
