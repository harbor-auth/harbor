package oidcapi

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/harbor-auth/harbor/internal/gen/openapi"
	"github.com/harbor-auth/harbor/internal/oidc"
)

// LogoutVerifier verifies an id_token_hint's signature (and issuer) but ignores
// expiry, so a user may log out with an expired ID token during RP-Initiated
// Logout (OIDC RP-Initiated Logout 1.0). *oidc.JWTVerifier satisfies this.
type LogoutVerifier interface {
	VerifySignatureOnly(ctx context.Context, token string) (*oidc.VerifiedClaims, error)
}

// SessionRevoker revokes all active refresh sessions for a (userID, clientID)
// pair — the user's sessions at exactly the RP that initiated the logout, never
// their sessions at other RPs (DESIGN §11.7). *clients.DBSessionStore (via
// oidc.SessionStore) satisfies this.
type SessionRevoker interface {
	RevokeSessionsByUserClient(ctx context.Context, userID, clientID string) error
}

// endSessionParams is the method-agnostic view of an /end_session request.
// Both GET (query params) and POST (form body) normalise onto this.
type endSessionParams struct {
	IDTokenHint           string
	PostLogoutRedirectURI string
	State                 string
	ClientID              string
}

// GetEndSession serves RP-Initiated Logout via GET /end_session (the generated
// wrapper already enforced that id_token_hint is present).
func (s *Server) GetEndSession(w http.ResponseWriter, r *http.Request, params openapi.GetEndSessionParams) {
	s.endSession(w, r, endSessionParams{
		IDTokenHint:           params.IdTokenHint,
		PostLogoutRedirectURI: deref(params.PostLogoutRedirectUri),
		State:                 deref(params.State),
		ClientID:              deref(params.ClientId),
	})
}

// PostEndSession serves RP-Initiated Logout via POST /end_session. The RP sends
// the same fields as a form-encoded body (OIDC RP-Initiated Logout 1.0 §2).
func (s *Server) PostEndSession(w http.ResponseWriter, r *http.Request) {
	// Cap the body so a flooded endpoint can't exhaust memory (DESIGN §6.5).
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	if err := r.ParseForm(); err != nil {
		// Malformed body: we can't trust anything in it, so fall back to the
		// issuer's default logged-out page rather than honour an unvalidated URI.
		s.redirectLoggedOut(w, r)
		return
	}
	s.endSession(w, r, endSessionParams{
		IDTokenHint:           r.PostFormValue("id_token_hint"),
		PostLogoutRedirectURI: r.PostFormValue("post_logout_redirect_uri"),
		State:                 r.PostFormValue("state"),
		ClientID:              r.PostFormValue("client_id"),
	})
}

// endSession implements the shared RP-Initiated Logout pipeline:
//
//  1. Verify the id_token_hint signature (expiry ignored) to prove the token was
//     genuinely issued by Harbor. The token's aud claim is the client_id and the
//     sub claim is the RP-specific PPID.
//  2. Reverse-lookup the internal userID from (PPID, clientID) via the grant
//     store — the RP never learns the internal user UUID.
//  3. Revoke the user's sessions at that RP (and only that RP).
//  4. If post_logout_redirect_uri was supplied AND it exactly matches one of the
//     client's registered logout_uris, redirect there (echoing state);
//     otherwise redirect to the issuer's default logged-out page.
//
// Any failure to identify/verify the request degrades to the default logged-out
// page rather than an error — logout should be as forgiving as possible while
// never redirecting to an unproven URI (open-redirect defence, DESIGN §11.7).
func (s *Server) endSession(w http.ResponseWriter, r *http.Request, p endSessionParams) {
	// If the logout dependencies aren't wired (e.g. discovery-only test server),
	// there is nothing to revoke — just show the default logged-out page.
	if s.logoutVerifier == nil || s.grants == nil || s.clients == nil || s.sessionRevoker == nil {
		s.redirectLoggedOut(w, r)
		return
	}

	if p.IDTokenHint == "" {
		// Without an id_token_hint we cannot identify the user/client to revoke.
		s.redirectLoggedOut(w, r)
		return
	}

	claims, err := s.logoutVerifier.VerifySignatureOnly(r.Context(), p.IDTokenHint)
	if err != nil {
		// Bad signature / issuer mismatch: the hint is untrustworthy. Do NOT act
		// on any of its claims and do NOT honour post_logout_redirect_uri.
		s.redirectLoggedOut(w, r)
		return
	}

	// The id_token's aud claim is the authoritative client_id. If the RP also
	// supplied a client_id form/query param, it must agree with the token —
	// a mismatch means the request is inconsistent and we refuse to act on it.
	clientID := claims.Audience
	if clientID == "" || (p.ClientID != "" && p.ClientID != clientID) {
		s.redirectLoggedOut(w, r)
		return
	}

	// Reverse-lookup the internal userID from the RP-specific PPID (sub).
	grant, found, err := s.grants.FindGrantByPPID(r.Context(), claims.Subject, clientID)
	if err != nil {
		// DB error looking up the grant: log and still complete the logout redirect
		// (a transient DB blip must not strand the user on an error page).
		slog.Default().Error("oidcapi: end_session grant lookup failed", "error", err)
		s.redirectLoggedOut(w, r)
		return
	}
	if found {
		if err := s.sessionRevoker.RevokeSessionsByUserClient(r.Context(), grant.UserID, clientID); err != nil {
			// Revocation failure is logged but non-fatal: we still redirect so the
			// user isn't stuck, and the sessions remain revocable via other paths.
			slog.Default().Error("oidcapi: end_session revoke failed", "error", err)
		}
	}

	// Only honour a post_logout_redirect_uri that EXACTLY matches a URI the
	// client registered (open-redirect defence, DESIGN §11.7). A DB error in
	// Lookup returns ok=false, so we fail safe to the default page.
	if p.PostLogoutRedirectURI != "" {
		if client, ok := s.clients.Lookup(r.Context(), clientID); ok && client.HasLogoutURI(p.PostLogoutRedirectURI) {
			s.redirectPostLogout(w, r, p.PostLogoutRedirectURI, p.State)
			return
		}
	}

	s.redirectLoggedOut(w, r)
}

// redirectLoggedOut 302-redirects to the issuer's default logged-out page. This
// is the safe fallback whenever a validated post_logout_redirect_uri is not
// available.
func (s *Server) redirectLoggedOut(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, s.issuer+"/logged-out", http.StatusFound)
}

// redirectPostLogout 302-redirects to a validated post_logout_redirect_uri,
// echoing the RP's state (if any) so the RP can restore context / defend CSRF.
func (s *Server) redirectPostLogout(w http.ResponseWriter, r *http.Request, uri, state string) {
	if state == "" {
		http.Redirect(w, r, uri, http.StatusFound)
		return
	}
	u, err := url.Parse(uri)
	if err != nil {
		// uri was proven to match a registered logout_uri, so a parse failure is
		// unexpected; fail safe to the default page rather than a bad Location.
		s.redirectLoggedOut(w, r)
		return
	}
	q := u.Query()
	q.Set("state", state)
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}
