package oidcapi

import (
	"net/http"
	"net/url"

	"github.com/harbor/harbor/internal/gen/openapi"
	"github.com/harbor/harbor/internal/oidc"
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

	result, aerr := s.svc.Authorize(r.Context(), req)
	if aerr != nil {
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
