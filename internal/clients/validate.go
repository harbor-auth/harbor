package clients

import (
	"errors"
	"net"
	"net/url"
	"strings"
)

// RFC 7591/7592 client-metadata validation, shared by mgmtapi's dynamic
// client registration (POST /register) and cloudapi's namespace-scoped
// client provisioning (POST/PUT .../clients). It lives here rather than in
// mgmtapi because cloudapi must re-validate redirect URIs itself — never
// trust a network peer's validator — but importing mgmtapi would drag the
// mgmt-only webauthn package into the cloud surface (internal/arch's
// TestHarborHotDoesNotImportCloudAPI / TestClientsDoesNotImportWebAuthn).
// mgmtapi/register_validate.go keeps thin delegating wrappers so its
// exported API (and its tests) are unchanged.
//
// Everything here is PURE (no DB, no clock, no network) so it is
// exhaustively table-testable and safe to call from either hot path.

// Validation errors. These are sentinels so a caller can map each to its own
// error code (e.g. mgmtapi's RFC 7591 §3.2.2 invalid_redirect_uri /
// invalid_client_metadata) without string matching.
var (
	// ErrNoRedirectURIs is returned when a request omits redirect_uris. At
	// least one is required — Harbor only supports the authorization-code
	// flow, which is a redirect flow (docs/DESIGN.md §3.1).
	ErrNoRedirectURIs = errors.New("clients: at least one redirect_uri is required")
	// ErrRedirectURIInvalid is returned for a malformed or non-absolute URI.
	ErrRedirectURIInvalid = errors.New("clients: redirect_uri is not a valid absolute URI")
	// ErrRedirectURINotHTTPS is returned for a non-HTTPS URI whose host is not
	// a loopback address (RFC 8252 §7.3 allows http only for loopback).
	ErrRedirectURINotHTTPS = errors.New("clients: redirect_uri must use https (http allowed only for loopback)")
	// ErrRedirectURIFragment is returned when a redirect_uri carries a
	// fragment, which OAuth 2.0 forbids (RFC 6749 §3.1.2).
	ErrRedirectURIFragment = errors.New("clients: redirect_uri must not contain a fragment")
	// ErrUnsupportedGrantType is returned for a grant_type Harbor does not issue.
	ErrUnsupportedGrantType = errors.New("clients: unsupported grant_type")
	// ErrUnsupportedResponseType is returned for a response_type Harbor does not support.
	ErrUnsupportedResponseType = errors.New("clients: unsupported response_type")
	// ErrUnsupportedAuthMethod is returned for a token_endpoint_auth_method Harbor rejects.
	ErrUnsupportedAuthMethod = errors.New("clients: unsupported token_endpoint_auth_method")
)

// allowedGrantTypes is the set of grant types Harbor can issue. Harbor is an
// authorization-code + refresh-token provider (docs/DESIGN.md §3.1, §3.5);
// implicit / password / client_credentials are intentionally unsupported.
var allowedGrantTypes = map[string]bool{
	"authorization_code": true,
	"refresh_token":      true,
}

// allowedResponseTypes is the set of response types Harbor supports. Only
// "code" — Harbor is authorization-code-only (PKCE-protected; docs/DESIGN.md
// §3.1, §11.7). The implicit flow ("token") is deliberately excluded.
var allowedResponseTypes = map[string]bool{
	"code": true,
}

// allowedAuthMethods is the set of token-endpoint client authentication
// methods Harbor accepts (RFC 7591 §2). "none" is for public clients
// (PKCE-protected).
var allowedAuthMethods = map[string]bool{
	"client_secret_basic": true,
	"client_secret_post":  true,
	"none":                true,
}

// ValidateRedirectURIs requires at least one redirect_uri and validates each
// one. The exact-match invariant Harbor enforces at /authorize (see
// oidc.Client.HasRedirectURI) means we must store precisely what the client
// registers — so we reject anything that could never match safely (non-HTTPS
// non-loopback, fragments, relative URIs) at registration time.
func ValidateRedirectURIs(uris []string) error {
	if len(uris) == 0 {
		return ErrNoRedirectURIs
	}
	for _, u := range uris {
		if err := validateRedirectURI(u); err != nil {
			return err
		}
	}
	return nil
}

// validateRedirectURI enforces the per-URI rules: absolute URI, no fragment,
// and https-only except for loopback hosts (RFC 8252 §7.3).
func validateRedirectURI(raw string) error {
	if raw == "" {
		return ErrRedirectURIInvalid
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ErrRedirectURIInvalid
	}
	// Must be absolute with a scheme and host. A relative URI, or one missing
	// the authority (e.g. "https:///cb"), can never be exact-matched safely.
	if !u.IsAbs() || u.Host == "" {
		return ErrRedirectURIInvalid
	}
	// No fragment allowed (RFC 6749 §3.1.2). url.Parse strips a trailing "#"
	// into an empty Fragment, so also guard the raw string for a bare "#".
	if u.Fragment != "" || strings.Contains(raw, "#") {
		return ErrRedirectURIFragment
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if isLoopbackHost(u.Hostname()) {
			return nil
		}
		return ErrRedirectURINotHTTPS
	default:
		return ErrRedirectURINotHTTPS
	}
}

// isLoopbackHost reports whether host is a loopback destination for which
// RFC 8252 permits plain http: the literal "localhost", or any IP in the
// loopback range (127.0.0.0/8 or ::1).
func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// ValidateGrantTypes accepts an empty list (the caller applies the RFC 7591
// default of ["authorization_code"]) and otherwise requires every entry to be
// a grant type Harbor can issue.
func ValidateGrantTypes(grantTypes []string) error {
	for _, gt := range grantTypes {
		if !allowedGrantTypes[gt] {
			return ErrUnsupportedGrantType
		}
	}
	return nil
}

// ValidateResponseTypes accepts an empty list (default ["code"]) and
// otherwise requires every entry to be a response type Harbor supports.
func ValidateResponseTypes(responseTypes []string) error {
	for _, rt := range responseTypes {
		if !allowedResponseTypes[rt] {
			return ErrUnsupportedResponseType
		}
	}
	return nil
}

// ValidateTokenEndpointAuthMethod accepts the empty string (default
// "client_secret_basic") and otherwise requires a method Harbor accepts.
func ValidateTokenEndpointAuthMethod(method string) error {
	if method == "" {
		return nil
	}
	if !allowedAuthMethods[method] {
		return ErrUnsupportedAuthMethod
	}
	return nil
}
