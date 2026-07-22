package mgmtapi

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net"
	"net/url"
	"strings"
)

// RFC 7591/7592 client-metadata validation and credential helpers. Everything
// in this file is PURE (no DB, no clock, no network) so it is exhaustively
// table-testable and safe to call from the /register hot path. The HTTP handler
// (later task) parses the request body, calls ValidateClientMetadata, then mints
// and hashes credentials here before handing the sealed record to
// clients.DBClientRegistrationStore.

// Validation errors. These are sentinels so the handler can map each to the
// RFC 7591 §3.2.2 error code (invalid_redirect_uri / invalid_client_metadata)
// without string matching.
var (
	// ErrNoRedirectURIs is returned when a registration omits redirect_uris.
	// At least one is required — Harbor only supports the authorization-code
	// flow, which is a redirect flow (docs/DESIGN.md §3.1).
	ErrNoRedirectURIs = errors.New("mgmtapi: at least one redirect_uri is required")
	// ErrRedirectURIInvalid is returned for a malformed or non-absolute URI.
	ErrRedirectURIInvalid = errors.New("mgmtapi: redirect_uri is not a valid absolute URI")
	// ErrRedirectURINotHTTPS is returned for a non-HTTPS URI whose host is not
	// a loopback address (RFC 8252 §7.3 allows http only for loopback).
	ErrRedirectURINotHTTPS = errors.New("mgmtapi: redirect_uri must use https (http allowed only for loopback)")
	// ErrRedirectURIFragment is returned when a redirect_uri carries a fragment,
	// which OAuth 2.0 forbids (RFC 6749 §3.1.2).
	ErrRedirectURIFragment = errors.New("mgmtapi: redirect_uri must not contain a fragment")
	// ErrUnsupportedGrantType is returned for a grant_type Harbor does not issue.
	ErrUnsupportedGrantType = errors.New("mgmtapi: unsupported grant_type")
	// ErrUnsupportedResponseType is returned for a response_type Harbor does not support.
	ErrUnsupportedResponseType = errors.New("mgmtapi: unsupported response_type")
	// ErrUnsupportedAuthMethod is returned for a token_endpoint_auth_method Harbor rejects.
	ErrUnsupportedAuthMethod = errors.New("mgmtapi: unsupported token_endpoint_auth_method")
)

// ClientMetadata is the subset of RFC 7591 §2 registration request fields that
// Harbor validates. It is populated by the handler from the JSON request body.
// Empty grant_types / response_types / token_endpoint_auth_method mean "use the
// RFC 7591 default" and pass validation; the handler applies the defaults.
type ClientMetadata struct {
	RedirectURIs            []string
	GrantTypes              []string
	ResponseTypes           []string
	TokenEndpointAuthMethod string
	Scopes                  []string
	ClientName              string
}

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

// allowedAuthMethods is the set of token-endpoint client authentication methods
// Harbor accepts (RFC 7591 §2). "none" is for public clients (PKCE-protected).
var allowedAuthMethods = map[string]bool{
	"client_secret_basic": true,
	"client_secret_post":  true,
	"none":                true,
}

// ValidateClientMetadata runs every metadata check and returns the first
// failure. It is the single entry point the handler calls; the individual
// Validate* functions are exported so tests (and future callers) can exercise
// each rule in isolation.
func ValidateClientMetadata(m ClientMetadata) error {
	if err := ValidateRedirectURIs(m.RedirectURIs); err != nil {
		return err
	}
	if err := ValidateGrantTypes(m.GrantTypes); err != nil {
		return err
	}
	if err := ValidateResponseTypes(m.ResponseTypes); err != nil {
		return err
	}
	if err := ValidateTokenEndpointAuthMethod(m.TokenEndpointAuthMethod); err != nil {
		return err
	}
	return nil
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

// ValidateGrantTypes accepts an empty list (the handler applies the RFC 7591
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

// ValidateResponseTypes accepts an empty list (default ["code"]) and otherwise
// requires every entry to be a response type Harbor supports.
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

// Credential byte lengths. All credentials are high-entropy random tokens, so a
// plain SHA-256 (see HashSecret) is the correct storage transform — Argon2id is
// for LOW-entropy human passwords and would add a non-deterministic salt that
// defeats table-driven testing and O(1) hash lookup.
const (
	// clientIDBytes is the raw entropy behind a minted client_id (128-bit).
	clientIDBytes = 16
	// clientSecretBytes is the raw entropy behind a client_secret (256-bit).
	clientSecretBytes = 32
	// regTokenBytes is the raw entropy behind a registration_access_token (256-bit).
	regTokenBytes = 32
)

// ClientCredentials holds the freshly-minted PLAINTEXT credentials for a new
// registration. They are returned to the client exactly once (in the POST
// /register response); only their hashes (HashSecret) are persisted. Do not log
// or store the plaintext fields.
type ClientCredentials struct {
	ClientID                string
	ClientSecret            string
	RegistrationAccessToken string
}

// MintClientCredentials generates a client_id, client_secret, and
// registration_access_token in one call. Any failure of the system CSPRNG is
// returned (the caller must fail the registration — never fall back to weak
// randomness).
func MintClientCredentials() (ClientCredentials, error) {
	clientID, err := randToken(clientIDBytes)
	if err != nil {
		return ClientCredentials{}, err
	}
	secret, err := randToken(clientSecretBytes)
	if err != nil {
		return ClientCredentials{}, err
	}
	regToken, err := randToken(regTokenBytes)
	if err != nil {
		return ClientCredentials{}, err
	}
	return ClientCredentials{
		ClientID:                clientID,
		ClientSecret:            secret,
		RegistrationAccessToken: regToken,
	}, nil
}

// MintClientID returns a fresh 128-bit URL-safe client_id.
func MintClientID() (string, error) { return randToken(clientIDBytes) }

// MintClientSecret returns a fresh 256-bit URL-safe client_secret.
func MintClientSecret() (string, error) { return randToken(clientSecretBytes) }

// MintRegistrationAccessToken returns a fresh 256-bit URL-safe RFC 7592
// registration access token.
func MintRegistrationAccessToken() (string, error) { return randToken(regTokenBytes) }

// HashSecret returns the SHA-256 of a credential for storage/comparison. It is
// PURE and deterministic, matching clients.DBClientRegistrationStore.VerifyRegToken
// (which hashes the presented token the same way). Both the client_secret and
// the registration_access_token are hashed with this function before they touch
// the database — the plaintext is never persisted.
func HashSecret(secret string) []byte {
	sum := sha256.Sum256([]byte(secret))
	return sum[:]
}

// randToken returns n bytes of CSPRNG output encoded as unpadded base64url.
func randToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
