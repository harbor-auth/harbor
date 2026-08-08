package mgmtapi

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"

	"github.com/harbor-auth/harbor/internal/clients"
)

// RFC 7591/7592 client-metadata validation and credential helpers. Credential
// minting/hashing is PURE (no DB, no clock, no network) so it is exhaustively
// table-testable and safe to call from the /register hot path. The HTTP
// handler parses the request body, calls ValidateClientMetadata, then mints
// and hashes credentials here before handing the sealed record to
// clients.DBClientRegistrationStore.
//
// The metadata validation rules themselves (ValidateRedirectURIs and
// friends) live in internal/clients/validate.go — cloudapi's namespace-scoped
// client provisioning needs the exact same rules and must not import mgmtapi
// (see that file's doc comment). These are thin delegating wrappers so this
// package's exported API, and its tests, are unchanged.

// Validation errors. These are sentinels so the handler can map each to the
// RFC 7591 §3.2.2 error code (invalid_redirect_uri / invalid_client_metadata)
// without string matching. Aliased from internal/clients so errors.Is works
// identically whether the caller imports mgmtapi or clients.
var (
	// ErrNoRedirectURIs is returned when a registration omits redirect_uris.
	// At least one is required — Harbor only supports the authorization-code
	// flow, which is a redirect flow (docs/DESIGN.md §3.1).
	ErrNoRedirectURIs = clients.ErrNoRedirectURIs
	// ErrRedirectURIInvalid is returned for a malformed or non-absolute URI.
	ErrRedirectURIInvalid = clients.ErrRedirectURIInvalid
	// ErrRedirectURINotHTTPS is returned for a non-HTTPS URI whose host is not
	// a loopback address (RFC 8252 §7.3 allows http only for loopback).
	ErrRedirectURINotHTTPS = clients.ErrRedirectURINotHTTPS
	// ErrRedirectURIFragment is returned when a redirect_uri carries a fragment,
	// which OAuth 2.0 forbids (RFC 6749 §3.1.2).
	ErrRedirectURIFragment = clients.ErrRedirectURIFragment
	// ErrUnsupportedGrantType is returned for a grant_type Harbor does not issue.
	ErrUnsupportedGrantType = clients.ErrUnsupportedGrantType
	// ErrUnsupportedResponseType is returned for a response_type Harbor does not support.
	ErrUnsupportedResponseType = clients.ErrUnsupportedResponseType
	// ErrUnsupportedAuthMethod is returned for a token_endpoint_auth_method Harbor rejects.
	ErrUnsupportedAuthMethod = clients.ErrUnsupportedAuthMethod
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

// ValidateRedirectURIs delegates to internal/clients.ValidateRedirectURIs —
// see this file's doc comment for why the rule lives there.
func ValidateRedirectURIs(uris []string) error {
	return clients.ValidateRedirectURIs(uris)
}

// ValidateGrantTypes delegates to internal/clients.ValidateGrantTypes.
func ValidateGrantTypes(grantTypes []string) error {
	return clients.ValidateGrantTypes(grantTypes)
}

// ValidateResponseTypes delegates to internal/clients.ValidateResponseTypes.
func ValidateResponseTypes(responseTypes []string) error {
	return clients.ValidateResponseTypes(responseTypes)
}

// ValidateTokenEndpointAuthMethod delegates to
// internal/clients.ValidateTokenEndpointAuthMethod.
func ValidateTokenEndpointAuthMethod(method string) error {
	return clients.ValidateTokenEndpointAuthMethod(method)
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
