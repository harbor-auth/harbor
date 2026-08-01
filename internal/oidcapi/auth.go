package oidcapi

import (
	"context"
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/harbor-auth/harbor/internal/oidc"
)

// ClientCredentials holds the extracted client_id and client_secret from
// HTTP Basic authentication. Used for /introspect and future /revoke endpoints.
type ClientCredentials struct {
	ClientID     string
	ClientSecret string
}

// validateClientCredentials is retained for package callers and delegates to
// the shared authenticator. Introspection and revocation require Basic auth.
func validateClientCredentials(ctx context.Context, registry oidc.ClientRegistry, clientID, secret string) (oidc.Client, bool) {
	return oidc.AuthenticateClient(ctx, registry, clientID, oidc.ClientAuthSecretBasic, secret)
}

// parseBasicAuth extracts client_id and client_secret from an HTTP Basic
// Authorization header. Returns (credentials, true) on success, or
// (ClientCredentials{}, false) if the header is missing, malformed, or not
// Basic auth.
//
// Per RFC 7617, the credentials are base64-encoded as "client_id:client_secret".
func parseBasicAuth(r *http.Request) (ClientCredentials, bool) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return ClientCredentials{}, false
	}

	// Check for "Basic " prefix (case-insensitive per RFC 7235)
	const prefix = "basic "
	if len(auth) <= len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
		return ClientCredentials{}, false
	}

	// Decode base64 credentials
	encoded := strings.TrimSpace(auth[len(prefix):])
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return ClientCredentials{}, false
	}

	// Split on first colon (client_secret may contain colons)
	creds := string(decoded)
	idx := strings.IndexByte(creds, ':')
	if idx < 0 {
		return ClientCredentials{}, false
	}

	clientID := creds[:idx]
	clientSecret := creds[idx+1:]

	// Empty client_id is invalid
	if clientID == "" {
		return ClientCredentials{}, false
	}

	return ClientCredentials{
		ClientID:     clientID,
		ClientSecret: clientSecret,
	}, true
}
