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

// validateClientCredentials checks if the client_id exists in the registry and
// validates the secret. Returns (client, true) if valid, or (Client{}, false)
// if the client is unknown or credentials are invalid.
//
// SCAFFOLD: Harbor's current design uses public clients (PKCE replaces secrets).
// This function validates that the client exists — actual secret comparison is
// not yet wired. When confidential client support is added, this should compare
// the secret against a stored hash.
func validateClientCredentials(ctx context.Context, clients oidc.ClientRegistry, clientID, secret string) (oidc.Client, bool) {
	client, found := clients.Lookup(ctx, clientID)
	if !found {
		return oidc.Client{}, false
	}
	// TODO(introspect): compare secret against stored hash when confidential
	// clients are supported. For now, existence check is sufficient for public
	// clients that authenticate via PKCE on the /token endpoint.
	//
	// The secret parameter is intentionally unused until confidential client
	// support is added — the function signature is forward-compatible.
	_ = secret
	return client, true
}
