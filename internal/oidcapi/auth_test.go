package oidcapi

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/harbor/harbor/internal/oidc"
)

// TestParseBasicAuthValid verifies correct extraction of client_id and secret.
func TestParseBasicAuthValid(t *testing.T) {
	tests := []struct {
		name       string
		clientID   string
		secret     string
		wantID     string
		wantSecret string
	}{
		{
			name:       "simple credentials",
			clientID:   "demo-client",
			secret:     "s3cr3t",
			wantID:     "demo-client",
			wantSecret: "s3cr3t",
		},
		{
			name:       "secret with colons",
			clientID:   "client-a",
			secret:     "pass:word:with:colons",
			wantID:     "client-a",
			wantSecret: "pass:word:with:colons",
		},
		{
			name:       "empty secret",
			clientID:   "public-client",
			secret:     "",
			wantID:     "public-client",
			wantSecret: "",
		},
		{
			name:       "unicode characters",
			clientID:   "client-unicode",
			secret:     "пароль密码",
			wantID:     "client-unicode",
			wantSecret: "пароль密码",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/introspect", nil)
			creds := tt.clientID + ":" + tt.secret
			r.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(creds)))

			got, ok := parseBasicAuth(r)
			if !ok {
				t.Fatal("expected parseBasicAuth to succeed")
			}
			if got.ClientID != tt.wantID {
				t.Errorf("ClientID = %q, want %q", got.ClientID, tt.wantID)
			}
			if got.ClientSecret != tt.wantSecret {
				t.Errorf("ClientSecret = %q, want %q", got.ClientSecret, tt.wantSecret)
			}
		})
	}
}

// TestParseBasicAuthCaseInsensitive verifies Basic prefix is case-insensitive.
func TestParseBasicAuthCaseInsensitive(t *testing.T) {
	prefixes := []string{"Basic", "basic", "BASIC", "BaSiC"}
	for _, prefix := range prefixes {
		t.Run(prefix, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/introspect", nil)
			creds := base64.StdEncoding.EncodeToString([]byte("client:secret"))
			r.Header.Set("Authorization", prefix+" "+creds)

			got, ok := parseBasicAuth(r)
			if !ok {
				t.Fatalf("expected parseBasicAuth to succeed with prefix %q", prefix)
			}
			if got.ClientID != "client" {
				t.Errorf("ClientID = %q, want %q", got.ClientID, "client")
			}
		})
	}
}

// TestParseBasicAuthMissing verifies behavior when Authorization header is absent.
func TestParseBasicAuthMissing(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/introspect", nil)
	// No Authorization header set

	_, ok := parseBasicAuth(r)
	if ok {
		t.Fatal("expected parseBasicAuth to fail when Authorization header is missing")
	}
}

// TestParseBasicAuthMalformed verifies various malformed headers are rejected.
func TestParseBasicAuthMalformed(t *testing.T) {
	tests := []struct {
		name   string
		header string
	}{
		{
			name:   "empty header",
			header: "",
		},
		{
			name:   "bearer token instead of basic",
			header: "Bearer eyJhbGciOiJIUzI1NiJ9.e30.ZRrHA1JJJW8opsbCGfG_HACGpVUMN_a9IV7pAx_Zmeo",
		},
		{
			name:   "digest auth",
			header: "Digest username=\"user\"",
		},
		{
			name:   "basic without space",
			header: "BasicdGVzdDpzZWNyZXQ=",
		},
		{
			name:   "basic with invalid base64",
			header: "Basic not-valid-base64!!!",
		},
		{
			name:   "basic without colon in decoded",
			header: "Basic " + base64.StdEncoding.EncodeToString([]byte("no-colon-here")),
		},
		{
			name:   "basic with empty client_id",
			header: "Basic " + base64.StdEncoding.EncodeToString([]byte(":secret")),
		},
		{
			name:   "just Basic prefix",
			header: "Basic ",
		},
		{
			name:   "just Basic word",
			header: "Basic",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/introspect", nil)
			if tt.header != "" {
				r.Header.Set("Authorization", tt.header)
			}

			_, ok := parseBasicAuth(r)
			if ok {
				t.Fatalf("expected parseBasicAuth to fail for header %q", tt.header)
			}
		})
	}
}

// --- validateClientCredentials tests ---

// mockClientRegistry implements oidc.ClientRegistry for testing.
type mockClientRegistry struct {
	clients map[string]oidc.Client
}

func (m *mockClientRegistry) Lookup(_ context.Context, clientID string) (oidc.Client, bool) {
	c, ok := m.clients[clientID]
	return c, ok
}

// TestValidateClientCredentialsValid verifies a known client is accepted.
func TestValidateClientCredentialsValid(t *testing.T) {
	registry := &mockClientRegistry{
		clients: map[string]oidc.Client{
			"demo-client": {ID: "demo-client", SectorID: "example.com"},
			"other-client": {ID: "other-client", SectorID: "other.com"},
		},
	}

	client, ok := validateClientCredentials(context.Background(), registry, "demo-client", "any-secret")
	if !ok {
		t.Fatal("expected validateClientCredentials to succeed for known client")
	}
	if client.ID != "demo-client" {
		t.Errorf("client.ID = %q, want %q", client.ID, "demo-client")
	}
	if client.SectorID != "example.com" {
		t.Errorf("client.SectorID = %q, want %q", client.SectorID, "example.com")
	}
}

// TestValidateClientCredentialsUnknown verifies an unknown client is rejected.
func TestValidateClientCredentialsUnknown(t *testing.T) {
	registry := &mockClientRegistry{
		clients: map[string]oidc.Client{
			"demo-client": {ID: "demo-client"},
		},
	}

	_, ok := validateClientCredentials(context.Background(), registry, "unknown-client", "secret")
	if ok {
		t.Fatal("expected validateClientCredentials to fail for unknown client")
	}
}

// TestValidateClientCredentialsEmptyRegistry verifies behavior with no clients.
func TestValidateClientCredentialsEmptyRegistry(t *testing.T) {
	registry := &mockClientRegistry{
		clients: map[string]oidc.Client{},
	}

	_, ok := validateClientCredentials(context.Background(), registry, "any-client", "secret")
	if ok {
		t.Fatal("expected validateClientCredentials to fail with empty registry")
	}
}

// TestValidateClientCredentialsSecretIgnored verifies the secret is currently
// ignored (public client model). This test documents current behavior and will
// need updating when confidential client support is added.
func TestValidateClientCredentialsSecretIgnored(t *testing.T) {
	registry := &mockClientRegistry{
		clients: map[string]oidc.Client{
			"demo-client": {ID: "demo-client"},
		},
	}

	// All these should succeed since secret is currently unused
	secrets := []string{"", "wrong-secret", "correct-secret", "any-value"}
	for _, secret := range secrets {
		t.Run("secret="+secret, func(t *testing.T) {
			_, ok := validateClientCredentials(context.Background(), registry, "demo-client", secret)
			if !ok {
				t.Fatalf("expected validateClientCredentials to succeed regardless of secret %q", secret)
			}
		})
	}
}

// TestValidateClientCredentialsReturnsFullClient verifies the full client
// struct is returned, not just a boolean.
func TestValidateClientCredentialsReturnsFullClient(t *testing.T) {
	registry := &mockClientRegistry{
		clients: map[string]oidc.Client{
			"full-client": {
				ID:            "full-client",
				SectorID:      "sector.example.com",
				ScopesAllowed: []string{"openid", "profile", "email"},
			},
		},
	}

	client, ok := validateClientCredentials(context.Background(), registry, "full-client", "secret")
	if !ok {
		t.Fatal("expected validateClientCredentials to succeed")
	}
	if client.ID != "full-client" {
		t.Errorf("client.ID = %q, want %q", client.ID, "full-client")
	}
	if client.SectorID != "sector.example.com" {
		t.Errorf("client.SectorID = %q, want %q", client.SectorID, "sector.example.com")
	}
	if len(client.ScopesAllowed) != 3 {
		t.Errorf("len(client.ScopesAllowed) = %d, want 3", len(client.ScopesAllowed))
	}
}
