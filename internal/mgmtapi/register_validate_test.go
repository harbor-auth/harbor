package mgmtapi

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"
)

func TestValidateRedirectURIs(t *testing.T) {
	tests := []struct {
		name    string
		uris    []string
		wantErr error
	}{
		{name: "nil list", uris: nil, wantErr: ErrNoRedirectURIs},
		{name: "empty list", uris: []string{}, wantErr: ErrNoRedirectURIs},
		{name: "single https", uris: []string{"https://rp.example.com/cb"}, wantErr: nil},
		{name: "multiple https", uris: []string{"https://a.example.com/cb", "https://b.example.com/cb"}, wantErr: nil},
		{name: "https with port and path", uris: []string{"https://rp.example.com:8443/oauth/callback"}, wantErr: nil},
		{name: "http loopback ipv4", uris: []string{"http://127.0.0.1:1234/cb"}, wantErr: nil},
		{name: "http loopback range", uris: []string{"http://127.0.0.53/cb"}, wantErr: nil},
		{name: "http localhost", uris: []string{"http://localhost:9000/cb"}, wantErr: nil},
		{name: "http loopback ipv6", uris: []string{"http://[::1]:8080/cb"}, wantErr: nil},
		{name: "http non-loopback rejected", uris: []string{"http://rp.example.com/cb"}, wantErr: ErrRedirectURINotHTTPS},
		{name: "http public ip rejected", uris: []string{"http://8.8.8.8/cb"}, wantErr: ErrRedirectURINotHTTPS},
		{name: "custom scheme rejected", uris: []string{"myapp://cb"}, wantErr: ErrRedirectURINotHTTPS},
		{name: "fragment rejected", uris: []string{"https://rp.example.com/cb#section"}, wantErr: ErrRedirectURIFragment},
		{name: "bare fragment rejected", uris: []string{"https://rp.example.com/cb#"}, wantErr: ErrRedirectURIFragment},
		{name: "relative uri rejected", uris: []string{"/callback"}, wantErr: ErrRedirectURIInvalid},
		{name: "missing host rejected", uris: []string{"https:///cb"}, wantErr: ErrRedirectURIInvalid},
		{name: "empty string rejected", uris: []string{""}, wantErr: ErrRedirectURIInvalid},
		{name: "one bad among good", uris: []string{"https://ok.example.com/cb", "http://bad.example.com/cb"}, wantErr: ErrRedirectURINotHTTPS},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRedirectURIs(tt.uris)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("ValidateRedirectURIs(%v) = %v, want %v", tt.uris, err, tt.wantErr)
			}
		})
	}
}

func TestValidateGrantTypes(t *testing.T) {
	tests := []struct {
		name    string
		grants  []string
		wantErr error
	}{
		{name: "empty defaults ok", grants: nil, wantErr: nil},
		{name: "authorization_code", grants: []string{"authorization_code"}, wantErr: nil},
		{name: "refresh_token", grants: []string{"refresh_token"}, wantErr: nil},
		{name: "both supported", grants: []string{"authorization_code", "refresh_token"}, wantErr: nil},
		{name: "implicit rejected", grants: []string{"implicit"}, wantErr: ErrUnsupportedGrantType},
		{name: "password rejected", grants: []string{"password"}, wantErr: ErrUnsupportedGrantType},
		{name: "client_credentials rejected", grants: []string{"client_credentials"}, wantErr: ErrUnsupportedGrantType},
		{name: "one bad among good", grants: []string{"authorization_code", "implicit"}, wantErr: ErrUnsupportedGrantType},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateGrantTypes(tt.grants)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("ValidateGrantTypes(%v) = %v, want %v", tt.grants, err, tt.wantErr)
			}
		})
	}
}

func TestValidateResponseTypes(t *testing.T) {
	tests := []struct {
		name    string
		types   []string
		wantErr error
	}{
		{name: "empty defaults ok", types: nil, wantErr: nil},
		{name: "code", types: []string{"code"}, wantErr: nil},
		{name: "token rejected", types: []string{"token"}, wantErr: ErrUnsupportedResponseType},
		{name: "id_token rejected", types: []string{"id_token"}, wantErr: ErrUnsupportedResponseType},
		{name: "one bad among good", types: []string{"code", "token"}, wantErr: ErrUnsupportedResponseType},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateResponseTypes(tt.types)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("ValidateResponseTypes(%v) = %v, want %v", tt.types, err, tt.wantErr)
			}
		})
	}
}

func TestValidateTokenEndpointAuthMethod(t *testing.T) {
	tests := []struct {
		name    string
		method  string
		wantErr error
	}{
		{name: "empty defaults ok", method: "", wantErr: nil},
		{name: "client_secret_basic", method: "client_secret_basic", wantErr: nil},
		{name: "client_secret_post", method: "client_secret_post", wantErr: nil},
		{name: "none", method: "none", wantErr: nil},
		{name: "private_key_jwt rejected", method: "private_key_jwt", wantErr: ErrUnsupportedAuthMethod},
		{name: "tls_client_auth rejected", method: "tls_client_auth", wantErr: ErrUnsupportedAuthMethod},
		{name: "garbage rejected", method: "nonsense", wantErr: ErrUnsupportedAuthMethod},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateTokenEndpointAuthMethod(tt.method)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("ValidateTokenEndpointAuthMethod(%q) = %v, want %v", tt.method, err, tt.wantErr)
			}
		})
	}
}

func TestValidateClientMetadata(t *testing.T) {
	tests := []struct {
		name    string
		meta    ClientMetadata
		wantErr error
	}{
		{
			name: "full valid metadata",
			meta: ClientMetadata{
				RedirectURIs:            []string{"https://rp.example.com/cb"},
				GrantTypes:              []string{"authorization_code", "refresh_token"},
				ResponseTypes:           []string{"code"},
				TokenEndpointAuthMethod: "client_secret_basic",
				ClientName:              "My App",
			},
			wantErr: nil,
		},
		{
			name:    "minimal valid metadata (defaults)",
			meta:    ClientMetadata{RedirectURIs: []string{"https://rp.example.com/cb"}},
			wantErr: nil,
		},
		{
			name:    "missing redirect uris",
			meta:    ClientMetadata{GrantTypes: []string{"authorization_code"}},
			wantErr: ErrNoRedirectURIs,
		},
		{
			name:    "bad redirect uri wins over other fields",
			meta:    ClientMetadata{RedirectURIs: []string{"http://rp.example.com/cb"}, GrantTypes: []string{"implicit"}},
			wantErr: ErrRedirectURINotHTTPS,
		},
		{
			name:    "bad grant type",
			meta:    ClientMetadata{RedirectURIs: []string{"https://rp.example.com/cb"}, GrantTypes: []string{"implicit"}},
			wantErr: ErrUnsupportedGrantType,
		},
		{
			name:    "bad response type",
			meta:    ClientMetadata{RedirectURIs: []string{"https://rp.example.com/cb"}, ResponseTypes: []string{"token"}},
			wantErr: ErrUnsupportedResponseType,
		},
		{
			name:    "bad auth method",
			meta:    ClientMetadata{RedirectURIs: []string{"https://rp.example.com/cb"}, TokenEndpointAuthMethod: "private_key_jwt"},
			wantErr: ErrUnsupportedAuthMethod,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateClientMetadata(tt.meta)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("ValidateClientMetadata() = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestMintClientCredentials(t *testing.T) {
	creds, err := MintClientCredentials()
	if err != nil {
		t.Fatalf("MintClientCredentials() error = %v", err)
	}

	// All three must be present and distinct.
	if creds.ClientID == "" || creds.ClientSecret == "" || creds.RegistrationAccessToken == "" {
		t.Fatalf("minted empty credential: %+v", creds)
	}
	if creds.ClientID == creds.ClientSecret || creds.ClientID == creds.RegistrationAccessToken || creds.ClientSecret == creds.RegistrationAccessToken {
		t.Errorf("credentials must be distinct: %+v", creds)
	}

	// Each must decode to the expected byte length.
	assertTokenBytes(t, "client_id", creds.ClientID, clientIDBytes)
	assertTokenBytes(t, "client_secret", creds.ClientSecret, clientSecretBytes)
	assertTokenBytes(t, "registration_access_token", creds.RegistrationAccessToken, regTokenBytes)
}

func TestMintCredentialsAreUnique(t *testing.T) {
	// Two independent mints must not collide (sanity check on the CSPRNG usage).
	a, err := MintClientCredentials()
	if err != nil {
		t.Fatalf("mint a: %v", err)
	}
	b, err := MintClientCredentials()
	if err != nil {
		t.Fatalf("mint b: %v", err)
	}
	if a.ClientID == b.ClientID {
		t.Error("client_id collided across mints")
	}
	if a.ClientSecret == b.ClientSecret {
		t.Error("client_secret collided across mints")
	}
	if a.RegistrationAccessToken == b.RegistrationAccessToken {
		t.Error("registration_access_token collided across mints")
	}
}

func TestMintIndividualHelpers(t *testing.T) {
	tests := []struct {
		name      string
		mint      func() (string, error)
		wantBytes int
	}{
		{name: "MintClientID", mint: MintClientID, wantBytes: clientIDBytes},
		{name: "MintClientSecret", mint: MintClientSecret, wantBytes: clientSecretBytes},
		{name: "MintRegistrationAccessToken", mint: MintRegistrationAccessToken, wantBytes: regTokenBytes},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := tt.mint()
			if err != nil {
				t.Fatalf("%s() error = %v", tt.name, err)
			}
			assertTokenBytes(t, tt.name, v, tt.wantBytes)
		})
	}
}

func TestHashSecret(t *testing.T) {
	tests := []struct {
		name   string
		secret string
	}{
		{name: "typical secret", secret: "s3cr3t-token-value"},
		{name: "empty string", secret: ""},
		{name: "unicode", secret: "héllo-wörld-🔒"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := HashSecret(tt.secret)

			// SHA-256 output is always 32 bytes.
			if len(got) != sha256.Size {
				t.Errorf("HashSecret len = %d, want %d", len(got), sha256.Size)
			}
			// Deterministic: same input → same output.
			if again := HashSecret(tt.secret); !bytes.Equal(got, again) {
				t.Error("HashSecret is not deterministic")
			}
			// Matches a direct sha256.Sum256 (so it interops with VerifyRegToken).
			want := sha256.Sum256([]byte(tt.secret))
			if !bytes.Equal(got, want[:]) {
				t.Error("HashSecret does not match sha256.Sum256")
			}
		})
	}
}

func TestHashSecretDistinctInputs(t *testing.T) {
	if bytes.Equal(HashSecret("a"), HashSecret("b")) {
		t.Error("distinct inputs produced identical hashes")
	}
}

// assertTokenBytes decodes a base64url token and asserts its raw byte length.
func assertTokenBytes(t *testing.T, name, token string, wantBytes int) {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		t.Fatalf("%s: not valid base64url: %v", name, err)
	}
	if len(raw) != wantBytes {
		t.Errorf("%s: decoded to %d bytes, want %d", name, len(raw), wantBytes)
	}
}
