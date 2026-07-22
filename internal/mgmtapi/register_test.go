package mgmtapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/harbor-auth/harbor/internal/clients"
)

const testRegBaseURL = "https://mgmt.example.com"

// fakeClientReg is an in-memory ClientRegistrationStore for handler tests. It
// echoes the created record back as the stored RegisteredClient (mirroring the
// RETURNING * of the real CreateRegisteredClient query).
type fakeClientReg struct {
	created clients.NewRegisteredClient
	err     error
	called  bool
}

func (f *fakeClientReg) Create(_ context.Context, c clients.NewRegisteredClient) (clients.RegisteredClient, error) {
	f.called = true
	f.created = c
	if f.err != nil {
		return clients.RegisteredClient{}, f.err
	}
	return clients.RegisteredClient{
		ClientID:                c.ClientID,
		Name:                    c.Name,
		SectorID:                c.SectorID,
		RedirectURIs:            c.RedirectURIs,
		TokenFormat:             c.TokenFormat,
		ScopesAllowed:           c.ScopesAllowed,
		ClientSecretHash:        c.ClientSecretHash,
		GrantTypes:              c.GrantTypes,
		ResponseTypes:           c.ResponseTypes,
		TokenEndpointAuthMethod: c.TokenEndpointAuthMethod,
		CreatedAt:               c.CreatedAt,
	}, nil
}

func newRegServer(store ClientRegistrationStore) *Server {
	return New(nil, nil).WithClientRegistration(store, testRegBaseURL)
}

func doRegister(t *testing.T, s *Server, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(body))
	rec := httptest.NewRecorder()
	s.PostRegister(rec, req)
	return rec
}

func decodeRegisterResponse(t *testing.T, rec *httptest.ResponseRecorder) registerResponse {
	t.Helper()
	var resp registerResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v; body=%s", err, rec.Body.String())
	}
	return resp
}

func decodeRegisterError(t *testing.T, rec *httptest.ResponseRecorder) errorResponse {
	t.Helper()
	var er errorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &er); err != nil {
		t.Fatalf("decode error: %v; body=%s", err, rec.Body.String())
	}
	return er
}

func TestPostRegisterConfidentialSuccess(t *testing.T) {
	fake := &fakeClientReg{}
	s := newRegServer(fake)

	rec := doRegister(t, s, `{
		"redirect_uris": ["https://rp.example.com/cb"],
		"client_name": "My App",
		"scope": "openid profile"
	}`)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	if !fake.called {
		t.Fatal("expected Create to be called")
	}
	resp := decodeRegisterResponse(t, rec)

	if resp.ClientID == "" {
		t.Error("client_id must be present")
	}
	if resp.ClientSecret == "" {
		t.Error("client_secret must be present for a confidential client")
	}
	if resp.RegistrationAccessToken == "" {
		t.Error("registration_access_token must be present")
	}
	if resp.ClientSecretExpiresAt == nil || *resp.ClientSecretExpiresAt != 0 {
		t.Errorf("client_secret_expires_at = %v, want pointer to 0", resp.ClientSecretExpiresAt)
	}
	wantURI := testRegBaseURL + "/register/" + resp.ClientID
	if resp.RegistrationClientURI != wantURI {
		t.Errorf("registration_client_uri = %q, want %q", resp.RegistrationClientURI, wantURI)
	}
	if resp.ClientIDIssuedAt == 0 {
		t.Error("client_id_issued_at must be set")
	}

	// Defaults applied.
	if len(resp.GrantTypes) != 1 || resp.GrantTypes[0] != defaultGrantType {
		t.Errorf("grant_types = %v, want [%q]", resp.GrantTypes, defaultGrantType)
	}
	if len(resp.ResponseTypes) != 1 || resp.ResponseTypes[0] != defaultResponseType {
		t.Errorf("response_types = %v, want [%q]", resp.ResponseTypes, defaultResponseType)
	}
	if resp.TokenEndpointAuthMethod != defaultAuthMethod {
		t.Errorf("token_endpoint_auth_method = %q, want %q", resp.TokenEndpointAuthMethod, defaultAuthMethod)
	}
	if resp.Scope != "openid profile" {
		t.Errorf("scope = %q, want %q", resp.Scope, "openid profile")
	}

	// The store must receive HASHES, never plaintext, and the hashes must match
	// the returned plaintext credentials.
	if bytes.Equal(fake.created.ClientSecretHash, []byte(resp.ClientSecret)) {
		t.Error("client_secret must be stored hashed, not in plaintext")
	}
	if !bytes.Equal(fake.created.ClientSecretHash, HashSecret(resp.ClientSecret)) {
		t.Error("stored client_secret hash does not match returned secret")
	}
	if !bytes.Equal(fake.created.RegistrationAccessTokenHash, HashSecret(resp.RegistrationAccessToken)) {
		t.Error("stored registration_access_token hash does not match returned token")
	}
	if fake.created.SectorID != resp.ClientID {
		t.Errorf("sector_id = %q, want it to equal client_id %q", fake.created.SectorID, resp.ClientID)
	}
	if fake.created.TokenFormat != defaultTokenFormat {
		t.Errorf("token_format = %q, want %q", fake.created.TokenFormat, defaultTokenFormat)
	}
}

func TestPostRegisterPublicClientNoSecret(t *testing.T) {
	fake := &fakeClientReg{}
	s := newRegServer(fake)

	rec := doRegister(t, s, `{
		"redirect_uris": ["https://rp.example.com/cb"],
		"token_endpoint_auth_method": "none"
	}`)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	resp := decodeRegisterResponse(t, rec)

	if resp.ClientSecret != "" {
		t.Error("public client must not receive a client_secret")
	}
	if resp.ClientSecretExpiresAt != nil {
		t.Error("public client must not receive client_secret_expires_at")
	}
	if resp.TokenEndpointAuthMethod != authMethodNone {
		t.Errorf("token_endpoint_auth_method = %q, want %q", resp.TokenEndpointAuthMethod, authMethodNone)
	}
	if len(fake.created.ClientSecretHash) != 0 {
		t.Error("public client must not store a client_secret hash")
	}
	// A registration access token is still issued (RFC 7592 management).
	if resp.RegistrationAccessToken == "" {
		t.Error("registration_access_token must be present even for public clients")
	}
}

func TestPostRegisterExplicitGrantAndResponseTypes(t *testing.T) {
	fake := &fakeClientReg{}
	s := newRegServer(fake)

	rec := doRegister(t, s, `{
		"redirect_uris": ["https://rp.example.com/cb"],
		"grant_types": ["authorization_code", "refresh_token"],
		"response_types": ["code"],
		"token_endpoint_auth_method": "client_secret_post"
	}`)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	resp := decodeRegisterResponse(t, rec)
	if len(resp.GrantTypes) != 2 {
		t.Errorf("grant_types = %v, want 2 entries", resp.GrantTypes)
	}
	if resp.TokenEndpointAuthMethod != "client_secret_post" {
		t.Errorf("token_endpoint_auth_method = %q, want client_secret_post", resp.TokenEndpointAuthMethod)
	}
}

func TestPostRegisterValidationErrors(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		wantCode string
	}{
		{
			name:     "missing redirect_uris",
			body:     `{"client_name":"x"}`,
			wantCode: "invalid_redirect_uri",
		},
		{
			name:     "http non-loopback redirect",
			body:     `{"redirect_uris":["http://rp.example.com/cb"]}`,
			wantCode: "invalid_redirect_uri",
		},
		{
			name:     "redirect with fragment",
			body:     `{"redirect_uris":["https://rp.example.com/cb#x"]}`,
			wantCode: "invalid_redirect_uri",
		},
		{
			name:     "unsupported grant_type",
			body:     `{"redirect_uris":["https://rp.example.com/cb"],"grant_types":["implicit"]}`,
			wantCode: "invalid_client_metadata",
		},
		{
			name:     "unsupported response_type",
			body:     `{"redirect_uris":["https://rp.example.com/cb"],"response_types":["token"]}`,
			wantCode: "invalid_client_metadata",
		},
		{
			name:     "unsupported auth method",
			body:     `{"redirect_uris":["https://rp.example.com/cb"],"token_endpoint_auth_method":"private_key_jwt"}`,
			wantCode: "invalid_client_metadata",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := &fakeClientReg{}
			s := newRegServer(fake)
			rec := doRegister(t, s, tt.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
			}
			if fake.called {
				t.Error("Create must not be called when validation fails")
			}
			if er := decodeRegisterError(t, rec); er.Error != tt.wantCode {
				t.Errorf("error = %q, want %q", er.Error, tt.wantCode)
			}
		})
	}
}

func TestPostRegisterMalformedBody(t *testing.T) {
	fake := &fakeClientReg{}
	s := newRegServer(fake)

	rec := doRegister(t, s, `{not json`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if fake.called {
		t.Error("Create must not be called for a malformed body")
	}
}

func TestPostRegisterUnavailable(t *testing.T) {
	s := New(nil, nil) // no registration store wired

	rec := doRegister(t, s, `{"redirect_uris":["https://rp.example.com/cb"]}`)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

func TestPostRegisterServerError(t *testing.T) {
	fake := &fakeClientReg{err: errors.New("db down")}
	s := newRegServer(fake)

	rec := doRegister(t, s, `{"redirect_uris":["https://rp.example.com/cb"]}`)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", rec.Code, rec.Body.String())
	}
}

func TestPostRegisterIssuedAtUsesStoredTime(t *testing.T) {
	fake := &fakeClientReg{}
	s := newRegServer(fake)

	before := time.Now().Add(-time.Second).Unix()
	rec := doRegister(t, s, `{"redirect_uris":["https://rp.example.com/cb"]}`)
	after := time.Now().Add(time.Second).Unix()

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201", rec.Code)
	}
	resp := decodeRegisterResponse(t, rec)
	if resp.ClientIDIssuedAt < before || resp.ClientIDIssuedAt > after {
		t.Errorf("client_id_issued_at = %d, want within [%d, %d]", resp.ClientIDIssuedAt, before, after)
	}
}

// TestRoutesRegistersRegister verifies POST /register is wired through the mux.
func TestRoutesRegistersRegister(t *testing.T) {
	fake := &fakeClientReg{}
	s := newRegServer(fake)

	mux := http.NewServeMux()
	s.Routes(mux)

	req := httptest.NewRequest(http.MethodPost, "/register",
		bytes.NewReader([]byte(`{"redirect_uris":["https://rp.example.com/cb"]}`)))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("routed status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
}
