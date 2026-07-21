package mgmtapi

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/harbor/harbor/internal/clients"
)

const testRegToken = "reg-token-plaintext-value"

// sampleManagedClient is the client a valid testRegToken resolves to.
func sampleManagedClient() clients.RegisteredClient {
	return clients.RegisteredClient{
		ClientID:                "client-abc",
		Name:                    "Sample App",
		SectorID:                "client-abc",
		RedirectURIs:            []string{"https://rp.example.com/cb"},
		TokenFormat:             defaultTokenFormat,
		ScopesAllowed:           []string{"openid", "profile"},
		ClientSecretHash:        HashSecret("orig-secret"),
		GrantTypes:              []string{defaultGrantType},
		ResponseTypes:           []string{defaultResponseType},
		TokenEndpointAuthMethod: defaultAuthMethod,
		CreatedAt:               time.Now().Add(-time.Hour).UTC(),
	}
}

// fakeClientMgmt implements both ClientRegistrationStore (Create) and
// ClientManagementStore (VerifyRegToken/Update/Delete) so that
// WithClientRegistration wires the RFC 7592 routes via its type assertion.
type fakeClientMgmt struct {
	client    clients.RegisteredClient
	token     string // plaintext registration_access_token that resolves to client
	verifyErr error
	updateErr error
	deleteErr error

	updated      clients.UpdateRegisteredClient
	deletedID    string
	updateCalled bool
	deleteCalled bool
}

func (f *fakeClientMgmt) Create(_ context.Context, _ clients.NewRegisteredClient) (clients.RegisteredClient, error) {
	return f.client, nil
}

func (f *fakeClientMgmt) VerifyRegToken(_ context.Context, token string) (clients.RegisteredClient, error) {
	if f.verifyErr != nil {
		return clients.RegisteredClient{}, f.verifyErr
	}
	if token == "" || token != f.token {
		return clients.RegisteredClient{}, clients.ErrInvalidRegToken
	}
	return f.client, nil
}

func (f *fakeClientMgmt) Update(_ context.Context, c clients.UpdateRegisteredClient) (clients.RegisteredClient, error) {
	f.updateCalled = true
	f.updated = c
	if f.updateErr != nil {
		return clients.RegisteredClient{}, f.updateErr
	}
	u := f.client
	u.Name = c.Name
	u.RedirectURIs = c.RedirectURIs
	u.TokenFormat = c.TokenFormat
	u.ScopesAllowed = c.ScopesAllowed
	u.ClientSecretHash = c.ClientSecretHash
	u.GrantTypes = c.GrantTypes
	u.ResponseTypes = c.ResponseTypes
	u.TokenEndpointAuthMethod = c.TokenEndpointAuthMethod
	return u, nil
}

func (f *fakeClientMgmt) Delete(_ context.Context, clientID string) error {
	f.deleteCalled = true
	f.deletedID = clientID
	return f.deleteErr
}

func newMgmtServer(f *fakeClientMgmt) *Server {
	return New(nil, nil).WithClientRegistration(f, testRegBaseURL)
}

// doManage invokes the RFC 7592 handler for method directly, wiring the
// {client_id} path value the same way the mux would.
func doManage(t *testing.T, s *Server, method, clientID, body, authHeader string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, "/register/"+clientID, strings.NewReader(body))
	req.SetPathValue("client_id", clientID)
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	rec := httptest.NewRecorder()
	switch method {
	case http.MethodGet:
		s.GetRegister(rec, req)
	case http.MethodPut:
		s.PutRegister(rec, req)
	case http.MethodDelete:
		s.DeleteRegister(rec, req)
	default:
		t.Fatalf("unsupported method %q", method)
	}
	return rec
}

func bearer(token string) string { return "Bearer " + token }

// --- GET -------------------------------------------------------------------

func TestGetRegisterSuccess(t *testing.T) {
	fake := &fakeClientMgmt{client: sampleManagedClient(), token: testRegToken}
	s := newMgmtServer(fake)

	rec := doManage(t, s, http.MethodGet, "client-abc", "", bearer(testRegToken))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	resp := decodeRegisterResponse(t, rec)

	if resp.ClientID != "client-abc" {
		t.Errorf("client_id = %q, want %q", resp.ClientID, "client-abc")
	}
	if resp.ClientSecret != "" {
		t.Error("client_secret must never be returned (only its hash is stored)")
	}
	if resp.RegistrationAccessToken != testRegToken {
		t.Errorf("registration_access_token = %q, want the presented token", resp.RegistrationAccessToken)
	}
	wantURI := testRegBaseURL + "/register/client-abc"
	if resp.RegistrationClientURI != wantURI {
		t.Errorf("registration_client_uri = %q, want %q", resp.RegistrationClientURI, wantURI)
	}
	if resp.Scope != "openid profile" {
		t.Errorf("scope = %q, want %q", resp.Scope, "openid profile")
	}
}

func TestGetRegisterMissingToken(t *testing.T) {
	fake := &fakeClientMgmt{client: sampleManagedClient(), token: testRegToken}
	s := newMgmtServer(fake)

	rec := doManage(t, s, http.MethodGet, "client-abc", "", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("WWW-Authenticate"); !strings.Contains(got, "Bearer") {
		t.Errorf("WWW-Authenticate = %q, want it to contain %q", got, "Bearer")
	}
}

func TestGetRegisterInvalidToken(t *testing.T) {
	fake := &fakeClientMgmt{client: sampleManagedClient(), token: testRegToken}
	s := newMgmtServer(fake)

	rec := doManage(t, s, http.MethodGet, "client-abc", "", bearer("wrong-token"))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", rec.Code, rec.Body.String())
	}
}

func TestGetRegisterCrossClientForbidden(t *testing.T) {
	// Valid token resolves to client-abc, but the path names a different client.
	// The server must refuse (403) without leaking whether "other-client" exists.
	fake := &fakeClientMgmt{client: sampleManagedClient(), token: testRegToken}
	s := newMgmtServer(fake)

	rec := doManage(t, s, http.MethodGet, "other-client", "", bearer(testRegToken))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); strings.Contains(body, "rp.example.com") {
		t.Errorf("response leaked client metadata: %s", body)
	}
}

// --- PUT -------------------------------------------------------------------

func TestPutRegisterSuccess(t *testing.T) {
	fake := &fakeClientMgmt{client: sampleManagedClient(), token: testRegToken}
	s := newMgmtServer(fake)

	rec := doManage(t, s, http.MethodPut, "client-abc", `{
		"redirect_uris": ["https://rp.example.com/new-cb"],
		"client_name": "Renamed App",
		"scope": "openid"
	}`, bearer(testRegToken))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if !fake.updateCalled {
		t.Fatal("expected Update to be called")
	}
	resp := decodeRegisterResponse(t, rec)
	if len(resp.RedirectURIs) != 1 || resp.RedirectURIs[0] != "https://rp.example.com/new-cb" {
		t.Errorf("redirect_uris = %v, want the updated URI", resp.RedirectURIs)
	}
	if resp.ClientName != "Renamed App" {
		t.Errorf("client_name = %q, want %q", resp.ClientName, "Renamed App")
	}

	// Credentials must be preserved: the client_secret hash is untouched and the
	// stored registration_access_token hash matches the presented token.
	if !bytes.Equal(fake.updated.ClientSecretHash, HashSecret("orig-secret")) {
		t.Error("PUT must preserve the existing client_secret hash")
	}
	if !bytes.Equal(fake.updated.RegistrationAccessTokenHash, HashSecret(testRegToken)) {
		t.Error("PUT must preserve the registration_access_token (re-hashed from the presented token)")
	}
	if fake.updated.ClientID != "client-abc" {
		t.Errorf("update client_id = %q, want %q", fake.updated.ClientID, "client-abc")
	}
	if fake.updated.TokenFormat != defaultTokenFormat {
		t.Errorf("token_format = %q, want it preserved as %q", fake.updated.TokenFormat, defaultTokenFormat)
	}
}

func TestPutRegisterValidationError(t *testing.T) {
	fake := &fakeClientMgmt{client: sampleManagedClient(), token: testRegToken}
	s := newMgmtServer(fake)

	rec := doManage(t, s, http.MethodPut, "client-abc",
		`{"redirect_uris":["http://rp.example.com/cb"]}`, bearer(testRegToken))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if fake.updateCalled {
		t.Error("Update must not be called when validation fails")
	}
	if er := decodeRegisterError(t, rec); er.Error != "invalid_redirect_uri" {
		t.Errorf("error = %q, want %q", er.Error, "invalid_redirect_uri")
	}
}

func TestPutRegisterMalformedBody(t *testing.T) {
	fake := &fakeClientMgmt{client: sampleManagedClient(), token: testRegToken}
	s := newMgmtServer(fake)

	rec := doManage(t, s, http.MethodPut, "client-abc", `{not json`, bearer(testRegToken))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if fake.updateCalled {
		t.Error("Update must not be called for a malformed body")
	}
}

func TestPutRegisterInvalidToken(t *testing.T) {
	fake := &fakeClientMgmt{client: sampleManagedClient(), token: testRegToken}
	s := newMgmtServer(fake)

	rec := doManage(t, s, http.MethodPut, "client-abc",
		`{"redirect_uris":["https://rp.example.com/cb"]}`, bearer("wrong"))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if fake.updateCalled {
		t.Error("Update must not be called when the token is invalid")
	}
}

func TestPutRegisterClientDeletedRace(t *testing.T) {
	// The token authenticates, but the client is gone by the time Update runs.
	fake := &fakeClientMgmt{
		client:    sampleManagedClient(),
		token:     testRegToken,
		updateErr: clients.ErrClientNotFound,
	}
	s := newMgmtServer(fake)

	rec := doManage(t, s, http.MethodPut, "client-abc",
		`{"redirect_uris":["https://rp.example.com/cb"]}`, bearer(testRegToken))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", rec.Code, rec.Body.String())
	}
}

func TestPutRegisterServerError(t *testing.T) {
	fake := &fakeClientMgmt{
		client:    sampleManagedClient(),
		token:     testRegToken,
		updateErr: errors.New("db down"),
	}
	s := newMgmtServer(fake)

	rec := doManage(t, s, http.MethodPut, "client-abc",
		`{"redirect_uris":["https://rp.example.com/cb"]}`, bearer(testRegToken))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", rec.Code, rec.Body.String())
	}
}

// --- DELETE ----------------------------------------------------------------

func TestDeleteRegisterSuccess(t *testing.T) {
	fake := &fakeClientMgmt{client: sampleManagedClient(), token: testRegToken}
	s := newMgmtServer(fake)

	rec := doManage(t, s, http.MethodDelete, "client-abc", "", bearer(testRegToken))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body=%s", rec.Code, rec.Body.String())
	}
	if !fake.deleteCalled {
		t.Fatal("expected Delete to be called")
	}
	if fake.deletedID != "client-abc" {
		t.Errorf("deleted client_id = %q, want %q", fake.deletedID, "client-abc")
	}
	if rec.Body.Len() != 0 {
		t.Errorf("204 response must have an empty body, got %q", rec.Body.String())
	}
}

func TestDeleteRegisterInvalidToken(t *testing.T) {
	fake := &fakeClientMgmt{client: sampleManagedClient(), token: testRegToken}
	s := newMgmtServer(fake)

	rec := doManage(t, s, http.MethodDelete, "client-abc", "", bearer("wrong"))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if fake.deleteCalled {
		t.Error("Delete must not be called when the token is invalid")
	}
}

func TestDeleteRegisterCrossClientForbidden(t *testing.T) {
	fake := &fakeClientMgmt{client: sampleManagedClient(), token: testRegToken}
	s := newMgmtServer(fake)

	rec := doManage(t, s, http.MethodDelete, "other-client", "", bearer(testRegToken))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if fake.deleteCalled {
		t.Error("Delete must not be called for a cross-client token")
	}
}

func TestDeleteRegisterServerError(t *testing.T) {
	fake := &fakeClientMgmt{
		client:    sampleManagedClient(),
		token:     testRegToken,
		deleteErr: errors.New("db down"),
	}
	s := newMgmtServer(fake)

	rec := doManage(t, s, http.MethodDelete, "client-abc", "", bearer(testRegToken))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", rec.Code, rec.Body.String())
	}
}

// --- unavailable + routing -------------------------------------------------

func TestManagementUnavailableWhenNotWired(t *testing.T) {
	// fakeClientReg only implements Create, so clientMgmt is never wired and the
	// RFC 7592 routes report 503.
	s := newRegServer(&fakeClientReg{})
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		rec := doManage(t, s, method, "client-abc", "{}", bearer(testRegToken))
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("%s status = %d, want 503", method, rec.Code)
		}
	}
}

func TestRoutesRegisterManagement(t *testing.T) {
	fake := &fakeClientMgmt{client: sampleManagedClient(), token: testRegToken}
	s := newMgmtServer(fake)

	mux := http.NewServeMux()
	s.Routes(mux)

	cases := []struct {
		method   string
		body     string
		wantCode int
	}{
		{http.MethodGet, "", http.StatusOK},
		{http.MethodPut, `{"redirect_uris":["https://rp.example.com/cb"]}`, http.StatusOK},
		{http.MethodDelete, "", http.StatusNoContent},
	}
	for _, c := range cases {
		t.Run(c.method, func(t *testing.T) {
			req := httptest.NewRequest(c.method, "/register/client-abc", strings.NewReader(c.body))
			req.Header.Set("Authorization", bearer(testRegToken))
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			if rec.Code != c.wantCode {
				t.Fatalf("routed %s status = %d, want %d; body=%s", c.method, rec.Code, c.wantCode, rec.Body.String())
			}
		})
	}
}
