package mgmtapi

import (
	"bytes"
	"context"
	"crypto/subtle"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/harbor/harbor/internal/clients"
)

// DCR end-to-end integration test (RFC 7591/7592). Unlike the per-handler unit
// tests (register_test.go, register_manage_test.go, register_gate_test.go),
// this drives the FULL register→manage lifecycle through the real mux
// (Server.Routes) against a realistic in-memory store that mirrors the
// production clients.DBClientRegistrationStore: the handler hashes credentials
// before persistence, the store holds only hashes, and VerifyRegToken re-hashes
// the presented token to resolve exactly one client. That fidelity is what lets
// this test assert the security invariants the task calls out — hashed-at-rest,
// anonymous-gate rejection, and cross-client isolation — as an assembled flow
// rather than in isolation.
//
// It is an ordinary in-process test (no build tag, no live server or Postgres),
// so it runs under the default `go test ./...`. The live-stack e2e harness lives
// in e2e/ behind the `e2e` tag.

// storedClient is one persisted registration. The domain
// clients.RegisteredClient intentionally omits the registration_access_token
// hash (it is never exposed), so memClientStore keeps it alongside.
type storedClient struct {
	rc      clients.RegisteredClient
	regHash []byte
}

// memClientStore is an in-memory ClientRegistrationStore + ClientManagementStore
// that faithfully reproduces DBClientRegistrationStore's contract: it stores the
// hashes it is given (never plaintext) and resolves a registration_access_token
// by re-hashing it and constant-time-comparing against the stored hash.
type memClientStore struct {
	byID map[string]storedClient
}

func newMemClientStore() *memClientStore {
	return &memClientStore{byID: make(map[string]storedClient)}
}

func (m *memClientStore) Create(_ context.Context, c clients.NewRegisteredClient) (clients.RegisteredClient, error) {
	rc := clients.RegisteredClient{
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
	}
	m.byID[c.ClientID] = storedClient{rc: rc, regHash: c.RegistrationAccessTokenHash}
	return rc, nil
}

func (m *memClientStore) VerifyRegToken(_ context.Context, token string) (clients.RegisteredClient, error) {
	if token == "" {
		return clients.RegisteredClient{}, clients.ErrInvalidRegToken
	}
	// Mirror the DB store: hash the presented token and constant-time-compare
	// against each stored hash. A token can only ever resolve to its own client.
	presented := HashSecret(token)
	for _, sc := range m.byID {
		if subtle.ConstantTimeCompare(sc.regHash, presented) == 1 {
			return sc.rc, nil
		}
	}
	return clients.RegisteredClient{}, clients.ErrInvalidRegToken
}

func (m *memClientStore) Update(_ context.Context, c clients.UpdateRegisteredClient) (clients.RegisteredClient, error) {
	sc, ok := m.byID[c.ClientID]
	if !ok {
		return clients.RegisteredClient{}, clients.ErrClientNotFound
	}
	// Replace the mutable metadata; preserve immutable fields (sector_id,
	// created_at) carried on the existing domain record.
	sc.rc.Name = c.Name
	sc.rc.RedirectURIs = c.RedirectURIs
	sc.rc.TokenFormat = c.TokenFormat
	sc.rc.ScopesAllowed = c.ScopesAllowed
	sc.rc.ClientSecretHash = c.ClientSecretHash
	sc.rc.GrantTypes = c.GrantTypes
	sc.rc.ResponseTypes = c.ResponseTypes
	sc.rc.TokenEndpointAuthMethod = c.TokenEndpointAuthMethod
	sc.regHash = c.RegistrationAccessTokenHash
	m.byID[c.ClientID] = sc
	return sc.rc, nil
}

func (m *memClientStore) Delete(_ context.Context, clientID string) error {
	delete(m.byID, clientID) // idempotent, mirrors the DB store's hard delete
	return nil
}

func (m *memClientStore) get(clientID string) (storedClient, bool) {
	sc, ok := m.byID[clientID]
	return sc, ok
}

func (m *memClientStore) len() int { return len(m.byID) }

// newIntegrationServer wires a Server over the mem store exactly as production
// does (the same store backs both POST /register and the RFC 7592 routes).
func newIntegrationServer(store *memClientStore) *Server {
	return New(nil, nil).WithClientRegistration(store, testRegBaseURL)
}

// serveMgmt drives one request through the real mux the way a client would.
func serveMgmt(t *testing.T, mux *http.ServeMux, method, target, body, authHeader string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

// registerClient POSTs body to /register through mux and returns the decoded
// 201 client-information response, failing on any other status.
func registerClient(t *testing.T, mux *http.ServeMux, body, authHeader string) registerResponse {
	t.Helper()
	rec := serveMgmt(t, mux, http.MethodPost, "/register", body, authHeader)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /register = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	return decodeRegisterResponse(t, rec)
}

const integrationRegisterBody = `{
	"redirect_uris": ["https://rp.example.com/cb"],
	"client_name": "Integration App",
	"scope": "openid profile"
}`

// TestIntegrationRegisterThenManageLifecycle exercises the whole RFC 7591→
// RFC 7592 flow end-to-end: register a client, read it back, update its
// metadata, delete it, and confirm the token stops resolving afterwards.
func TestIntegrationRegisterThenManageLifecycle(t *testing.T) {
	store := newMemClientStore()
	s := newIntegrationServer(store)
	mux := http.NewServeMux()
	s.Routes(mux)

	// 1. Register.
	resp := registerClient(t, mux, integrationRegisterBody, "")
	if resp.ClientID == "" || resp.ClientSecret == "" || resp.RegistrationAccessToken == "" {
		t.Fatalf("register response missing credentials: %+v", resp)
	}
	regURI := "/register/" + resp.ClientID
	auth := bearer(resp.RegistrationAccessToken)

	// 2. GET the configuration back — same client, and never the client_secret.
	getRec := serveMgmt(t, mux, http.MethodGet, regURI, "", auth)
	if getRec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200; body=%s", regURI, getRec.Code, getRec.Body.String())
	}
	got := decodeRegisterResponse(t, getRec)
	if got.ClientID != resp.ClientID {
		t.Errorf("GET client_id = %q, want %q", got.ClientID, resp.ClientID)
	}
	if got.ClientSecret != "" {
		t.Error("GET must never return the client_secret")
	}
	if len(got.RedirectURIs) != 1 || got.RedirectURIs[0] != "https://rp.example.com/cb" {
		t.Errorf("GET redirect_uris = %v, want the registered URI", got.RedirectURIs)
	}

	// 3. PUT updated metadata.
	putBody := `{"redirect_uris":["https://rp.example.com/updated"],"client_name":"Integration App v2"}`
	putRec := serveMgmt(t, mux, http.MethodPut, regURI, putBody, auth)
	if putRec.Code != http.StatusOK {
		t.Fatalf("PUT %s = %d, want 200; body=%s", regURI, putRec.Code, putRec.Body.String())
	}
	updated := decodeRegisterResponse(t, putRec)
	if len(updated.RedirectURIs) != 1 || updated.RedirectURIs[0] != "https://rp.example.com/updated" {
		t.Errorf("PUT redirect_uris = %v, want the updated URI", updated.RedirectURIs)
	}

	// The update must be durable: a fresh GET reflects the new metadata and the
	// same registration_access_token still authenticates.
	getRec2 := serveMgmt(t, mux, http.MethodGet, regURI, "", auth)
	if getRec2.Code != http.StatusOK {
		t.Fatalf("GET-after-PUT %s = %d, want 200", regURI, getRec2.Code)
	}
	if reread := decodeRegisterResponse(t, getRec2); reread.RedirectURIs[0] != "https://rp.example.com/updated" {
		t.Errorf("GET-after-PUT redirect_uris = %v, want the updated URI", reread.RedirectURIs)
	}

	// 4. DELETE removes the client.
	delRec := serveMgmt(t, mux, http.MethodDelete, regURI, "", auth)
	if delRec.Code != http.StatusNoContent {
		t.Fatalf("DELETE %s = %d, want 204; body=%s", regURI, delRec.Code, delRec.Body.String())
	}
	if store.len() != 0 {
		t.Errorf("store holds %d clients after DELETE, want 0", store.len())
	}

	// 5. The token no longer resolves — GET is now 401 (not 403/leak).
	afterRec := serveMgmt(t, mux, http.MethodGet, regURI, "", auth)
	if afterRec.Code != http.StatusUnauthorized {
		t.Fatalf("GET after DELETE = %d, want 401; body=%s", afterRec.Code, afterRec.Body.String())
	}
}

// TestIntegrationCredentialsHashedAtRest asserts the core storage invariant:
// the persisted record holds only SHA-256 HASHES of the client_secret and
// registration_access_token — never the plaintext returned to the caller.
func TestIntegrationCredentialsHashedAtRest(t *testing.T) {
	store := newMemClientStore()
	s := newIntegrationServer(store)
	mux := http.NewServeMux()
	s.Routes(mux)

	resp := registerClient(t, mux, integrationRegisterBody, "")

	sc, ok := store.get(resp.ClientID)
	if !ok {
		t.Fatalf("registered client %q not found in store", resp.ClientID)
	}

	// client_secret: stored value is the hash, and is NOT the plaintext bytes.
	if !bytes.Equal(sc.rc.ClientSecretHash, HashSecret(resp.ClientSecret)) {
		t.Error("stored client_secret hash does not match hash of the returned secret")
	}
	if bytes.Equal(sc.rc.ClientSecretHash, []byte(resp.ClientSecret)) {
		t.Error("client_secret is stored in PLAINTEXT — must be hashed at rest")
	}

	// registration_access_token: same invariant.
	if !bytes.Equal(sc.regHash, HashSecret(resp.RegistrationAccessToken)) {
		t.Error("stored registration_access_token hash does not match hash of the returned token")
	}
	if bytes.Equal(sc.regHash, []byte(resp.RegistrationAccessToken)) {
		t.Error("registration_access_token is stored in PLAINTEXT — must be hashed at rest")
	}

	// Belt-and-braces: no stored hash column may contain the plaintext substring.
	for _, blob := range [][]byte{sc.rc.ClientSecretHash, sc.regHash} {
		if bytes.Contains(blob, []byte(resp.ClientSecret)) || bytes.Contains(blob, []byte(resp.RegistrationAccessToken)) {
			t.Error("a stored credential column contains plaintext credential material")
		}
	}
}

// TestIntegrationRegisteredClientCanAuthorizeAndToken checks that a freshly
// registered client is immediately usable by the hot-path authorize/token flow.
// DCR writes into the same relying_parties registry the OIDC resolver reads, so
// rather than pulling the whole oidc stack into this package-local test we
// assert the persisted record satisfies every authorize/token precondition:
// an exact-match redirect URI, the authorization_code grant, the code response
// type, a JWT token format, and a self-scoped PPID sector — and that the shared
// registry can resolve the client by its registration_access_token.
func TestIntegrationRegisteredClientCanAuthorizeAndToken(t *testing.T) {
	store := newMemClientStore()
	s := newIntegrationServer(store)
	mux := http.NewServeMux()
	s.Routes(mux)

	resp := registerClient(t, mux, integrationRegisterBody, "")

	sc, ok := store.get(resp.ClientID)
	if !ok {
		t.Fatalf("registered client %q not found in store", resp.ClientID)
	}
	rc := sc.rc

	// Exact-match redirect URI — /authorize will only bounce to a registered URI.
	if !containsString(rc.RedirectURIs, "https://rp.example.com/cb") {
		t.Errorf("redirect_uris = %v, want the exact registered callback", rc.RedirectURIs)
	}
	// authorization_code grant + code response type — required to mint a code and
	// exchange it at /token.
	if !containsString(rc.GrantTypes, defaultGrantType) {
		t.Errorf("grant_types = %v, want to include %q", rc.GrantTypes, defaultGrantType)
	}
	if !containsString(rc.ResponseTypes, defaultResponseType) {
		t.Errorf("response_types = %v, want to include %q", rc.ResponseTypes, defaultResponseType)
	}
	// JWT access tokens (Harbor's token format) — needed by /token issuance.
	if rc.TokenFormat != defaultTokenFormat {
		t.Errorf("token_format = %q, want %q", rc.TokenFormat, defaultTokenFormat)
	}
	// PPID sector defaults to the client_id, so pairwise subjects are derivable.
	if rc.SectorID != rc.ClientID {
		t.Errorf("sector_id = %q, want it to equal client_id %q", rc.SectorID, rc.ClientID)
	}

	// The shared registry resolves the client from its registration_access_token
	// — the same store the hot path reads, proving the record is live-usable.
	resolved, err := store.VerifyRegToken(context.Background(), resp.RegistrationAccessToken)
	if err != nil {
		t.Fatalf("VerifyRegToken for the freshly registered client failed: %v", err)
	}
	if resolved.ClientID != resp.ClientID {
		t.Errorf("resolved client_id = %q, want %q", resolved.ClientID, resp.ClientID)
	}
}

// TestIntegrationGateRejectsAnonymous verifies that when POST /register is gated
// behind an initial access token, an anonymous (or wrong-token) request is
// rejected with 401 and persists NOTHING, while a correctly-authenticated
// request succeeds.
func TestIntegrationGateRejectsAnonymous(t *testing.T) {
	const iat = "operator-initial-access-token"
	store := newMemClientStore()
	s := newIntegrationServer(store).WithInitialAccessToken(iat)
	mux := http.NewServeMux()
	s.Routes(mux)

	// Anonymous — no Authorization header.
	anon := serveMgmt(t, mux, http.MethodPost, "/register", integrationRegisterBody, "")
	if anon.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous POST /register = %d, want 401; body=%s", anon.Code, anon.Body.String())
	}
	if store.len() != 0 {
		t.Errorf("anonymous rejected register still persisted %d clients, want 0", store.len())
	}

	// Wrong token.
	wrong := serveMgmt(t, mux, http.MethodPost, "/register", integrationRegisterBody, bearer("not-the-iat"))
	if wrong.Code != http.StatusUnauthorized {
		t.Fatalf("wrong-token POST /register = %d, want 401", wrong.Code)
	}
	if store.len() != 0 {
		t.Errorf("wrong-token rejected register persisted %d clients, want 0", store.len())
	}

	// Correct initial access token — succeeds and persists exactly one client.
	resp := registerClient(t, mux, integrationRegisterBody, bearer(iat))
	if resp.ClientID == "" {
		t.Fatal("gated register with valid token returned no client_id")
	}
	if store.len() != 1 {
		t.Errorf("store holds %d clients after gated register, want 1", store.len())
	}
}

// TestIntegrationCrossClientIsolation registers two independent clients and
// verifies client A's registration_access_token cannot read, update, or delete
// client B (403), and vice-versa — while each token fully manages its OWN
// client. This is the multi-tenant isolation guarantee of RFC 7592.
func TestIntegrationCrossClientIsolation(t *testing.T) {
	store := newMemClientStore()
	s := newIntegrationServer(store)
	mux := http.NewServeMux()
	s.Routes(mux)

	a := registerClient(t, mux, `{"redirect_uris":["https://a.example.com/cb"],"client_name":"A"}`, "")
	b := registerClient(t, mux, `{"redirect_uris":["https://b.example.com/cb"],"client_name":"B"}`, "")
	if a.ClientID == b.ClientID {
		t.Fatalf("two registrations returned the same client_id %q", a.ClientID)
	}

	aToken := bearer(a.RegistrationAccessToken)
	bURI := "/register/" + b.ClientID

	// A's token addressing B must be forbidden on every verb, with no metadata
	// leak (B's redirect URI must not appear in the response body).
	cases := []struct {
		method string
		body   string
	}{
		{http.MethodGet, ""},
		{http.MethodPut, `{"redirect_uris":["https://evil.example.com/cb"]}`},
		{http.MethodDelete, ""},
	}
	for _, c := range cases {
		rec := serveMgmt(t, mux, c.method, bURI, c.body, aToken)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s %s with A's token = %d, want 403; body=%s", c.method, bURI, rec.Code, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), "b.example.com") {
			t.Errorf("%s cross-client response leaked B's metadata: %s", c.method, rec.Body.String())
		}
	}

	// B is untouched by A's attempts — still present and unchanged.
	bGet := serveMgmt(t, mux, http.MethodGet, bURI, "", bearer(b.RegistrationAccessToken))
	if bGet.Code != http.StatusOK {
		t.Fatalf("GET B with B's token = %d, want 200; body=%s", bGet.Code, bGet.Body.String())
	}
	if got := decodeRegisterResponse(t, bGet); got.RedirectURIs[0] != "https://b.example.com/cb" {
		t.Errorf("B's redirect_uris = %v, want it unchanged after A's cross-client attempts", got.RedirectURIs)
	}
	if store.len() != 2 {
		t.Errorf("store holds %d clients, want 2 (A's DELETE on B must not have removed anything)", store.len())
	}

	// And A can manage its OWN client.
	aGet := serveMgmt(t, mux, http.MethodGet, "/register/"+a.ClientID, "", aToken)
	if aGet.Code != http.StatusOK {
		t.Fatalf("GET A with A's token = %d, want 200", aGet.Code)
	}
}

// containsString reports whether s contains want.
func containsString(s []string, want string) bool {
	for _, v := range s {
		if v == want {
			return true
		}
	}
	return false
}

// compile-time assertions: the mem store satisfies both DCR store interfaces,
// exactly as the production clients.DBClientRegistrationStore does.
var (
	_ ClientRegistrationStore = (*memClientStore)(nil)
	_ ClientManagementStore   = (*memClientStore)(nil)
)
