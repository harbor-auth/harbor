package oidcapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/harbor/harbor/internal/gen/openapi"
	"github.com/harbor/harbor/internal/oidc"
)

// newRefreshFlowServer builds a Server wired for the full refresh-token rotation
// cycle. Unlike newFlowServer it adds:
//   - offline_access in ScopesAllowed so the token endpoint issues a refresh token
//   - SectorID on the client (required by PPIDSessionResolver for PPID derivation)
//   - InMemorySessionStore so refresh sessions are persisted across requests
//   - InMemoryGrantStore + PPIDSessionResolver so Refresh() can recover the frozen
//     PPID and scopes from the consent grant
func newRefreshFlowServer(t *testing.T) *httptest.Server {
	t.Helper()
	const userID = "00000000-0000-0000-0000-000000000042"

	clients := oidc.NewInMemoryClientRegistry()
	clients.Put(oidc.Client{
		ID:            testClientID,
		RedirectURIs:  []string{testRedirectURI},
		ScopesAllowed: []string{"openid", "profile", "email", "offline_access"},
		SectorID:      "localhost", // required: PPIDSessionResolver fails closed without it
	})

	loader := oidc.NewInMemorySecretLoader()
	loader.Put(userID, oidc.UserSecret{
		Region: "eu",
		Secret: bytes.Repeat([]byte{0x01}, 32), // deterministic 256-bit test secret
	})

	grants := oidc.NewInMemoryGrantStore()

	resolver := oidc.NewPPIDSessionResolver(oidc.PPIDSessionResolverConfig{
		Auth:   oidc.NewFixedAuthSource(userID),
		Loader: loader,
		Grants: grants,
	})

	svc := oidc.NewService(oidc.ServiceConfig{
		Issuer:       "https://eu.harbor.id",
		Clients:      clients,
		Codes:        oidc.NewInMemoryAuthCodeStore(),
		Tokens:       oidc.NewPlaceholderIssuer(),
		Sessions:     resolver,
		SessionStore: oidc.NewInMemorySessionStore(),
		Grants:       grants, // shared with resolver so FindGrant succeeds in Refresh()
	})

	srv := New(Config{Issuer: "https://eu.harbor.id", Service: svc})
	h := openapi.HandlerFromMux(srv, http.NewServeMux())
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	return ts
}

// validOfflineAuthorizeQuery is validAuthorizeQuery with offline_access appended
// so the token endpoint will issue a refresh token.
func validOfflineAuthorizeQuery() url.Values {
	q := validAuthorizeQuery()
	q.Set("scope", "openid profile offline_access")
	return q
}

// tokenBody is the JSON shape of a successful /token response.
type tokenBody struct {
	AccessToken      string `json:"access_token"`
	TokenType        string `json:"token_type"`
	IDToken          string `json:"id_token"`
	Scope            string `json:"scope"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshToken     string `json:"refresh_token"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
}

// decodeTokenBody decodes a successful /token JSON response into tokenBody.
func decodeTokenBody(t *testing.T, res *http.Response) tokenBody {
	t.Helper()
	var body tokenBody
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("decodeTokenBody: %v", err)
	}
	return body
}

// mintRefreshToken runs the authorize → code exchange cycle with offline_access
// and returns the opaque refresh token returned by /token.
func mintRefreshToken(t *testing.T, ts *httptest.Server) string {
	t.Helper()

	// Step 1: GET /authorize with offline_access scope → 302 with code.
	authRes := getAuthorize(t, ts, validOfflineAuthorizeQuery())
	defer func() { _ = authRes.Body.Close() }()
	if authRes.StatusCode != http.StatusFound {
		t.Fatalf("authorize status = %d, want 302", authRes.StatusCode)
	}
	code := locationQuery(t, authRes, testRedirectURI).Get("code")
	if code == "" {
		t.Fatal("no code in authorize redirect")
	}

	// Step 2: POST /token (authorization_code) → 200 with refresh_token.
	tokenRes := postToken(t, ts, validTokenForm(code))
	defer func() { _ = tokenRes.Body.Close() }()
	if tokenRes.StatusCode != http.StatusOK {
		t.Fatalf("token exchange status = %d, want 200", tokenRes.StatusCode)
	}
	body := decodeTokenBody(t, tokenRes)
	if body.RefreshToken == "" {
		t.Fatal("token exchange did not return a refresh_token (was offline_access in scope?)")
	}
	return body.RefreshToken
}

// postRefresh POSTs a refresh_token grant to /token and returns the raw response.
func postRefresh(t *testing.T, ts *httptest.Server, refreshToken string) *http.Response {
	t.Helper()
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	form.Set("client_id", testClientID)
	return postToken(t, ts, form)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestToken_RefreshRotation exercises the full rotation cycle end-to-end:
//
//  1. authorize with offline_access → code exchange → get refresh token
//  2. POST refresh_token grant → get new access + id + refresh tokens
//  3. The OLD refresh token is now single-use/rotated and must be rejected with
//     invalid_grant (docs/DESIGN.md §3.5, INV-REFRESH-ROTATION-SINGLE-USE).
func TestToken_RefreshRotation(t *testing.T) {
	ts := newRefreshFlowServer(t)
	refreshToken1 := mintRefreshToken(t, ts)

	// Rotate: exchange the first refresh token for fresh tokens.
	res1 := postRefresh(t, ts, refreshToken1)
	defer func() { _ = res1.Body.Close() }()

	if res1.StatusCode != http.StatusOK {
		t.Fatalf("refresh status = %d, want 200", res1.StatusCode)
	}
	assertNoStore(t, res1)

	body1 := decodeTokenBody(t, res1)
	if body1.AccessToken == "" {
		t.Fatal("refresh response missing access_token")
	}
	refreshToken2 := body1.RefreshToken
	if refreshToken2 == "" {
		t.Fatal("refresh response missing new refresh_token")
	}
	if refreshToken2 == refreshToken1 {
		t.Fatal("rotated refresh_token must differ from the original")
	}

	// The original token is now revoked; replaying it must yield invalid_grant.
	res2 := postRefresh(t, ts, refreshToken1)
	defer func() { _ = res2.Body.Close() }()

	if res2.StatusCode != http.StatusBadRequest {
		t.Fatalf("old token reuse status = %d, want 400", res2.StatusCode)
	}
	assertNoStore(t, res2)
	if code := decodeOAuthErrorCode(t, res2); code != "invalid_grant" {
		t.Fatalf("old token error = %q, want invalid_grant", code)
	}
}

// TestToken_RefreshTheftSignal_RevokesFamily verifies the theft-detection path
// (docs/DESIGN.md §3.5, INV-REFRESH-THEFT-SIGNAL-FAMILY-REVOKE):
//
//  1. Rotate token1 → token2 (token1 is now revoked).
//  2. Replay token1 (revoked) → theft signal fires → entire (user, client)
//     session family is revoked.
//  3. token2 must also be rejected because it was in the same family.
func TestToken_RefreshTheftSignal_RevokesFamily(t *testing.T) {
	ts := newRefreshFlowServer(t)
	refreshToken1 := mintRefreshToken(t, ts)

	// Rotate once: token1 → token2.
	res1 := postRefresh(t, ts, refreshToken1)
	if res1.StatusCode != http.StatusOK {
		_ = res1.Body.Close()
		t.Fatalf("first rotation status = %d, want 200", res1.StatusCode)
	}
	var body1 tokenBody
	if err := json.NewDecoder(res1.Body).Decode(&body1); err != nil {
		t.Fatalf("decode rotation response: %v", err)
	}
	_ = res1.Body.Close()
	refreshToken2 := body1.RefreshToken
	if refreshToken2 == "" {
		t.Fatal("rotation did not return a second refresh_token")
	}

	// Replay the OLD revoked token → theft signal → family revoked.
	res2 := postRefresh(t, ts, refreshToken1)
	defer func() { _ = res2.Body.Close() }()
	if res2.StatusCode != http.StatusBadRequest {
		t.Fatalf("theft detection status = %d, want 400", res2.StatusCode)
	}
	if code := decodeOAuthErrorCode(t, res2); code != "invalid_grant" {
		t.Fatalf("theft signal error = %q, want invalid_grant", code)
	}

	// token2 must also be rejected now — it was in the same (user, client)
	// family that the theft signal revoked.
	res3 := postRefresh(t, ts, refreshToken2)
	defer func() { _ = res3.Body.Close() }()
	if res3.StatusCode != http.StatusBadRequest {
		t.Fatalf("post-theft token2 status = %d, want 400", res3.StatusCode)
	}
	if code := decodeOAuthErrorCode(t, res3); code != "invalid_grant" {
		t.Fatalf("post-theft token2 error = %q, want invalid_grant", code)
	}
}
