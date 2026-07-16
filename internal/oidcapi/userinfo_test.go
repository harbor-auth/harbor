package oidcapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// mintAccessToken runs the full /authorize -> /token happy path and returns the
// issued access token.
func mintAccessToken(t *testing.T, ts *httptest.Server) string {
	t.Helper()
	code := mintCode(t, ts)
	res := postToken(t, ts, validTokenForm(code))
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("token status = %d, want 200", res.StatusCode)
	}
	var body struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	if body.AccessToken == "" {
		t.Fatal("no access token issued")
	}
	return body.AccessToken
}

// getUserInfo issues GET /userinfo with an optional Bearer token.
func getUserInfo(t *testing.T, ts *httptest.Server, token string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, ts.URL+"/userinfo", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("GET /userinfo: %v", err)
	}
	return res
}

// A valid access token yields 200 with the PPID sub echoed back.
func TestUserInfo_HappyPath(t *testing.T) {
	ts := newFlowServer(t)
	accessToken := mintAccessToken(t, ts)

	res := getUserInfo(t, ts, accessToken)
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}
	var body struct {
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified *bool  `json:"email_verified"`
	}
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("decode userinfo: %v", err)
	}
	if body.Sub == "" {
		t.Fatal("userinfo response missing sub")
	}
}

// A missing Authorization header is rejected with 401 invalid_token.
func TestUserInfo_MissingToken_Unauthorized(t *testing.T) {
	ts := newFlowServer(t)

	res := getUserInfo(t, ts, "")
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", res.StatusCode)
	}
	if errCode := decodeOAuthErrorCode(t, res); errCode != "invalid_token" {
		t.Fatalf("error = %q, want invalid_token", errCode)
	}
	if wa := res.Header.Get("WWW-Authenticate"); wa == "" {
		t.Fatal("missing WWW-Authenticate challenge")
	}
}

// A garbage / unverifiable token is rejected with 401 invalid_token.
func TestUserInfo_InvalidToken_Unauthorized(t *testing.T) {
	ts := newFlowServer(t)

	res := getUserInfo(t, ts, "not.a.jwt")
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", res.StatusCode)
	}
	if errCode := decodeOAuthErrorCode(t, res); errCode != "invalid_token" {
		t.Fatalf("error = %q, want invalid_token", errCode)
	}
}
