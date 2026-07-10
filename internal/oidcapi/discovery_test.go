package oidcapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func decodeDiscovery(t *testing.T, issuer string) map[string]any {
	t.Helper()
	srv := New(Config{Issuer: issuer})
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	rec := httptest.NewRecorder()
	srv.GetOpenIDConfiguration(rec, req)

	res := rec.Result()
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", res.StatusCode, http.StatusOK)
	}
	if ct := res.Header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type = %q, want application/json", ct)
	}

	var doc map[string]any
	if err := json.NewDecoder(res.Body).Decode(&doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return doc
}

func TestGetOpenIDConfiguration_EndpointsFromIssuer(t *testing.T) {
	doc := decodeDiscovery(t, "https://eu.harbor.id")

	want := map[string]string{
		"issuer":                 "https://eu.harbor.id",
		"authorization_endpoint": "https://eu.harbor.id/authorize",
		"token_endpoint":         "https://eu.harbor.id/token",
		"jwks_uri":               "https://eu.harbor.id/jwks.json",
	}
	for k, v := range want {
		if doc[k] != v {
			t.Fatalf("%s = %v, want %q", k, doc[k], v)
		}
	}
}

func TestGetOpenIDConfiguration_TrimsTrailingSlash(t *testing.T) {
	doc := decodeDiscovery(t, "https://eu.harbor.id/")
	if got := doc["authorization_endpoint"]; got != "https://eu.harbor.id/authorize" {
		t.Fatalf("authorization_endpoint = %v, want no double slash", got)
	}
}

// Privacy invariant (docs/DESIGN.md §3.2): pairwise subjects only.
func TestGetOpenIDConfiguration_PairwiseOnly(t *testing.T) {
	doc := decodeDiscovery(t, "https://eu.harbor.id")
	subs := toStrings(t, doc["subject_types_supported"])
	if len(subs) != 1 || subs[0] != "pairwise" {
		t.Fatalf("subject_types_supported = %v, want [pairwise]", subs)
	}
}

// Security invariant (docs/DESIGN.md §7): asymmetric signing only — no `none`/HS*.
func TestGetOpenIDConfiguration_AsymmetricSigningOnly(t *testing.T) {
	doc := decodeDiscovery(t, "https://eu.harbor.id")
	algs := toStrings(t, doc["id_token_signing_alg_values_supported"])
	if len(algs) == 0 {
		t.Fatal("id_token_signing_alg_values_supported is empty")
	}
	allowed := map[string]bool{"ES256": true, "EdDSA": true}
	for _, a := range algs {
		if !allowed[a] {
			t.Fatalf("disallowed signing alg %q — asymmetric only (ES256/EdDSA)", a)
		}
	}
}

// Security invariant (docs/DESIGN.md §3.1, §11.7): PKCE mandatory, S256 only —
// `plain` must never be advertised.
func TestGetOpenIDConfiguration_PKCES256Only(t *testing.T) {
	doc := decodeDiscovery(t, "https://eu.harbor.id")
	methods := toStrings(t, doc["code_challenge_methods_supported"])
	if len(methods) != 1 || methods[0] != "S256" {
		t.Fatalf("code_challenge_methods_supported = %v, want [S256]", methods)
	}
}

// OAuth 2.1 (docs/DESIGN.md §3.1): only Authorization Code + refresh; no implicit/ROPC.
func TestGetOpenIDConfiguration_GrantTypes(t *testing.T) {
	doc := decodeDiscovery(t, "https://eu.harbor.id")
	grants := toStrings(t, doc["grant_types_supported"])
	allowed := map[string]bool{"authorization_code": true, "refresh_token": true}
	if len(grants) == 0 {
		t.Fatal("grant_types_supported is empty")
	}
	for _, g := range grants {
		if !allowed[g] {
			t.Fatalf("disallowed grant type %q — Authorization Code + refresh only", g)
		}
	}
}

func TestGetOpenIDConfiguration_ScopesIncludeOpenID(t *testing.T) {
	doc := decodeDiscovery(t, "https://eu.harbor.id")
	scopes := toStrings(t, doc["scopes_supported"])
	var hasOpenID bool
	for _, s := range scopes {
		if s == "openid" {
			hasOpenID = true
		}
	}
	if !hasOpenID {
		t.Fatalf("scopes_supported = %v, must include \"openid\"", scopes)
	}
}

func toStrings(t *testing.T, v any) []string {
	t.Helper()
	arr, ok := v.([]any)
	if !ok {
		t.Fatalf("expected array, got %T", v)
	}
	out := make([]string, len(arr))
	for i, e := range arr {
		s, ok := e.(string)
		if !ok {
			t.Fatalf("expected string element, got %T", e)
		}
		out[i] = s
	}
	return out
}
