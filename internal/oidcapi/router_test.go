package oidcapi

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/harbor-auth/harbor/internal/crypto"
	"github.com/harbor-auth/harbor/internal/gen/openapi"
)

// TestHandlerFromMux proves the spec-generated router dispatches every endpoint
// to this Server — the exact wiring cmd/harbor-hot performs.
func TestHandlerFromMux(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	srv := New(Config{
		Issuer:  "https://eu.harbor.id",
		Signers: []crypto.Signer{crypto.NewSignerFromKey(priv)},
	})
	h := openapi.HandlerFromMux(srv, http.NewServeMux())
	ts := httptest.NewServer(h)
	defer ts.Close()

	cases := []struct {
		path       string
		wantStatus int
	}{
		{"/healthz", http.StatusOK},
		{"/.well-known/openid-configuration", http.StatusOK},
		{"/jwks.json", http.StatusOK},
	}
	for _, tc := range cases {
		res, err := http.Get(ts.URL + tc.path)
		if err != nil {
			t.Fatalf("GET %s: %v", tc.path, err)
		}
		_ = res.Body.Close()
		if res.StatusCode != tc.wantStatus {
			t.Fatalf("GET %s status = %d, want %d", tc.path, res.StatusCode, tc.wantStatus)
		}
	}
}

// TestHarborHotRouteTableHasNoAdminV1Path proves
// openspec/changes/harbor-cloud-management-api-contract-2ee993ea/specs/harbor-cloud-management-api/spec.md's
// "harbor-hot never exposes the contract" scenario: harbor-hot's route table
// (openapi.HandlerFromMux(srv, mux) — the exact wiring cmd/harbor-hot/main.go
// performs) has no /admin/v1/* path at all. internal/cloudapi's
// /admin/v1/{sessions,namespaces,keys/rotate} contract is wired only into
// cmd/harbor-mgmt, behind mgmt.cloudIntegration — harbor-hot's public
// listener never imports internal/cloudapi (see internal/cloudapi/store.go's
// package doc, and internal/arch's TestHarborHotDoesNotImportCloudAPI for the
// stronger, import-graph version of this same invariant).
func TestHarborHotRouteTableHasNoAdminV1Path(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	srv := New(Config{
		Issuer:  "https://eu.harbor.id",
		Signers: []crypto.Signer{crypto.NewSignerFromKey(priv)},
	})
	h := openapi.HandlerFromMux(srv, http.NewServeMux())
	ts := httptest.NewServer(h)
	defer ts.Close()

	adminV1Paths := []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/admin/v1/sessions"},
		{http.MethodPost, "/admin/v1/namespaces"},
		{http.MethodGet, "/admin/v1/namespaces/some-namespace"},
		{http.MethodDelete, "/admin/v1/namespaces/some-namespace"},
		{http.MethodPost, "/admin/v1/keys/rotate"},
	}
	for _, tc := range adminV1Paths {
		req, err := http.NewRequest(tc.method, ts.URL+tc.path, nil)
		if err != nil {
			t.Fatalf("NewRequest(%s %s): %v", tc.method, tc.path, err)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", tc.method, tc.path, err)
		}
		_ = res.Body.Close()
		if res.StatusCode != http.StatusNotFound {
			t.Errorf("%s %s status = %d, want 404 (not registered) — harbor-hot must never expose the Harbor Cloud management contract", tc.method, tc.path, res.StatusCode)
		}
	}
}
