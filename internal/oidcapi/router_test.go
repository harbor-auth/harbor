package oidcapi

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/harbor/harbor/internal/crypto"
	"github.com/harbor/harbor/internal/gen/openapi"
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
