package oidcapi

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/harbor/harbor/internal/gen/openapi"
)

// TestHandlerFromMux proves the spec-generated router dispatches both endpoints
// to this Server — the exact wiring cmd/harbor-hot performs.
func TestHandlerFromMux(t *testing.T) {
	srv := New(Config{Issuer: "https://eu.harbor.id"})
	h := openapi.HandlerFromMux(srv, http.NewServeMux())
	ts := httptest.NewServer(h)
	defer ts.Close()

	cases := []struct {
		path       string
		wantStatus int
	}{
		{"/healthz", http.StatusOK},
		{"/.well-known/openid-configuration", http.StatusOK},
	}
	for _, tc := range cases {
		res, err := http.Get(ts.URL + tc.path)
		if err != nil {
			t.Fatalf("GET %s: %v", tc.path, err)
		}
		res.Body.Close()
		if res.StatusCode != tc.wantStatus {
			t.Fatalf("GET %s status = %d, want %d", tc.path, res.StatusCode, tc.wantStatus)
		}
	}
}
