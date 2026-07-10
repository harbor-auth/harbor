package oidcapi

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetHealthz(t *testing.T) {
	srv := New(Config{Issuer: "https://eu.harbor.id"})

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	srv.GetHealthz(rec, req)

	res := rec.Result()
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", res.StatusCode, http.StatusOK)
	}
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if got := string(body); got != "ok" {
		t.Fatalf("body = %q, want %q", got, "ok")
	}
}
