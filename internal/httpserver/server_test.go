package httpserver

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthMux(t *testing.T) {
	mux := NewHealthMux()

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	res := rec.Result()
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("GET /healthz status = %d, want %d", res.StatusCode, http.StatusOK)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if got := string(body); got != "ok" {
		t.Fatalf("GET /healthz body = %q, want %q", got, "ok")
	}
}

func TestHealthMux_MethodNotAllowed(t *testing.T) {
	mux := NewHealthMux()

	req := httptest.NewRequest(http.MethodPost, "/healthz", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	// The method-specific pattern "GET /healthz" must not match POST.
	if rec.Result().StatusCode == http.StatusOK {
		t.Fatalf("POST /healthz unexpectedly returned 200")
	}
}
