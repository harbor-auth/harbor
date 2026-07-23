package oidcapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGetLoggedOut_ReturnsHTMLPage(t *testing.T) {
	srv := New(Config{Issuer: "https://eu.harbor.id"})
	req := httptest.NewRequest(http.MethodGet, "/logged-out", nil)
	rec := httptest.NewRecorder()

	srv.GetLoggedOut(rec, req)

	res := rec.Result()
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", res.StatusCode, http.StatusOK)
	}
	if ct := res.Header.Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Fatalf("Content-Type = %q, want text/html; charset=utf-8", ct)
	}
	if cc := res.Header.Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", cc)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "logged out") {
		t.Error("response body should contain 'logged out'")
	}
	if !strings.Contains(body, "<!DOCTYPE html>") {
		t.Error("response body should be a valid HTML document")
	}
}
