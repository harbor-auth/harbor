package oidcapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestWriteErrorSetsNoStore pins RFC 6749 §5.1/§5.2: every error response written
// through writeError — including fail-closed pre-handler rejections such as the
// region middleware's 400 region_unknown on /token — MUST carry
// Cache-Control: no-store and Pragma: no-cache so no intermediary caches an error
// body. This guards the regression at the fast unit layer (the e2e
// TestRefreshInvalidTokenIsInvalidGrant covers it end-to-end).
func TestWriteErrorSetsNoStore(t *testing.T) {
	rec := httptest.NewRecorder()

	writeError(rec, http.StatusBadRequest, "region_unknown", "host does not map to a region")

	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want %q", got, "no-store")
	}
	if got := rec.Header().Get("Pragma"); got != "no-cache" {
		t.Errorf("Pragma = %q, want %q", got, "no-cache")
	}
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want %q", got, "application/json")
	}
}
