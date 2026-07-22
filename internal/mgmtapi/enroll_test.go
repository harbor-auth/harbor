package mgmtapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/harbor-auth/harbor/internal/identity"
)

// fakeEnroller is an in-memory Enroller for handler tests.
type fakeEnroller struct {
	result    identity.EnrollResult
	err       error
	gotRegion string
	called    bool
}

func (f *fakeEnroller) Enroll(_ context.Context, rawRegion string) (identity.EnrollResult, error) {
	f.called = true
	f.gotRegion = rawRegion
	return f.result, f.err
}

func doEnroll(t *testing.T, s *Server, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/enroll", strings.NewReader(body))
	rec := httptest.NewRecorder()
	s.PostEnroll(rec, req)
	return rec
}

func TestPostEnrollSuccess(t *testing.T) {
	fe := &fakeEnroller{result: identity.EnrollResult{UserID: "user-123", Region: "EU"}}
	s := New(fe, nil)

	rec := doEnroll(t, s, `{"region":"EU"}`)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	var resp enrollResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.UserID != "user-123" {
		t.Errorf("user_id = %q, want user-123", resp.UserID)
	}
	if resp.Status != statusPending {
		t.Errorf("status = %q, want %q", resp.Status, statusPending)
	}
	if !fe.called {
		t.Error("expected Enroll to be called")
	}
	if fe.gotRegion != "EU" {
		t.Errorf("Enroll got region %q, want EU", fe.gotRegion)
	}
}

func TestPostEnrollInvalidRegion(t *testing.T) {
	fe := &fakeEnroller{result: identity.EnrollResult{UserID: "x"}}
	s := New(fe, nil)

	rec := doEnroll(t, s, `{"region":"ATLANTIS"}`)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if fe.called {
		t.Error("Enroll must not be called for an invalid region")
	}
}

func TestPostEnrollMalformedBody(t *testing.T) {
	fe := &fakeEnroller{}
	s := New(fe, nil)

	rec := doEnroll(t, s, `{not json`)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if fe.called {
		t.Error("Enroll must not be called for a malformed body")
	}
}

func TestPostEnrollUnavailable(t *testing.T) {
	s := New(nil, nil) // dev-scaffold mode: no enroller wired

	rec := doEnroll(t, s, `{"region":"EU"}`)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

func TestPostEnrollServerError(t *testing.T) {
	fe := &fakeEnroller{err: errors.New("db down")}
	s := New(fe, nil)

	rec := doEnroll(t, s, `{"region":"EU"}`)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

// TestRoutesRegistersEnroll verifies POST /enroll is wired through the mux.
func TestRoutesRegistersEnroll(t *testing.T) {
	fe := &fakeEnroller{result: identity.EnrollResult{UserID: "u1", Region: "EU"}}
	s := New(fe, nil)

	mux := http.NewServeMux()
	s.Routes(mux)

	req := httptest.NewRequest(http.MethodPost, "/enroll", bytes.NewReader([]byte(`{"region":"EU"}`)))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("routed status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
}
