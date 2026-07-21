package mgmtapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/harbor/harbor/internal/oidc"
)

// fakeConsentStore implements ConsentStore for testing.
type fakeConsentStore struct {
	grants  []oidc.ConsentGrant
	listErr error
}

func (f *fakeConsentStore) List(_ context.Context, userID string) ([]oidc.ConsentGrant, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	// Filter by userID to simulate real behavior
	var result []oidc.ConsentGrant
	for _, g := range f.grants {
		if g.UserID == userID {
			result = append(result, g)
		}
	}
	return result, nil
}

func TestGetConsentGrants_Success(t *testing.T) {
	grantedAt := time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)
	store := &fakeConsentStore{
		grants: []oidc.ConsentGrant{
			{
				ID:        "grant-001",
				UserID:    "user-123",
				ClientID:  "client-a",
				Scopes:    []string{"openid", "profile"},
				GrantedAt: grantedAt,
			},
			{
				ID:        "grant-002",
				UserID:    "user-123",
				ClientID:  "client-b",
				Scopes:    []string{"openid", "email"},
				GrantedAt: grantedAt.Add(time.Hour),
			},
		},
	}

	srv := New(nil, nil).WithConsentStore(store)
	mux := http.NewServeMux()
	srv.Routes(mux)

	req := httptest.NewRequest("GET", "/consent-grants", nil)
	req.Header.Set(UserIDHeader, "user-123")
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var resp ConsentGrantsListResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if len(resp.Grants) != 2 {
		t.Fatalf("got %d grants, want 2", len(resp.Grants))
	}

	// Check first grant
	if resp.Grants[0].ClientID != "client-a" {
		t.Errorf("grants[0].client_id = %q, want %q", resp.Grants[0].ClientID, "client-a")
	}
	if len(resp.Grants[0].Scopes) != 2 {
		t.Errorf("grants[0].scopes len = %d, want 2", len(resp.Grants[0].Scopes))
	}
}

func TestGetConsentGrants_EmptyList(t *testing.T) {
	store := &fakeConsentStore{grants: nil}

	srv := New(nil, nil).WithConsentStore(store)
	mux := http.NewServeMux()
	srv.Routes(mux)

	req := httptest.NewRequest("GET", "/consent-grants", nil)
	req.Header.Set(UserIDHeader, "user-with-no-grants")
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var resp ConsentGrantsListResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if len(resp.Grants) != 0 {
		t.Fatalf("got %d grants, want 0", len(resp.Grants))
	}
}

func TestGetConsentGrants_Unauthorized(t *testing.T) {
	store := &fakeConsentStore{}

	srv := New(nil, nil).WithConsentStore(store)
	mux := http.NewServeMux()
	srv.Routes(mux)

	// No X-Harbor-User-ID header
	req := httptest.NewRequest("GET", "/consent-grants", nil)
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}

	var resp errorResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if resp.Error != "unauthorized" {
		t.Errorf("error = %q, want %q", resp.Error, "unauthorized")
	}
}

func TestGetConsentGrants_ServiceUnavailable(t *testing.T) {
	// No consent store wired
	srv := New(nil, nil)
	mux := http.NewServeMux()
	srv.Routes(mux)

	req := httptest.NewRequest("GET", "/consent-grants", nil)
	req.Header.Set(UserIDHeader, "user-123")
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
}

func TestGetConsentGrants_StoreError(t *testing.T) {
	store := &fakeConsentStore{
		listErr: errors.New("database connection failed"),
	}

	srv := New(nil, nil).WithConsentStore(store)
	mux := http.NewServeMux()
	srv.Routes(mux)

	req := httptest.NewRequest("GET", "/consent-grants", nil)
	req.Header.Set(UserIDHeader, "user-123")
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}

	var resp errorResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if resp.Error != "server_error" {
		t.Errorf("error = %q, want %q", resp.Error, "server_error")
	}
}

func TestGetConsentGrants_OnlyReturnsOwnGrants(t *testing.T) {
	grantedAt := time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)
	store := &fakeConsentStore{
		grants: []oidc.ConsentGrant{
			{
				ID:        "grant-001",
				UserID:    "user-123",
				ClientID:  "client-a",
				Scopes:    []string{"openid"},
				GrantedAt: grantedAt,
			},
			{
				ID:        "grant-002",
				UserID:    "other-user", // Different user
				ClientID:  "client-b",
				Scopes:    []string{"openid"},
				GrantedAt: grantedAt,
			},
		},
	}

	srv := New(nil, nil).WithConsentStore(store)
	mux := http.NewServeMux()
	srv.Routes(mux)

	req := httptest.NewRequest("GET", "/consent-grants", nil)
	req.Header.Set(UserIDHeader, "user-123")
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var resp ConsentGrantsListResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	// Should only see grants for user-123, not other-user
	if len(resp.Grants) != 1 {
		t.Fatalf("got %d grants, want 1", len(resp.Grants))
	}
	if resp.Grants[0].ID != "grant-001" {
		t.Errorf("grants[0].id = %q, want %q", resp.Grants[0].ID, "grant-001")
	}
}
