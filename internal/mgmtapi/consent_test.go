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
	grants    []oidc.ConsentGrant
	listErr   error
	getErr    error
	revokeErr error
	revokedID string // records the ID passed to the last successful Revoke call
}

func (f *fakeConsentStore) Get(_ context.Context, userID, clientID string) (oidc.ConsentGrant, bool, error) {
	if f.getErr != nil {
		return oidc.ConsentGrant{}, false, f.getErr
	}
	for _, g := range f.grants {
		if g.UserID == userID && g.ClientID == clientID && g.RevokedAt == nil {
			return g, true, nil
		}
	}
	return oidc.ConsentGrant{}, false, nil
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

func (f *fakeConsentStore) Revoke(_ context.Context, id string) error {
	if f.revokeErr != nil {
		return f.revokeErr
	}
	f.revokedID = id
	return nil
}

// fakeSessionRevoker implements SessionRevoker for testing.
type fakeSessionRevoker struct {
	err          error
	calledUserID string
	calledClient string
	called       bool
}

func (f *fakeSessionRevoker) RevokeSessionsByUserClient(_ context.Context, userID, clientID string) error {
	f.called = true
	f.calledUserID = userID
	f.calledClient = clientID
	return f.err
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

func TestDeleteConsentGrant_Success(t *testing.T) {
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
		},
	}
	revoker := &fakeSessionRevoker{}

	srv := New(nil, nil).WithConsentStore(store).WithSessionRevoker(revoker)
	mux := http.NewServeMux()
	srv.Routes(mux)

	req := httptest.NewRequest("DELETE", "/consent-grants/client-a", nil)
	req.Header.Set(UserIDHeader, "user-123")
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
	if store.revokedID != "grant-001" {
		t.Errorf("revoked grant ID = %q, want %q", store.revokedID, "grant-001")
	}
	// Cascade must fire with the correct (user, client) pair.
	if !revoker.called {
		t.Error("session revoker was not called")
	}
	if revoker.calledUserID != "user-123" || revoker.calledClient != "client-a" {
		t.Errorf("cascade called with (%q, %q), want (user-123, client-a)",
			revoker.calledUserID, revoker.calledClient)
	}
}

func TestDeleteConsentGrant_Idempotent_NoGrant(t *testing.T) {
	// No matching grant exists; deletion should still succeed and cascade.
	store := &fakeConsentStore{grants: nil}
	revoker := &fakeSessionRevoker{}

	srv := New(nil, nil).WithConsentStore(store).WithSessionRevoker(revoker)
	mux := http.NewServeMux()
	srv.Routes(mux)

	req := httptest.NewRequest("DELETE", "/consent-grants/client-a", nil)
	req.Header.Set(UserIDHeader, "user-123")
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
	if store.revokedID != "" {
		t.Errorf("revoke should not be called when no grant exists, got ID %q", store.revokedID)
	}
	// Cascade still runs so any lingering sessions are torn down.
	if !revoker.called {
		t.Error("session revoker should still be called for idempotent cleanup")
	}
}

func TestDeleteConsentGrant_OnlyOwnGrant(t *testing.T) {
	grantedAt := time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)
	store := &fakeConsentStore{
		grants: []oidc.ConsentGrant{
			{
				ID:        "grant-other",
				UserID:    "other-user",
				ClientID:  "client-a",
				Scopes:    []string{"openid"},
				GrantedAt: grantedAt,
			},
		},
	}
	revoker := &fakeSessionRevoker{}

	srv := New(nil, nil).WithConsentStore(store).WithSessionRevoker(revoker)
	mux := http.NewServeMux()
	srv.Routes(mux)

	// user-123 tries to revoke client-a, but only other-user has that grant.
	req := httptest.NewRequest("DELETE", "/consent-grants/client-a", nil)
	req.Header.Set(UserIDHeader, "user-123")
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	// Idempotent success, but the other user's grant must NOT be revoked.
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
	if store.revokedID != "" {
		t.Errorf("must not revoke another user's grant, got ID %q", store.revokedID)
	}
}

func TestDeleteConsentGrant_Unauthorized(t *testing.T) {
	store := &fakeConsentStore{}

	srv := New(nil, nil).WithConsentStore(store)
	mux := http.NewServeMux()
	srv.Routes(mux)

	// No X-Harbor-User-ID header
	req := httptest.NewRequest("DELETE", "/consent-grants/client-a", nil)
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestDeleteConsentGrant_ServiceUnavailable(t *testing.T) {
	// No consent store wired
	srv := New(nil, nil)
	mux := http.NewServeMux()
	srv.Routes(mux)

	req := httptest.NewRequest("DELETE", "/consent-grants/client-a", nil)
	req.Header.Set(UserIDHeader, "user-123")
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
}

func TestDeleteConsentGrant_GetError(t *testing.T) {
	store := &fakeConsentStore{getErr: errors.New("database connection failed")}

	srv := New(nil, nil).WithConsentStore(store)
	mux := http.NewServeMux()
	srv.Routes(mux)

	req := httptest.NewRequest("DELETE", "/consent-grants/client-a", nil)
	req.Header.Set(UserIDHeader, "user-123")
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
}

func TestDeleteConsentGrant_RevokeError(t *testing.T) {
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
		},
		revokeErr: errors.New("revoke failed"),
	}

	srv := New(nil, nil).WithConsentStore(store)
	mux := http.NewServeMux()
	srv.Routes(mux)

	req := httptest.NewRequest("DELETE", "/consent-grants/client-a", nil)
	req.Header.Set(UserIDHeader, "user-123")
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
}

func TestDeleteConsentGrant_CascadeError(t *testing.T) {
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
		},
	}
	revoker := &fakeSessionRevoker{err: errors.New("cascade failed")}

	srv := New(nil, nil).WithConsentStore(store).WithSessionRevoker(revoker)
	mux := http.NewServeMux()
	srv.Routes(mux)

	req := httptest.NewRequest("DELETE", "/consent-grants/client-a", nil)
	req.Header.Set(UserIDHeader, "user-123")
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
}
