package bff

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
)

// mockWebAuthnService implements WebAuthnService for testing.
type mockWebAuthnService struct {
	beginLoginFunc func(ctx context.Context, userID []byte) (*protocol.CredentialAssertion, string, error)
}

func (m *mockWebAuthnService) BeginLogin(ctx context.Context, userID []byte) (*protocol.CredentialAssertion, string, error) {
	if m.beginLoginFunc != nil {
		return m.beginLoginFunc(ctx, userID)
	}
	// Return a minimal valid response
	return &protocol.CredentialAssertion{
		Response: protocol.PublicKeyCredentialRequestOptions{
			Challenge: []byte("test-challenge"),
		},
	}, "test-session-key", nil
}

// mockUserResolver implements UserResolver for testing.
type mockUserResolver struct {
	resolveFunc func(ctx context.Context, r *http.Request, session BFFSessionRecord) ([]byte, error)
}

func (m *mockUserResolver) ResolveUser(ctx context.Context, r *http.Request, session BFFSessionRecord) ([]byte, error) {
	if m.resolveFunc != nil {
		return m.resolveFunc(ctx, r, session)
	}
	return []byte("test-user-id"), nil
}

func TestLoginHandler_BeginLogin_MissingRequestID(t *testing.T) {
	store := NewInMemoryBFFSessionStore()
	handler := NewLoginHandler(store, &mockWebAuthnService{}, &mockUserResolver{})

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	rec := httptest.NewRecorder()

	handler.BeginLogin(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}

	var resp loginErrorResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Code != "invalid_request" {
		t.Errorf("code = %q, want %q", resp.Code, "invalid_request")
	}
}

func TestLoginHandler_BeginLogin_SessionNotFound(t *testing.T) {
	store := NewInMemoryBFFSessionStore()
	handler := NewLoginHandler(store, &mockWebAuthnService{}, &mockUserResolver{})

	req := httptest.NewRequest(http.MethodGet, "/login?request_id=nonexistent", nil)
	rec := httptest.NewRecorder()

	handler.BeginLogin(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}

	var resp loginErrorResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Code != "session_expired" {
		t.Errorf("code = %q, want %q", resp.Code, "session_expired")
	}
}

func TestLoginHandler_BeginLogin_SessionExpired(t *testing.T) {
	store := NewInMemoryBFFSessionStore()
	ctx := context.Background()

	// Create an expired session
	pastTime := time.Now().Add(-1 * time.Minute)
	record := BFFSessionRecord{
		RequestID: "expired-session",
		ClientID:  "test-client",
		ExpiresAt: pastTime,
	}
	// Manually insert with past expiry
	store.mu.Lock()
	store.sessions[record.RequestID] = record
	store.mu.Unlock()

	handler := NewLoginHandler(store, &mockWebAuthnService{}, &mockUserResolver{})

	req := httptest.NewRequest(http.MethodGet, "/login?request_id=expired-session", nil)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	handler.BeginLogin(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}

	var resp loginErrorResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Code != "session_expired" {
		t.Errorf("code = %q, want %q", resp.Code, "session_expired")
	}
}

func TestLoginHandler_BeginLogin_UserNotIdentified(t *testing.T) {
	store := NewInMemoryBFFSessionStore()
	ctx := context.Background()

	// Create a valid session
	record := BFFSessionRecord{
		RequestID: "valid-session",
		ClientID:  "test-client",
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
	if err := store.Create(ctx, record); err != nil {
		t.Fatalf("create session: %v", err)
	}

	// Resolver that returns ErrUserNotIdentified
	resolver := &mockUserResolver{
		resolveFunc: func(ctx context.Context, r *http.Request, session BFFSessionRecord) ([]byte, error) {
			return nil, ErrUserNotIdentified
		},
	}

	handler := NewLoginHandler(store, &mockWebAuthnService{}, resolver)

	req := httptest.NewRequest(http.MethodGet, "/login?request_id=valid-session", nil)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	handler.BeginLogin(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}

	var resp loginErrorResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Code != "user_not_identified" {
		t.Errorf("code = %q, want %q", resp.Code, "user_not_identified")
	}
}

func TestLoginHandler_BeginLogin_WebAuthnError(t *testing.T) {
	store := NewInMemoryBFFSessionStore()
	ctx := context.Background()

	// Create a valid session
	record := BFFSessionRecord{
		RequestID: "valid-session",
		ClientID:  "test-client",
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
	if err := store.Create(ctx, record); err != nil {
		t.Fatalf("create session: %v", err)
	}

	// WebAuthn service that returns an error
	webauthn := &mockWebAuthnService{
		beginLoginFunc: func(ctx context.Context, userID []byte) (*protocol.CredentialAssertion, string, error) {
			return nil, "", errors.New("user not found")
		},
	}

	handler := NewLoginHandler(store, webauthn, &mockUserResolver{})

	req := httptest.NewRequest(http.MethodGet, "/login?request_id=valid-session", nil)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	handler.BeginLogin(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}

	var resp loginErrorResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	// Should not leak whether user exists
	if resp.Code != "invalid_request" {
		t.Errorf("code = %q, want %q", resp.Code, "invalid_request")
	}
}

func TestLoginHandler_BeginLogin_HappyPath(t *testing.T) {
	store := NewInMemoryBFFSessionStore()
	ctx := context.Background()

	// Create a valid session
	record := BFFSessionRecord{
		RequestID:   "valid-session",
		ClientID:    "test-client",
		RedirectURI: "https://example.com/callback",
		State:       "oauth-state",
		ExpiresAt:   time.Now().Add(5 * time.Minute),
	}
	if err := store.Create(ctx, record); err != nil {
		t.Fatalf("create session: %v", err)
	}

	handler := NewLoginHandler(store, &mockWebAuthnService{}, &mockUserResolver{})

	req := httptest.NewRequest(http.MethodGet, "/login?request_id=valid-session", nil)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	handler.BeginLogin(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	// Check content type
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/json")
	}

	// Check cookies
	cookies := rec.Result().Cookies()
	var hasBFFCookie, hasWebAuthnCookie bool
	for _, c := range cookies {
		if c.Name == CookieName {
			hasBFFCookie = true
			if c.Value != "valid-session" {
				t.Errorf("BFF cookie value = %q, want %q", c.Value, "valid-session")
			}
			if !c.HttpOnly {
				t.Error("BFF cookie should be HttpOnly")
			}
			if !c.Secure {
				t.Error("BFF cookie should be Secure")
			}
			if c.SameSite != http.SameSiteStrictMode {
				t.Errorf("BFF cookie SameSite = %v, want Strict", c.SameSite)
			}
		}
		if c.Name == webauthnSessionCookieName {
			hasWebAuthnCookie = true
			if c.Value != "test-session-key" {
				t.Errorf("WebAuthn cookie value = %q, want %q", c.Value, "test-session-key")
			}
		}
	}
	if !hasBFFCookie {
		t.Error("missing BFF session cookie")
	}
	if !hasWebAuthnCookie {
		t.Error("missing WebAuthn session cookie")
	}

	// Check response body contains assertion options
	var options protocol.CredentialAssertion
	if err := json.NewDecoder(rec.Body).Decode(&options); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(options.Response.Challenge) == 0 {
		t.Error("expected challenge in response")
	}
}
