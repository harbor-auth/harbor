package bff

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/harbor-auth/harbor/internal/oidc"
)

// mockWebAuthnService implements WebAuthnService for testing.
type mockWebAuthnService struct {
	beginLoginFunc             func(ctx context.Context, userID []byte) (*protocol.CredentialAssertion, string, error)
	finishLoginFunc            func(ctx context.Context, sessionKey string, response *protocol.ParsedCredentialAssertionData) (string, error)
	beginDiscoverableLoginFunc func(ctx context.Context) (*protocol.CredentialAssertion, string, error)
	finishDiscoverableFunc     func(ctx context.Context, sessionKey string, response *protocol.ParsedCredentialAssertionData) (string, error)
}

func (m *mockWebAuthnService) BeginLogin(ctx context.Context, userID []byte) (*protocol.CredentialAssertion, string, error) {
	if m.beginLoginFunc != nil {
		return m.beginLoginFunc(ctx, userID)
	}
	return &protocol.CredentialAssertion{
		Response: protocol.PublicKeyCredentialRequestOptions{
			Challenge: []byte("test-challenge"),
		},
	}, "test-session-key", nil
}

func (m *mockWebAuthnService) FinishLogin(ctx context.Context, sessionKey string, response *protocol.ParsedCredentialAssertionData) (string, error) {
	if m.finishLoginFunc != nil {
		return m.finishLoginFunc(ctx, sessionKey, response)
	}
	return "authenticated-user-id", nil
}

func (m *mockWebAuthnService) BeginDiscoverableLogin(ctx context.Context) (*protocol.CredentialAssertion, string, error) {
	if m.beginDiscoverableLoginFunc != nil {
		return m.beginDiscoverableLoginFunc(ctx)
	}
	return &protocol.CredentialAssertion{
		Response: protocol.PublicKeyCredentialRequestOptions{
			Challenge: []byte("discoverable-challenge"),
		},
	}, "discoverable-session-key", nil
}

func (m *mockWebAuthnService) FinishDiscoverableLogin(ctx context.Context, sessionKey string, response *protocol.ParsedCredentialAssertionData) (string, error) {
	if m.finishDiscoverableFunc != nil {
		return m.finishDiscoverableFunc(ctx, sessionKey, response)
	}
	return "discoverable-user-id", nil
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

// --- FinishLogin Tests ---

func TestLoginHandler_FinishLogin_MissingBFFCookie(t *testing.T) {
	store := NewInMemoryBFFSessionStore()
	handler := NewLoginHandler(store, &mockWebAuthnService{}, &mockUserResolver{})

	req := httptest.NewRequest(http.MethodPost, "/login/complete", nil)
	rec := httptest.NewRecorder()

	handler.FinishLogin(rec, req)

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

func TestLoginHandler_FinishLogin_MissingWebAuthnCookie(t *testing.T) {
	store := NewInMemoryBFFSessionStore()
	handler := NewLoginHandler(store, &mockWebAuthnService{}, &mockUserResolver{})

	req := httptest.NewRequest(http.MethodPost, "/login/complete", nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: "test-request-id"})
	rec := httptest.NewRecorder()

	handler.FinishLogin(rec, req)

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

func TestLoginHandler_FinishLogin_SessionNotFound(t *testing.T) {
	store := NewInMemoryBFFSessionStore()
	handler := NewLoginHandler(store, &mockWebAuthnService{}, &mockUserResolver{})

	req := httptest.NewRequest(http.MethodPost, "/login/complete", nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: "nonexistent"})
	req.AddCookie(&http.Cookie{Name: webauthnSessionCookieName, Value: "session-key"})
	rec := httptest.NewRecorder()

	handler.FinishLogin(rec, req)

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

func TestLoginHandler_FinishLogin_InvalidBody(t *testing.T) {
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

	handler := NewLoginHandler(store, &mockWebAuthnService{}, &mockUserResolver{})

	// Invalid JSON body
	req := httptest.NewRequest(http.MethodPost, "/login/complete", strings.NewReader("not valid json"))
	req.AddCookie(&http.Cookie{Name: CookieName, Value: "valid-session"})
	req.AddCookie(&http.Cookie{Name: webauthnSessionCookieName, Value: "session-key"})
	rec := httptest.NewRecorder()

	handler.FinishLogin(rec, req)

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

// TestLoginHandler_FinishLogin_HappyPath tests the successful login completion flow.
// Since creating valid WebAuthn assertion data is complex, we use a testable
// version of the handler that accepts pre-parsed data.
func TestLoginHandler_FinishLogin_HappyPath(t *testing.T) {
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

	// Test the core logic via FinishLoginWithParsedData
	handler := NewLoginHandler(store, &mockWebAuthnService{}, &mockUserResolver{})

	req := httptest.NewRequest(http.MethodPost, "/login/complete", nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: "valid-session"})
	req.AddCookie(&http.Cookie{Name: webauthnSessionCookieName, Value: "session-key"})
	rec := httptest.NewRecorder()

	// Use the testable method that accepts pre-parsed data
	handler.FinishLoginWithParsedData(rec, req, &protocol.ParsedCredentialAssertionData{})

	// Should redirect to /authorize/complete
	if rec.Code != http.StatusFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusFound)
	}

	location := rec.Header().Get("Location")
	expectedLocation := "/authorize/complete?request_id=valid-session"
	if location != expectedLocation {
		t.Errorf("Location = %q, want %q", location, expectedLocation)
	}

	// Check that WebAuthn session cookie is cleared
	cookies := rec.Result().Cookies()
	for _, c := range cookies {
		if c.Name == webauthnSessionCookieName && c.MaxAge != -1 {
			t.Errorf("WebAuthn cookie should be cleared (MaxAge=-1), got MaxAge=%d", c.MaxAge)
		}
	}

	// Verify user_id and auth method were saved to session
	updatedSession, err := store.Get(ctx, "valid-session")
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	if updatedSession.UserID != "authenticated-user-id" {
		t.Errorf("session.UserID = %q, want %q", updatedSession.UserID, "authenticated-user-id")
	}
	if updatedSession.AuthMethod != oidc.AuthMethodWebAuthn {
		t.Errorf("session.AuthMethod = %q, want %q", updatedSession.AuthMethod, oidc.AuthMethodWebAuthn)
	}
}

// --- Discoverable Login Tests ---

// TestDiscoverableUserResolver_ResolveUser verifies that DiscoverableUserResolver
// always returns ErrDiscoverable so BeginLogin knows to branch to the
// discoverable flow.
func TestDiscoverableUserResolver_ResolveUser(t *testing.T) {
	resolver := DiscoverableUserResolver{}
	handle, err := resolver.ResolveUser(context.Background(), httptest.NewRequest(http.MethodGet, "/", nil), BFFSessionRecord{})
	if handle != nil {
		t.Errorf("user handle = %v, want nil", handle)
	}
	if !errors.Is(err, ErrDiscoverable) {
		t.Errorf("err = %v, want ErrDiscoverable", err)
	}
}

func TestLoginHandler_BeginLogin_Discoverable_HappyPath(t *testing.T) {
	store := NewInMemoryBFFSessionStore()
	ctx := context.Background()

	record := BFFSessionRecord{
		RequestID: "valid-session",
		ClientID:  "test-client",
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
	if err := store.Create(ctx, record); err != nil {
		t.Fatalf("create session: %v", err)
	}

	// Track whether BeginDiscoverableLogin was called (not BeginLogin).
	var beginDiscoverableCalled bool
	webauthn := &mockWebAuthnService{
		beginDiscoverableLoginFunc: func(ctx context.Context) (*protocol.CredentialAssertion, string, error) {
			beginDiscoverableCalled = true
			return &protocol.CredentialAssertion{
				Response: protocol.PublicKeyCredentialRequestOptions{
					Challenge: []byte("discoverable-challenge"),
				},
			}, "discoverable-session-key", nil
		},
	}

	handler := NewLoginHandler(store, webauthn, DiscoverableUserResolver{})

	req := httptest.NewRequest(http.MethodGet, "/login?request_id=valid-session", nil)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	handler.BeginLogin(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if !beginDiscoverableCalled {
		t.Error("expected BeginDiscoverableLogin to be called, but it was not")
	}

	// WebAuthn session cookie must carry the discoverable session key.
	var webauthnCookieValue string
	for _, c := range rec.Result().Cookies() {
		if c.Name == webauthnSessionCookieName {
			webauthnCookieValue = c.Value
		}
	}
	if webauthnCookieValue != "discoverable-session-key" {
		t.Errorf("WebAuthn cookie = %q, want %q", webauthnCookieValue, "discoverable-session-key")
	}

	// Response body must contain assertion options with a challenge.
	var options protocol.CredentialAssertion
	if err := json.NewDecoder(rec.Body).Decode(&options); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(options.Response.Challenge) == 0 {
		t.Error("expected challenge in discoverable assertion options")
	}
}

func TestLoginHandler_BeginLogin_Discoverable_WebAuthnError(t *testing.T) {
	store := NewInMemoryBFFSessionStore()
	ctx := context.Background()

	record := BFFSessionRecord{
		RequestID: "valid-session",
		ClientID:  "test-client",
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
	if err := store.Create(ctx, record); err != nil {
		t.Fatalf("create session: %v", err)
	}

	webauthn := &mockWebAuthnService{
		beginDiscoverableLoginFunc: func(ctx context.Context) (*protocol.CredentialAssertion, string, error) {
			return nil, "", errors.New("ceremony init failed")
		},
	}

	handler := NewLoginHandler(store, webauthn, DiscoverableUserResolver{})

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
	// Must collapse to a generic error — no details about the failure.
	if resp.Code != "invalid_request" {
		t.Errorf("code = %q, want %q", resp.Code, "invalid_request")
	}
}

func TestLoginHandler_FinishLogin_Discoverable_HappyPath(t *testing.T) {
	store := NewInMemoryBFFSessionStore()
	ctx := context.Background()

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

	// Track which finish branch was called and the session key supplied.
	var finishDiscoverableCalled bool
	var gotSessionKey string
	webauthn := &mockWebAuthnService{
		finishDiscoverableFunc: func(ctx context.Context, sessionKey string, response *protocol.ParsedCredentialAssertionData) (string, error) {
			finishDiscoverableCalled = true
			gotSessionKey = sessionKey
			return "discoverable-resolved-user", nil
		},
	}

	handler := NewLoginHandler(store, webauthn, DiscoverableUserResolver{})

	req := httptest.NewRequest(http.MethodPost, "/login/complete", nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: "valid-session"})
	req.AddCookie(&http.Cookie{Name: webauthnSessionCookieName, Value: "discoverable-session-key"})
	rec := httptest.NewRecorder()

	handler.FinishLoginWithParsedData(rec, req, &protocol.ParsedCredentialAssertionData{})

	if rec.Code != http.StatusFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusFound)
	}
	if !finishDiscoverableCalled {
		t.Error("expected FinishDiscoverableLogin to be called, but it was not")
	}
	if gotSessionKey != "discoverable-session-key" {
		t.Errorf("session key passed to FinishDiscoverableLogin = %q, want %q", gotSessionKey, "discoverable-session-key")
	}

	// The session must carry the user ID resolved from the discoverable flow.
	updatedSession, err := store.Get(ctx, "valid-session")
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	if updatedSession.UserID != "discoverable-resolved-user" {
		t.Errorf("session.UserID = %q, want %q", updatedSession.UserID, "discoverable-resolved-user")
	}
	if updatedSession.AuthMethod != oidc.AuthMethodWebAuthn {
		t.Errorf("session.AuthMethod = %q, want %q", updatedSession.AuthMethod, oidc.AuthMethodWebAuthn)
	}

	// WebAuthn session cookie must be cleared.
	for _, c := range rec.Result().Cookies() {
		if c.Name == webauthnSessionCookieName && c.MaxAge != -1 {
			t.Errorf("WebAuthn cookie should be cleared (MaxAge=-1), got MaxAge=%d", c.MaxAge)
		}
	}

	location := rec.Header().Get("Location")
	if location != "/authorize/complete?request_id=valid-session" {
		t.Errorf("Location = %q, want /authorize/complete?request_id=valid-session", location)
	}
}

func TestLoginHandler_FinishLogin_Discoverable_Failure(t *testing.T) {
	store := NewInMemoryBFFSessionStore()
	ctx := context.Background()

	record := BFFSessionRecord{
		RequestID: "valid-session",
		ClientID:  "test-client",
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
	if err := store.Create(ctx, record); err != nil {
		t.Fatalf("create session: %v", err)
	}

	webauthn := &mockWebAuthnService{
		finishDiscoverableFunc: func(ctx context.Context, sessionKey string, response *protocol.ParsedCredentialAssertionData) (string, error) {
			return "", errors.New("unknown userHandle")
		},
	}

	handler := NewLoginHandler(store, webauthn, DiscoverableUserResolver{})

	req := httptest.NewRequest(http.MethodPost, "/login/complete", nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: "valid-session"})
	req.AddCookie(&http.Cookie{Name: webauthnSessionCookieName, Value: "discoverable-session-key"})
	rec := httptest.NewRecorder()

	handler.FinishLoginWithParsedData(rec, req, &protocol.ParsedCredentialAssertionData{})

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}

	var resp loginErrorResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	// Must collapse to a generic error — no enumeration of user existence.
	if resp.Code != "authentication_failed" {
		t.Errorf("code = %q, want %q", resp.Code, "authentication_failed")
	}
}

func TestLoginHandler_FinishLogin_Discoverable_NotCalledForKnownUser(t *testing.T) {
	// When a non-discoverable resolver is wired, FinishLogin (not
	// FinishDiscoverableLogin) must be called even if the service would support it.
	store := NewInMemoryBFFSessionStore()
	ctx := context.Background()

	record := BFFSessionRecord{
		RequestID: "valid-session",
		ClientID:  "test-client",
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
	if err := store.Create(ctx, record); err != nil {
		t.Fatalf("create session: %v", err)
	}

	var finishDiscoverableCalled bool
	webauthn := &mockWebAuthnService{
		finishDiscoverableFunc: func(ctx context.Context, sessionKey string, response *protocol.ParsedCredentialAssertionData) (string, error) {
			finishDiscoverableCalled = true
			return "should-not-be-called", nil
		},
	}

	// Use a standard (non-discoverable) resolver.
	handler := NewLoginHandler(store, webauthn, &mockUserResolver{})

	req := httptest.NewRequest(http.MethodPost, "/login/complete", nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: "valid-session"})
	req.AddCookie(&http.Cookie{Name: webauthnSessionCookieName, Value: "session-key"})
	rec := httptest.NewRecorder()

	handler.FinishLoginWithParsedData(rec, req, &protocol.ParsedCredentialAssertionData{})

	if finishDiscoverableCalled {
		t.Error("FinishDiscoverableLogin must NOT be called when a non-discoverable resolver is wired")
	}
	if rec.Code != http.StatusFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusFound)
	}
}

func TestLoginHandler_FinishLogin_WebAuthnFailure(t *testing.T) {
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

	webauthn := &mockWebAuthnService{
		finishLoginFunc: func(ctx context.Context, sessionKey string, response *protocol.ParsedCredentialAssertionData) (string, error) {
			return "", errors.New("verification failed")
		},
	}

	handler := NewLoginHandler(store, webauthn, &mockUserResolver{})

	req := httptest.NewRequest(http.MethodPost, "/login/complete", nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: "valid-session"})
	req.AddCookie(&http.Cookie{Name: webauthnSessionCookieName, Value: "session-key"})
	rec := httptest.NewRecorder()

	// Use the testable method
	handler.FinishLoginWithParsedData(rec, req, &protocol.ParsedCredentialAssertionData{})

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}

	var resp loginErrorResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Code != "authentication_failed" {
		t.Errorf("code = %q, want %q", resp.Code, "authentication_failed")
	}
}
