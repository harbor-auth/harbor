package bff

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestMiddleware_NoCookie(t *testing.T) {
	store := NewInMemoryBFFSessionStore()
	middleware := Middleware(store)

	var gotUserID string
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUserID = UserIDFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if gotUserID != "" {
		t.Errorf("userID = %q, want empty (no cookie)", gotUserID)
	}
}

func TestMiddleware_SessionNotFound(t *testing.T) {
	store := NewInMemoryBFFSessionStore()
	middleware := Middleware(store)

	var gotUserID string
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUserID = UserIDFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: "nonexistent-session"})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if gotUserID != "" {
		t.Errorf("userID = %q, want empty (session not found)", gotUserID)
	}
}

func TestMiddleware_SessionWithoutUserID(t *testing.T) {
	store := NewInMemoryBFFSessionStore()
	ctx := context.Background()

	// Create a session without a user ID (passkey ceremony not completed)
	record := BFFSessionRecord{
		RequestID: "req-123",
		State:     "state-abc",
		ExpiresAt: time.Now().Add(5 * time.Minute),
		// UserID is empty
	}
	if err := store.Create(ctx, record); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	middleware := Middleware(store)

	var gotUserID string
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUserID = UserIDFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: "req-123"})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if gotUserID != "" {
		t.Errorf("userID = %q, want empty (no user in session)", gotUserID)
	}
}

func TestMiddleware_SessionWithUserID(t *testing.T) {
	store := NewInMemoryBFFSessionStore()
	ctx := context.Background()

	// Create a session with a user ID (passkey ceremony completed)
	record := BFFSessionRecord{
		RequestID: "req-456",
		State:     "state-xyz",
		UserID:    "user-789",
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
	if err := store.Create(ctx, record); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	middleware := Middleware(store)

	var gotUserID string
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUserID = UserIDFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: "req-456"})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if gotUserID != "user-789" {
		t.Errorf("userID = %q, want %q", gotUserID, "user-789")
	}
}

func TestMiddleware_ExpiredSession(t *testing.T) {
	store := NewInMemoryBFFSessionStore()
	ctx := context.Background()

	// Set a fixed "now" in the past so the session is already expired
	pastTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return pastTime }

	record := BFFSessionRecord{
		RequestID: "req-expired",
		UserID:    "user-should-not-see",
		ExpiresAt: pastTime.Add(-1 * time.Minute), // already expired
	}
	if err := store.Create(ctx, record); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	middleware := Middleware(store)

	var gotUserID string
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUserID = UserIDFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: "req-expired"})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if gotUserID != "" {
		t.Errorf("userID = %q, want empty (session expired)", gotUserID)
	}
}
