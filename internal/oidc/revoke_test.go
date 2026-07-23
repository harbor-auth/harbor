package oidc

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// newTestRevokeService returns a Service configured for /revoke tests with
// an in-memory session store seeded with a test session.
func newTestRevokeService(t *testing.T, sessionStore SessionStore) *Service {
	t.Helper()
	clients := NewInMemoryClientRegistry()
	clients.Put(testClient())

	return NewService(ServiceConfig{
		Issuer:       "https://eu.harbor.id",
		Clients:      clients,
		Codes:        NewInMemoryAuthCodeStore(),
		Tokens:       NewPlaceholderIssuer(),
		Sessions:     NewStubSessionResolver("demo-subject-ppid"),
		SessionStore: sessionStore,
		Grants:       NewInMemoryGrantStore(),
		Now:          func() time.Time { return time.Unix(1_700_000_000, 0) },
	})
}

// createTestSession creates a refresh session in the store and returns the
// encoded plaintext token for use in tests.
func createTestSession(t *testing.T, store *InMemorySessionStore, userID, clientID string) string {
	t.Helper()
	plaintext, hash, err := newOpaqueToken()
	if err != nil {
		t.Fatalf("newOpaqueToken: %v", err)
	}
	session := RefreshSession{
		ID:        "session-123",
		Region:    "eu",
		UserID:    userID,
		ClientID:  clientID,
		TokenHash: hash,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	if err := store.CreateSession(context.Background(), session); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	return encodeRefreshToken(plaintext)
}

func TestService_RevokeRefreshToken_Success(t *testing.T) {
	store := NewInMemorySessionStore()
	svc := newTestRevokeService(t, store)

	token := createTestSession(t, store, "user-456", "demo-client")

	// Revoke should succeed silently
	err := svc.RevokeRefreshToken(context.Background(), token, "demo-client")
	if err != nil {
		t.Fatalf("RevokeRefreshToken = %v, want nil", err)
	}

	// Session should be revoked (lookup should return ErrRefreshTokenRevoked)
	hash := hashRefreshToken(mustDecodeRefreshToken(t, token))
	_, err = store.GetSessionByTokenHash(context.Background(), hash)
	if !errors.Is(err, ErrRefreshTokenRevoked) {
		t.Fatalf("GetSessionByTokenHash = %v, want ErrRefreshTokenRevoked", err)
	}
}

func TestService_RevokeRefreshToken_UnknownToken(t *testing.T) {
	store := NewInMemorySessionStore()
	svc := newTestRevokeService(t, store)

	// Create a valid-looking but unknown token
	plaintext, _, err := newOpaqueToken()
	if err != nil {
		t.Fatalf("newOpaqueToken: %v", err)
	}
	unknownToken := encodeRefreshToken(plaintext)

	// Revoke should succeed silently (anti-enumeration)
	err = svc.RevokeRefreshToken(context.Background(), unknownToken, "demo-client")
	if err != nil {
		t.Fatalf("RevokeRefreshToken = %v, want nil (anti-enumeration)", err)
	}
}

func TestService_RevokeRefreshToken_MalformedToken(t *testing.T) {
	store := NewInMemorySessionStore()
	svc := newTestRevokeService(t, store)

	// Revoke with malformed token should succeed silently (anti-enumeration)
	err := svc.RevokeRefreshToken(context.Background(), "not-valid-base64!!!", "demo-client")
	if err != nil {
		t.Fatalf("RevokeRefreshToken = %v, want nil (anti-enumeration)", err)
	}
}

func TestService_RevokeRefreshToken_CrossClient_SilentNoOp(t *testing.T) {
	store := NewInMemorySessionStore()
	svc := newTestRevokeService(t, store)

	// Create session for client A
	token := createTestSession(t, store, "user-456", "client-a")

	// Attempt revoke from client B — should be silently ignored
	err := svc.RevokeRefreshToken(context.Background(), token, "client-b")
	if err != nil {
		t.Fatalf("RevokeRefreshToken = %v, want nil (anti-enumeration)", err)
	}

	// Session should still be active (not revoked)
	hash := hashRefreshToken(mustDecodeRefreshToken(t, token))
	session, err := store.GetSessionByTokenHash(context.Background(), hash)
	if err != nil {
		t.Fatalf("GetSessionByTokenHash = %v, want active session", err)
	}
	if session.ClientID != "client-a" {
		t.Fatalf("ClientID = %q, want %q", session.ClientID, "client-a")
	}
}

func TestService_RevokeRefreshToken_AlreadyRevoked_SilentNoOp(t *testing.T) {
	store := NewInMemorySessionStore()
	svc := newTestRevokeService(t, store)

	token := createTestSession(t, store, "user-456", "demo-client")

	// Revoke the session first
	hash := hashRefreshToken(mustDecodeRefreshToken(t, token))
	if err := store.RevokeSession(context.Background(), "session-123"); err != nil {
		t.Fatalf("RevokeSession: %v", err)
	}

	// Verify it's revoked
	_, err := store.GetSessionByTokenHash(context.Background(), hash)
	if !errors.Is(err, ErrRefreshTokenRevoked) {
		t.Fatalf("GetSessionByTokenHash = %v, want ErrRefreshTokenRevoked", err)
	}

	// Revoke again — should succeed silently (anti-enumeration)
	err = svc.RevokeRefreshToken(context.Background(), token, "demo-client")
	if err != nil {
		t.Fatalf("RevokeRefreshToken = %v, want nil (anti-enumeration)", err)
	}
}

func TestService_RevokeRefreshToken_RevokesFamilyNotJustSingleSession(t *testing.T) {
	store := NewInMemorySessionStore()
	svc := newTestRevokeService(t, store)

	// Create two sessions for the same (user, client) pair
	plaintext1, hash1, _ := newOpaqueToken()
	_, hash2, _ := newOpaqueToken()

	session1 := RefreshSession{
		ID:        "session-1",
		Region:    "eu",
		UserID:    "user-456",
		ClientID:  "demo-client",
		TokenHash: hash1,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	session2 := RefreshSession{
		ID:        "session-2",
		Region:    "eu",
		UserID:    "user-456",
		ClientID:  "demo-client",
		TokenHash: hash2,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	if err := store.CreateSession(context.Background(), session1); err != nil {
		t.Fatalf("CreateSession 1: %v", err)
	}
	if err := store.CreateSession(context.Background(), session2); err != nil {
		t.Fatalf("CreateSession 2: %v", err)
	}

	// Revoke using token 1
	token1 := encodeRefreshToken(plaintext1)
	err := svc.RevokeRefreshToken(context.Background(), token1, "demo-client")
	if err != nil {
		t.Fatalf("RevokeRefreshToken = %v, want nil", err)
	}

	// Both sessions should be revoked (family revoke)
	_, err = store.GetSessionByTokenHash(context.Background(), hash1)
	if !errors.Is(err, ErrRefreshTokenRevoked) {
		t.Fatalf("Session 1: GetSessionByTokenHash = %v, want ErrRefreshTokenRevoked", err)
	}
	_, err = store.GetSessionByTokenHash(context.Background(), hash2)
	if !errors.Is(err, ErrRefreshTokenRevoked) {
		t.Fatalf("Session 2: GetSessionByTokenHash = %v, want ErrRefreshTokenRevoked", err)
	}
}

func TestService_RevokeRefreshToken_DoesNotAffectOtherClients(t *testing.T) {
	store := NewInMemorySessionStore()
	svc := newTestRevokeService(t, store)

	// Create sessions for the same user but different clients
	plaintext1, hash1, _ := newOpaqueToken()
	_, hash2, _ := newOpaqueToken()

	session1 := RefreshSession{
		ID:        "session-1",
		Region:    "eu",
		UserID:    "user-456",
		ClientID:  "client-a",
		TokenHash: hash1,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	session2 := RefreshSession{
		ID:        "session-2",
		Region:    "eu",
		UserID:    "user-456",
		ClientID:  "client-b",
		TokenHash: hash2,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	if err := store.CreateSession(context.Background(), session1); err != nil {
		t.Fatalf("CreateSession 1: %v", err)
	}
	if err := store.CreateSession(context.Background(), session2); err != nil {
		t.Fatalf("CreateSession 2: %v", err)
	}

	// Revoke client-a's token
	token1 := encodeRefreshToken(plaintext1)
	err := svc.RevokeRefreshToken(context.Background(), token1, "client-a")
	if err != nil {
		t.Fatalf("RevokeRefreshToken = %v, want nil", err)
	}

	// Client-a's session should be revoked
	_, err = store.GetSessionByTokenHash(context.Background(), hash1)
	if !errors.Is(err, ErrRefreshTokenRevoked) {
		t.Fatalf("Client-a session: GetSessionByTokenHash = %v, want ErrRefreshTokenRevoked", err)
	}

	// Client-b's session should still be active
	_, err = store.GetSessionByTokenHash(context.Background(), hash2)
	if err != nil {
		t.Fatalf("Client-b session: GetSessionByTokenHash = %v, want active session", err)
	}
}

func TestService_RevokeRefreshToken_LogsDBError(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))

	store := &errSessionStore{
		getErr: errors.New("database connection failed"),
	}

	clients := NewInMemoryClientRegistry()
	clients.Put(testClient())

	svc := NewService(ServiceConfig{
		Issuer:       "https://eu.harbor.id",
		Clients:      clients,
		Codes:        NewInMemoryAuthCodeStore(),
		Tokens:       NewPlaceholderIssuer(),
		Sessions:     NewStubSessionResolver("demo-subject-ppid"),
		SessionStore: store,
		Grants:       NewInMemoryGrantStore(),
		Logger:       logger,
		Now:          func() time.Time { return time.Unix(1_700_000_000, 0) },
	})

	// Create a valid-looking token
	plaintext, _, _ := newOpaqueToken()
	token := encodeRefreshToken(plaintext)

	// Revoke should succeed silently (anti-enumeration) but log the error
	err := svc.RevokeRefreshToken(context.Background(), token, "demo-client")
	if err != nil {
		t.Fatalf("RevokeRefreshToken = %v, want nil (anti-enumeration)", err)
	}

	// Verify error was logged
	logOutput := logBuf.String()
	if !strings.Contains(logOutput, "session lookup failed") {
		t.Fatalf("expected log message about session lookup failure, got: %s", logOutput)
	}
	if !strings.Contains(logOutput, "database connection failed") {
		t.Fatalf("expected log to contain error message, got: %s", logOutput)
	}
}

func TestService_RevokeRefreshToken_EmptyUserID_SkipsRevoke(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))

	// Create a session with empty UserID (latent bug scenario)
	store := NewInMemorySessionStore()
	plaintext, hash, _ := newOpaqueToken()
	session := RefreshSession{
		ID:        "session-123",
		Region:    "eu",
		UserID:    "", // Empty UserID — should trigger guard
		ClientID:  "demo-client",
		TokenHash: hash,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	if err := store.CreateSession(context.Background(), session); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	clients := NewInMemoryClientRegistry()
	clients.Put(testClient())

	svc := NewService(ServiceConfig{
		Issuer:       "https://eu.harbor.id",
		Clients:      clients,
		Codes:        NewInMemoryAuthCodeStore(),
		Tokens:       NewPlaceholderIssuer(),
		Sessions:     NewStubSessionResolver("demo-subject-ppid"),
		SessionStore: store,
		Grants:       NewInMemoryGrantStore(),
		Logger:       logger,
		Now:          func() time.Time { return time.Unix(1_700_000_000, 0) },
	})

	token := encodeRefreshToken(plaintext)
	err := svc.RevokeRefreshToken(context.Background(), token, "demo-client")
	if err != nil {
		t.Fatalf("RevokeRefreshToken = %v, want nil", err)
	}

	// Verify the guard logged the issue
	logOutput := logBuf.String()
	if !strings.Contains(logOutput, "empty/zero UserID") {
		t.Fatalf("expected log message about empty UserID, got: %s", logOutput)
	}
}

func TestService_RevokeRefreshToken_ZeroUUID_SkipsRevoke(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))

	// Create a session with zero UUID UserID (latent bug scenario)
	store := NewInMemorySessionStore()
	plaintext, hash, _ := newOpaqueToken()
	session := RefreshSession{
		ID:        "session-123",
		Region:    "eu",
		UserID:    zeroUUID, // Zero UUID — should trigger guard
		ClientID:  "demo-client",
		TokenHash: hash,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	if err := store.CreateSession(context.Background(), session); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	clients := NewInMemoryClientRegistry()
	clients.Put(testClient())

	svc := NewService(ServiceConfig{
		Issuer:       "https://eu.harbor.id",
		Clients:      clients,
		Codes:        NewInMemoryAuthCodeStore(),
		Tokens:       NewPlaceholderIssuer(),
		Sessions:     NewStubSessionResolver("demo-subject-ppid"),
		SessionStore: store,
		Grants:       NewInMemoryGrantStore(),
		Logger:       logger,
		Now:          func() time.Time { return time.Unix(1_700_000_000, 0) },
	})

	token := encodeRefreshToken(plaintext)
	err := svc.RevokeRefreshToken(context.Background(), token, "demo-client")
	if err != nil {
		t.Fatalf("RevokeRefreshToken = %v, want nil", err)
	}

	// Verify the guard logged the issue
	logOutput := logBuf.String()
	if !strings.Contains(logOutput, "empty/zero UserID") {
		t.Fatalf("expected log message about zero UserID, got: %s", logOutput)
	}
}

// --- Test helpers ---

func mustDecodeRefreshToken(t *testing.T, s string) []byte {
	t.Helper()
	raw, err := decodeRefreshToken(s)
	if err != nil {
		t.Fatalf("decodeRefreshToken: %v", err)
	}
	return raw
}

// errSessionStore is a SessionStore that returns configurable errors.
type errSessionStore struct {
	getErr    error
	revokeErr error
}

func (s *errSessionStore) CreateSession(_ context.Context, _ RefreshSession) error {
	return nil
}

func (s *errSessionStore) GetSessionByTokenHash(_ context.Context, _ []byte) (RefreshSession, error) {
	if s.getErr != nil {
		return RefreshSession{}, s.getErr
	}
	return RefreshSession{}, ErrRefreshTokenNotFound
}

func (s *errSessionStore) RevokeSession(_ context.Context, _ string) error {
	return s.revokeErr
}

func (s *errSessionStore) RotateSession(_ context.Context, _ string, _ RefreshSession) error {
	return nil
}

func (s *errSessionStore) RevokeSessionsByUserClient(_ context.Context, _, _ string) error {
	return s.revokeErr
}

func (s *errSessionStore) RevokeSessionsByGrant(_ context.Context, _ string) error {
	return nil
}
