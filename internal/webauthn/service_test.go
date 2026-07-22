package webauthn

import (
	"context"
	"errors"
	"strings"
	"testing"

	gowebauthn "github.com/go-webauthn/webauthn/webauthn"
)

func testConfig() Config {
	return Config{
		RPID:          "localhost",
		RPDisplayName: "Harbor Test",
		RPOrigins:     []string{"http://localhost:8081"},
	}
}

// newTestService returns a Service with an in-memory store seeded with a demo
// user (no credentials) and a fresh session store.
func newTestService(t *testing.T) (*Service, *InMemoryStore) {
	t.Helper()
	store := NewInMemoryStore()
	store.PutUser(NewUser([]byte("demo-user"), "demo@harbor.local", "Demo", nil))
	svc, err := NewService(testConfig(), store, NewInMemorySessionStore())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc, store
}

func TestNewService_InvalidConfig(t *testing.T) {
	if _, err := NewService(Config{}, NewInMemoryStore(), NewInMemorySessionStore()); err == nil {
		t.Fatal("expected error for empty RP config, got nil")
	}
}

func TestService_BeginRegistration(t *testing.T) {
	svc, _ := newTestService(t)
	options, key, err := svc.BeginRegistration(context.Background(), []byte("demo-user"))
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	if options == nil || len(options.Response.Challenge) == 0 {
		t.Fatal("expected non-empty creation options with a challenge")
	}
	if key == "" {
		t.Fatal("expected a non-empty session key")
	}
}

func TestService_BeginRegistration_UnknownUser(t *testing.T) {
	svc, _ := newTestService(t)
	if _, _, err := svc.BeginRegistration(context.Background(), []byte("nobody")); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("err = %v, want ErrUserNotFound", err)
	}
}

func TestService_BeginLogin(t *testing.T) {
	store := NewInMemoryStore()
	// BeginLogin requires the user to already have a credential.
	cred := gowebauthn.Credential{ID: []byte("cred-1"), PublicKey: []byte("pk")}
	store.PutUser(NewUser([]byte("demo-user"), "demo@harbor.local", "Demo", []gowebauthn.Credential{cred}))
	svc, err := NewService(testConfig(), store, NewInMemorySessionStore())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	options, key, err := svc.BeginLogin(context.Background(), []byte("demo-user"))
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	if options == nil || key == "" {
		t.Fatal("expected assertion options and a session key")
	}
}

func TestService_BeginLogin_UnknownUser(t *testing.T) {
	svc, _ := newTestService(t)
	if _, _, err := svc.BeginLogin(context.Background(), []byte("nobody")); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("err = %v, want ErrUserNotFound", err)
	}
}

func TestService_FinishRegistration_NoSession(t *testing.T) {
	svc, _ := newTestService(t)
	_, err := svc.FinishRegistration(context.Background(), []byte("demo-user"), "missing-key", strings.NewReader("{}"))
	if !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("err = %v, want ErrSessionNotFound", err)
	}
}

func TestService_FinishLogin_NoSession(t *testing.T) {
	svc, _ := newTestService(t)
	_, err := svc.FinishLogin(context.Background(), []byte("demo-user"), "missing-key", strings.NewReader("{}"))
	if !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("err = %v, want ErrSessionNotFound", err)
	}
}

func TestService_FinishLogin_UnknownUser(t *testing.T) {
	svc, _ := newTestService(t)
	_, err := svc.FinishLogin(context.Background(), []byte("nobody"), "some-key", strings.NewReader("{}"))
	if !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("err = %v, want ErrUserNotFound", err)
	}
}

func TestService_FinishLogin_InvalidBody(t *testing.T) {
	// Create a service with a user that has credentials.
	store := NewInMemoryStore()
	cred := gowebauthn.Credential{ID: []byte("cred-1"), PublicKey: []byte("pk")}
	store.PutUser(NewUser([]byte("demo-user"), "demo@harbor.local", "Demo", []gowebauthn.Credential{cred}))
	sessions := NewInMemorySessionStore()
	svc, err := NewService(testConfig(), store, sessions)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	// Start a login ceremony to get a valid session.
	_, sessionKey, err := svc.BeginLogin(context.Background(), []byte("demo-user"))
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}

	// Try to finish with invalid JSON body.
	_, err = svc.FinishLogin(context.Background(), []byte("demo-user"), sessionKey, strings.NewReader("not-json"))
	if err == nil {
		t.Fatal("expected error for invalid body, got nil")
	}
}

func TestService_FinishLogin_MalformedAssertion(t *testing.T) {
	// Create a service with a user that has credentials.
	store := NewInMemoryStore()
	cred := gowebauthn.Credential{ID: []byte("cred-1"), PublicKey: []byte("pk")}
	store.PutUser(NewUser([]byte("demo-user"), "demo@harbor.local", "Demo", []gowebauthn.Credential{cred}))
	sessions := NewInMemorySessionStore()
	svc, err := NewService(testConfig(), store, sessions)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	// Start a login ceremony to get a valid session.
	_, sessionKey, err := svc.BeginLogin(context.Background(), []byte("demo-user"))
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}

	// Try to finish with valid JSON but incomplete/malformed assertion response.
	// This should fail validation in the WebAuthn library.
	_, err = svc.FinishLogin(context.Background(), []byte("demo-user"), sessionKey, strings.NewReader(`{"id":"bad","rawId":"bad","type":"public-key","response":{}}`))
	if err == nil {
		t.Fatal("expected error for malformed assertion, got nil")
	}
}

func TestService_FinishRegistration_UnknownUser(t *testing.T) {
	svc, _ := newTestService(t)
	_, err := svc.FinishRegistration(context.Background(), []byte("nobody"), "some-key", strings.NewReader("{}"))
	if !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("err = %v, want ErrUserNotFound", err)
	}
}

func TestService_FinishRegistration_InvalidBody(t *testing.T) {
	store := NewInMemoryStore()
	store.PutUser(NewUser([]byte("demo-user"), "demo@harbor.local", "Demo", nil))
	sessions := NewInMemorySessionStore()
	svc, err := NewService(testConfig(), store, sessions)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	// Start a registration ceremony to get a valid session.
	_, sessionKey, err := svc.BeginRegistration(context.Background(), []byte("demo-user"))
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}

	// Try to finish with invalid JSON body.
	_, err = svc.FinishRegistration(context.Background(), []byte("demo-user"), sessionKey, strings.NewReader("not-json"))
	if err == nil {
		t.Fatal("expected error for invalid body, got nil")
	}
}

func TestService_FinishRecoveryRegistration_UnknownUser(t *testing.T) {
	svc, _ := newTestService(t)
	_, err := svc.FinishRecoveryRegistration(context.Background(), []byte("nobody"), "some-key", strings.NewReader("{}"))
	if !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("err = %v, want ErrUserNotFound", err)
	}
}

func TestService_FinishRecoveryRegistration_NoSession(t *testing.T) {
	svc, _ := newTestService(t)
	_, err := svc.FinishRecoveryRegistration(context.Background(), []byte("demo-user"), "missing-key", strings.NewReader("{}"))
	if !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("err = %v, want ErrSessionNotFound", err)
	}
}

// TestService_FinishRecoveryRegistration_InvalidBody proves that when the
// attestation cannot be verified the recovery_required flag is NOT cleared —
// the account stays fenced until a fresh passkey is genuinely enrolled.
func TestService_FinishRecoveryRegistration_InvalidBodyKeepsRecoveryRequired(t *testing.T) {
	store := NewInMemoryStore()
	store.PutUser(NewUser([]byte("demo-user"), "demo@harbor.local", "Demo", nil))
	sessions := NewInMemorySessionStore()
	svc, err := NewService(testConfig(), store, sessions)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	_, sessionKey, err := svc.BeginRegistration(context.Background(), []byte("demo-user"))
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}

	if _, err := svc.FinishRecoveryRegistration(context.Background(), []byte("demo-user"), sessionKey, strings.NewReader("not-json")); err == nil {
		t.Fatal("expected error for invalid body, got nil")
	}
	if store.RecoveryCleared([]byte("demo-user")) {
		t.Fatal("recovery_required must NOT be cleared when enrollment fails")
	}
}
