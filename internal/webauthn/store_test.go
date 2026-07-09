package webauthn

import (
	"context"
	"errors"
	"testing"
	"time"

	gowebauthn "github.com/go-webauthn/webauthn/webauthn"
)

func TestInMemoryStore_UserLifecycle(t *testing.T) {
	ctx := context.Background()
	s := NewInMemoryStore()
	id := []byte("user-1")

	if _, err := s.GetUser(ctx, id); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("GetUser before Put: err = %v, want ErrUserNotFound", err)
	}

	s.PutUser(NewUser(id, "a@b.c", "A", nil))
	if _, err := s.GetUser(ctx, id); err != nil {
		t.Fatalf("GetUser after Put: %v", err)
	}

	cred := gowebauthn.Credential{ID: []byte("cred-1")}
	cred.Authenticator.SignCount = 1
	if err := s.AddCredential(ctx, id, cred); err != nil {
		t.Fatalf("AddCredential: %v", err)
	}
	u, _ := s.GetUser(ctx, id)
	if len(u.WebAuthnCredentials()) != 1 {
		t.Fatalf("want 1 credential, got %d", len(u.WebAuthnCredentials()))
	}

	// UpdateCredential must persist the advanced sign counter.
	cred.Authenticator.SignCount = 5
	if err := s.UpdateCredential(ctx, id, cred); err != nil {
		t.Fatalf("UpdateCredential: %v", err)
	}
	u, _ = s.GetUser(ctx, id)
	if got := u.WebAuthnCredentials()[0].Authenticator.SignCount; got != 5 {
		t.Fatalf("sign count = %d, want 5", got)
	}
}

func TestInMemoryStore_AddCredentialUnknownUser(t *testing.T) {
	s := NewInMemoryStore()
	err := s.AddCredential(context.Background(), []byte("nope"), gowebauthn.Credential{ID: []byte("c")})
	if !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("err = %v, want ErrUserNotFound", err)
	}
}

func TestInMemorySessionStore_OneTimeUse(t *testing.T) {
	ctx := context.Background()
	s := NewInMemorySessionStore()
	data := gowebauthn.SessionData{Challenge: "abc"}

	if err := s.Save(ctx, "k1", data); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := s.Take(ctx, "k1")
	if err != nil {
		t.Fatalf("Take: %v", err)
	}
	if got.Challenge != "abc" {
		t.Fatalf("challenge = %q, want abc", got.Challenge)
	}
	// Second Take must fail — sessions are single-use (replay defense).
	if _, err := s.Take(ctx, "k1"); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("second Take: err = %v, want ErrSessionNotFound", err)
	}
}

func TestInMemorySessionStore_Expiry(t *testing.T) {
	ctx := context.Background()
	s := NewInMemorySessionStore()
	now := time.Unix(1_000_000, 0)
	s.now = func() time.Time { return now }
	s.ttl = time.Minute

	if err := s.Save(ctx, "k", gowebauthn.SessionData{Challenge: "x"}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	// Advance past the TTL before taking.
	now = now.Add(2 * time.Minute)
	if _, err := s.Take(ctx, "k"); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("expired Take: err = %v, want ErrSessionNotFound", err)
	}
}

func TestInMemorySessionStore_MissingKey(t *testing.T) {
	if _, err := NewInMemorySessionStore().Take(context.Background(), "missing"); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("err = %v, want ErrSessionNotFound", err)
	}
}
