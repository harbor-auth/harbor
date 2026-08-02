package webauthn

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	gowebauthn "github.com/go-webauthn/webauthn/webauthn"
)

type InMemoryStore struct {
	mu              sync.RWMutex
	users           map[string]User
	recoveryCleared map[string]bool
}

func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{users: make(map[string]User), recoveryCleared: make(map[string]bool)}
}

func (s *InMemoryStore) PutUser(user User) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[string(user.id)] = user
}

func (s *InMemoryStore) GetUser(_ context.Context, userID []byte) (User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	user, ok := s.users[string(userID)]
	if !ok {
		return User{}, ErrUserNotFound
	}
	return user, nil
}

func (s *InMemoryStore) AddCredential(_ context.Context, userID []byte, cred gowebauthn.Credential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	user, ok := s.users[string(userID)]
	if !ok {
		return ErrUserNotFound
	}
	user.credentials = append(user.credentials, cred)
	s.users[string(userID)] = user
	return nil
}

func (s *InMemoryStore) AddCredentialAndActivateUser(ctx context.Context, userID []byte, cred gowebauthn.Credential) error {
	return s.AddCredential(ctx, userID, cred)
}

func (s *InMemoryStore) UpdateCredential(_ context.Context, userID []byte, cred gowebauthn.Credential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	user, ok := s.users[string(userID)]
	if !ok {
		return ErrUserNotFound
	}
	for i := range user.credentials {
		if bytes.Equal(user.credentials[i].ID, cred.ID) {
			old := user.credentials[i].Authenticator.SignCount
			if old != 0 && cred.Authenticator.SignCount <= old {
				return ErrSignCountRegression
			}
			user.credentials[i] = cred
			s.users[string(userID)] = user
			return nil
		}
	}
	return ErrUserNotFound
}

func (s *InMemoryStore) SetRecoveryComplete(_ context.Context, userID []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[string(userID)]; !ok {
		return ErrUserNotFound
	}
	s.recoveryCleared[string(userID)] = true
	return nil
}

func (s *InMemoryStore) RecoveryCleared(userID []byte) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.recoveryCleared[string(userID)]
}

type sessionEntry struct {
	data    gowebauthn.SessionData
	expires time.Time
}

type InMemorySessionStore struct {
	mu       sync.Mutex
	sessions map[string]sessionEntry
	ttl      time.Duration
	now      func() time.Time
}

func NewInMemorySessionStore() *InMemorySessionStore {
	return &InMemorySessionStore{sessions: make(map[string]sessionEntry), ttl: 5 * time.Minute, now: time.Now}
}

func (s *InMemorySessionStore) Save(_ context.Context, key string, data gowebauthn.SessionData) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[key] = sessionEntry{data: data, expires: s.now().Add(s.ttl)}
	return nil
}

func (s *InMemorySessionStore) Take(_ context.Context, key string) (gowebauthn.SessionData, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.sessions[key]
	if !ok {
		return gowebauthn.SessionData{}, ErrSessionNotFound
	}
	delete(s.sessions, key)
	if s.now().After(entry.expires) {
		return gowebauthn.SessionData{}, ErrSessionNotFound
	}
	return entry.data, nil
}

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
	u, err := s.GetUser(ctx, id)
	if err != nil {
		t.Fatalf("GetUser after AddCredential: %v", err)
	}
	if len(u.WebAuthnCredentials()) != 1 {
		t.Fatalf("want 1 credential, got %d", len(u.WebAuthnCredentials()))
	}

	// UpdateCredential must persist the advanced sign counter.
	cred.Authenticator.SignCount = 5
	if err := s.UpdateCredential(ctx, id, cred); err != nil {
		t.Fatalf("UpdateCredential: %v", err)
	}
	u, err = s.GetUser(ctx, id)
	if err != nil {
		t.Fatalf("GetUser after UpdateCredential: %v", err)
	}
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
