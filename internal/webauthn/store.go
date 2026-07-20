package webauthn

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"time"

	gowebauthn "github.com/go-webauthn/webauthn/webauthn"
)

// Sentinel errors from the stores. Handlers map these to HTTP status codes
// (handlers.go) with PII-free messages (docs/DESIGN.md §6.5).
var (
	ErrUserNotFound    = errors.New("webauthn: user not found")
	ErrSessionNotFound = errors.New("webauthn: session not found or expired")
	// ErrSignCountRegression is returned when a credential update would move the
	// signature counter backwards (or not forward) — a clone signal that must
	// never be persisted (docs/DESIGN.md §3.1).
	ErrSignCountRegression = errors.New("webauthn: signature counter regression")
)

// Store persists users and their passkey credentials. In production this is
// backed by the sqlc queries over the users/credentials tables (db/queries);
// here it is an interface so the ceremony logic stays pure and testable.
//
// All lookups are by the opaque WebAuthn user handle; there is no cross-user or
// cross-region enumeration surface by construction (docs/DESIGN.md §5).
type Store interface {
	// GetUser returns the user and their enrolled credentials, or
	// ErrUserNotFound.
	GetUser(ctx context.Context, userID []byte) (User, error)
	// AddCredential appends a newly-registered passkey to the user (used when a
	// user who is ALREADY active enrolls an additional passkey).
	AddCredential(ctx context.Context, userID []byte, cred gowebauthn.Credential) error
	// AddCredentialAndActivateUser atomically persists the user's FIRST passkey
	// AND flips their status from "pending" to "active" (design decision 3,
	// §11.1). Database-backed implementations MUST perform both writes in a
	// single transaction and roll back on any failure, so enrollment can never
	// leave a user "pending" with a credential, nor "active" with none.
	AddCredentialAndActivateUser(ctx context.Context, userID []byte, cred gowebauthn.Credential) error
	// UpdateCredential persists changes to an existing passkey — notably the
	// advanced signature counter after a successful assertion (WebAuthn clone
	// detection, docs/DESIGN.md §3.1).
	UpdateCredential(ctx context.Context, userID []byte, cred gowebauthn.Credential) error
}

// SessionStore holds the WebAuthn SessionData (challenge + parameters) between
// the Begin and Finish steps of a ceremony. The data is one-time-use: Take
// removes it so a challenge cannot be replayed.
type SessionStore interface {
	Save(ctx context.Context, key string, data gowebauthn.SessionData) error
	// Take returns the stored session and deletes it, or ErrSessionNotFound.
	Take(ctx context.Context, key string) (gowebauthn.SessionData, error)
}

// InMemoryStore is a development/testing Store. It is NOT for production use —
// it holds credentials in process memory with no encryption at rest.
type InMemoryStore struct {
	mu    sync.RWMutex
	users map[string]User
}

// NewInMemoryStore returns an empty in-memory Store.
func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{users: make(map[string]User)}
}

// PutUser seeds or replaces a user (used to provision accounts before passkey
// enrollment; tests and dev wiring call this directly).
func (s *InMemoryStore) PutUser(user User) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[string(user.id)] = user
}

// GetUser implements Store.
func (s *InMemoryStore) GetUser(_ context.Context, userID []byte) (User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	user, ok := s.users[string(userID)]
	if !ok {
		return User{}, ErrUserNotFound
	}
	return user, nil
}

// AddCredential implements Store.
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

// AddCredentialAndActivateUser implements Store. The in-memory User has no
// status column, so "activation" is implicit: this simply adds the credential.
// The atomic pending→active flip is a database concern — see DBStore.
func (s *InMemoryStore) AddCredentialAndActivateUser(ctx context.Context, userID []byte, cred gowebauthn.Credential) error {
	return s.AddCredential(ctx, userID, cred)
}

// UpdateCredential implements Store: replaces the stored credential whose ID
// matches, so the advanced sign counter is persisted.
func (s *InMemoryStore) UpdateCredential(_ context.Context, userID []byte, cred gowebauthn.Credential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	user, ok := s.users[string(userID)]
	if !ok {
		return ErrUserNotFound
	}
	for i := range user.credentials {
		if bytes.Equal(user.credentials[i].ID, cred.ID) {
			// Defensive monotonicity guard: the counter must strictly increase
			// (except the first assertion, where the stored count is still 0). A
			// non-increasing counter is a clone signal (docs/DESIGN.md §3.1) — the
			// service already fails closed on CloneWarning, but we refuse to persist
			// a regression here too so the stored counter can never move backwards.
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

// sessionEntry is a stored ceremony session plus its expiry.
type sessionEntry struct {
	data    gowebauthn.SessionData
	expires time.Time
}

// InMemorySessionStore is a development/testing SessionStore. Production wiring
// should use RedisSessionStore (see docs/plans/webauthn-session-store.md) so the
// ceremony works across replicas.
type InMemorySessionStore struct {
	mu       sync.Mutex
	sessions map[string]sessionEntry
	ttl      time.Duration
	now      func() time.Time
}

// NewInMemorySessionStore returns a session store whose entries expire after a
// fixed TTL (short — challenges are single-use and must not linger).
func NewInMemorySessionStore() *InMemorySessionStore {
	return &InMemorySessionStore{
		sessions: make(map[string]sessionEntry),
		ttl:      5 * time.Minute,
		now:      time.Now,
	}
}

// Save implements SessionStore.
func (s *InMemorySessionStore) Save(_ context.Context, key string, data gowebauthn.SessionData) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[key] = sessionEntry{data: data, expires: s.now().Add(s.ttl)}
	return nil
}

// Take implements SessionStore: returns and deletes the session (one-time use),
// treating an expired entry as absent.
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
