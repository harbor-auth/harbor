package mgmtapi

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

// ErrEnrollmentSessionNotFound is returned when an enrollment session key is
// unknown or has expired.
var ErrEnrollmentSessionNotFound = errors.New("mgmtapi: enrollment session not found or expired")

// EnrollmentSessionCookieName is the cookie carrying the enrollment session key
// from POST /enroll to the passkey registration ceremony. It MUST match
// webauthn.enrollmentCookieName — the packages are decoupled, so the value is
// duplicated and kept in sync deliberately.
const EnrollmentSessionCookieName = "harbor_enrollment_session"

// enrollmentSessionTTL bounds how long a just-enrolled user has to complete
// passkey registration before the handoff session expires. It is short:
// enrollment and first-passkey registration are a single, contiguous flow.
const enrollmentSessionTTL = 10 * time.Minute

// EnrollmentSessionStore maps a short-lived, opaque session key to the WebAuthn
// user handle of a just-enrolled user. It bridges POST /enroll (which creates
// the user) and the passkey registration ceremony (which must bind to that same
// user WITHOUT a client-supplied, IDOR-prone user_id — docs/DESIGN.md §9, §11.1).
type EnrollmentSessionStore interface {
	// Save associates key with the given user handle for the store's TTL.
	Save(ctx context.Context, key string, userHandle []byte) error
	// UserHandle returns the user handle for key, or ErrEnrollmentSessionNotFound.
	// Unlike a WebAuthn ceremony session it is NOT one-time-use: both
	// register/begin and register/finish read it within the same enrollment.
	UserHandle(ctx context.Context, key string) ([]byte, error)
}

// NewEnrollmentSessionKey returns a 256-bit random, URL-safe opaque key.
func NewEnrollmentSessionKey() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// enrollmentEntry is a stored user handle plus its expiry.
type enrollmentEntry struct {
	userHandle []byte
	expires    time.Time
}

// InMemoryEnrollmentSessionStore is a development/testing EnrollmentSessionStore.
// Production wiring should use a shared, short-TTL store (e.g. Redis) so the
// enrollment→registration handoff works across replicas (docs/DESIGN.md §4.4).
type InMemoryEnrollmentSessionStore struct {
	mu       sync.Mutex
	sessions map[string]enrollmentEntry
	ttl      time.Duration
	now      func() time.Time
}

// NewInMemoryEnrollmentSessionStore returns a store whose entries expire after a
// short TTL — the enrollment→passkey handoff is expected within minutes.
func NewInMemoryEnrollmentSessionStore() *InMemoryEnrollmentSessionStore {
	return &InMemoryEnrollmentSessionStore{
		sessions: make(map[string]enrollmentEntry),
		ttl:      enrollmentSessionTTL,
		now:      time.Now,
	}
}

// Save implements EnrollmentSessionStore.
func (s *InMemoryEnrollmentSessionStore) Save(_ context.Context, key string, userHandle []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Copy so a later mutation of the caller's slice can't change stored state.
	h := make([]byte, len(userHandle))
	copy(h, userHandle)
	s.sessions[key] = enrollmentEntry{userHandle: h, expires: s.now().Add(s.ttl)}
	return nil
}

// UserHandle implements EnrollmentSessionStore, treating an expired entry as
// absent (and evicting it).
func (s *InMemoryEnrollmentSessionStore) UserHandle(_ context.Context, key string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.sessions[key]
	if !ok {
		return nil, ErrEnrollmentSessionNotFound
	}
	if s.now().After(entry.expires) {
		delete(s.sessions, key)
		return nil, ErrEnrollmentSessionNotFound
	}
	return entry.userHandle, nil
}
