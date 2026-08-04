// Package mgmtapitest provides management API collaborators for tests outside
// internal/mgmtapi.
package mgmtapitest

import (
	"context"
	"sync"
	"time"

	"github.com/harbor-auth/harbor/internal/mgmtapi"
)

const enrollmentSessionTTL = 10 * time.Minute

type enrollmentEntry struct {
	userHandle []byte
	recovery   bool
	returnTo   string
	expires    time.Time
}

// InMemoryEnrollmentSessionStore is an isolated enrollment handoff fixture.
type InMemoryEnrollmentSessionStore struct {
	mu       sync.Mutex
	sessions map[string]enrollmentEntry
	now      func() time.Time
}

// NewInMemoryEnrollmentSessionStore returns an empty enrollment session store.
func NewInMemoryEnrollmentSessionStore() *InMemoryEnrollmentSessionStore {
	return &InMemoryEnrollmentSessionStore{sessions: make(map[string]enrollmentEntry), now: time.Now}
}

func (s *InMemoryEnrollmentSessionStore) Save(_ context.Context, key string, userHandle []byte, recovery bool, returnTo string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[key] = enrollmentEntry{
		userHandle: append([]byte(nil), userHandle...),
		recovery:   recovery,
		returnTo:   returnTo,
		expires:    s.now().Add(enrollmentSessionTTL),
	}
	return nil
}

func (s *InMemoryEnrollmentSessionStore) UserHandle(_ context.Context, key string) ([]byte, bool, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.sessions[key]
	if !ok || s.now().After(entry.expires) {
		delete(s.sessions, key)
		return nil, false, "", mgmtapi.ErrEnrollmentSessionNotFound
	}
	return append([]byte(nil), entry.userHandle...), entry.recovery, entry.returnTo, nil
}
