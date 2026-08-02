// Package bfftest provides BFF collaborators for tests outside internal/bff.
package bfftest

import (
	"context"
	"errors"
	"sync"
	"time"

	harborbff "github.com/harbor-auth/harbor/internal/bff"
	"github.com/harbor-auth/harbor/internal/oidc"
)

// InMemoryBFFSessionStore is an isolated test fixture. Sessions are held in
// process memory with no encryption at rest or cross-replica sharing.
type InMemoryBFFSessionStore struct {
	mu       sync.Mutex
	sessions map[string]harborbff.BFFSessionRecord
	now      func() time.Time
}

// NewInMemoryBFFSessionStore returns an empty in-memory BFF session store.
func NewInMemoryBFFSessionStore() *InMemoryBFFSessionStore {
	return &InMemoryBFFSessionStore{
		sessions: make(map[string]harborbff.BFFSessionRecord),
		now:      time.Now,
	}
}

// Create implements BFFSessionStore.
func (s *InMemoryBFFSessionStore) Create(_ context.Context, record harborbff.BFFSessionRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.sessions[record.RequestID]; exists {
		// CSPRNG collision or replay — both are critical.
		return errors.New("bff: session already exists")
	}
	s.sessions[record.RequestID] = record
	return nil
}

// Get implements BFFSessionStore.
func (s *InMemoryBFFSessionStore) Get(_ context.Context, requestID string) (harborbff.BFFSessionRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.sessions[requestID]
	if !ok {
		return harborbff.BFFSessionRecord{}, harborbff.ErrBFFSessionNotFound
	}
	if s.now().After(record.ExpiresAt) {
		// Expired sessions are treated as not found for security, but we return
		// a distinct error so callers can log appropriately.
		delete(s.sessions, requestID)
		return harborbff.BFFSessionRecord{}, harborbff.ErrBFFSessionExpired
	}
	return record, nil
}

// SetUser implements BFFSessionStore.
func (s *InMemoryBFFSessionStore) SetUser(_ context.Context, requestID string, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.sessions[requestID]
	if !ok {
		return harborbff.ErrBFFSessionNotFound
	}
	if s.now().After(record.ExpiresAt) {
		delete(s.sessions, requestID)
		return harborbff.ErrBFFSessionExpired
	}
	record.UserID = userID
	s.sessions[requestID] = record
	return nil
}

// SetUserWithRecoveryStatus implements BFFSessionStore.
func (s *InMemoryBFFSessionStore) SetUserWithRecoveryStatus(_ context.Context, requestID, userID string, recoveryRequired bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.sessions[requestID]
	if !ok {
		return harborbff.ErrBFFSessionNotFound
	}
	if s.now().After(record.ExpiresAt) {
		delete(s.sessions, requestID)
		return harborbff.ErrBFFSessionExpired
	}
	record.UserID = userID
	record.RecoveryRequired = recoveryRequired
	if recoveryRequired {
		record.SessionScope = harborbff.SessionScopeEnrollmentOnly
	} else {
		record.SessionScope = harborbff.SessionScopeFull
	}
	s.sessions[requestID] = record
	return nil
}

// SetMFAVerified implements BFFSessionStore.
func (s *InMemoryBFFSessionStore) SetMFAVerified(_ context.Context, requestID string, verifiedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.sessions[requestID]
	if !ok {
		return harborbff.ErrBFFSessionNotFound
	}
	if s.now().After(record.ExpiresAt) {
		delete(s.sessions, requestID)
		return harborbff.ErrBFFSessionExpired
	}
	record.MFAVerifiedAt = verifiedAt
	s.sessions[requestID] = record
	return nil
}

// RecordTOTPStepUp atomically verifies ownership and records both the step-up
// timestamp and authentication method on one session.
func (s *InMemoryBFFSessionStore) RecordTOTPStepUp(_ context.Context, requestID, userID string, verifiedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.sessions[requestID]
	if !ok || record.UserID != userID {
		return harborbff.ErrBFFSessionNotFound
	}
	if s.now().After(record.ExpiresAt) {
		delete(s.sessions, requestID)
		return harborbff.ErrBFFSessionExpired
	}
	record.MFAVerifiedAt = verifiedAt
	record.AuthMethod = oidc.AuthMethodTOTP
	s.sessions[requestID] = record
	return nil
}

// SetAuthMethod implements BFFSessionStore.
func (s *InMemoryBFFSessionStore) SetAuthMethod(_ context.Context, requestID string, method oidc.AuthMethod) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.sessions[requestID]
	if !ok {
		return harborbff.ErrBFFSessionNotFound
	}
	if s.now().After(record.ExpiresAt) {
		delete(s.sessions, requestID)
		return harborbff.ErrBFFSessionExpired
	}
	record.AuthMethod = method
	s.sessions[requestID] = record
	return nil
}

func (s *InMemoryBFFSessionStore) SetConsentPending(_ context.Context, requestID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.sessions[requestID]
	if !ok {
		return harborbff.ErrBFFSessionNotFound
	}
	if s.now().After(record.ExpiresAt) {
		delete(s.sessions, requestID)
		return harborbff.ErrBFFSessionExpired
	}
	record.ConsentPending = true
	s.sessions[requestID] = record
	return nil
}

func (s *InMemoryBFFSessionStore) Consume(_ context.Context, requestID string) (harborbff.BFFSessionRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.sessions[requestID]
	if !ok {
		return harborbff.BFFSessionRecord{}, harborbff.ErrBFFSessionNotFound
	}
	delete(s.sessions, requestID)
	if s.now().After(record.ExpiresAt) {
		return harborbff.BFFSessionRecord{}, harborbff.ErrBFFSessionExpired
	}
	return record, nil
}

// Delete implements BFFSessionStore.
func (s *InMemoryBFFSessionStore) Delete(_ context.Context, requestID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, requestID)
	return nil
}
