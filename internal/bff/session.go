package bff

import (
	"context"
	"errors"
	"sync"
	"time"
)

// Sentinel errors from the BFF session store. Handlers map these to HTTP status
// codes with PII-free messages (docs/DESIGN.md §6.5).
var (
	// ErrBFFSessionNotFound is returned when no session exists for the given
	// request ID (never issued, already consumed, or pruned).
	ErrBFFSessionNotFound = errors.New("bff: session not found")
	// ErrBFFSessionExpired is returned when the session exists but has exceeded
	// its TTL. Callers should treat this the same as NotFound for security, but
	// may log differently for diagnostics.
	ErrBFFSessionExpired = errors.New("bff: session expired")
)

// BFFSessionRecord holds the state of a BFF session across the OIDC/passkey
// ceremony flow. It is created at /authorize and consumed after FinishAssertion.
//
// Fields are exported for JSON serialization (Redis store) but are otherwise
// treated as opaque by callers.
type BFFSessionRecord struct {
	// RequestID is the opaque, CSPRNG-generated identifier for this session
	// (256-bit, base64url-encoded). It is the store key and the value carried
	// in the __Host-harbor-bff cookie.
	RequestID string

	// State is the OIDC state parameter from the /authorize request, echoed
	// back to the RP after the ceremony completes.
	State string

	// ClientID is the RP's client_id from the /authorize request.
	ClientID string

	// RedirectURI is the validated redirect_uri from the /authorize request.
	RedirectURI string

	// UserID is the authenticated user's internal UUID, populated by
	// FinishAssertion after a successful passkey ceremony. Empty until the
	// user authenticates.
	UserID string

	// ExpiresAt is the absolute time after which the session is invalid.
	// Callers must enforce this; the store may also TTL-evict.
	ExpiresAt time.Time
}

// BFFSessionStore persists BFF session records across the OIDC/passkey ceremony
// flow. The session is created at /authorize, updated with the authenticated
// user_id after FinishAssertion, and deleted after the auth code is issued.
//
// Implementations must be safe for concurrent use. Production uses Redis with
// a 5-minute TTL (docs/plans/bff-session-middleware.md); dev/test uses the
// in-memory implementation.
type BFFSessionStore interface {
	// Create stores a new session record. Returns an error if a session with
	// the same RequestID already exists (collision on CSPRNG output is a
	// critical failure).
	Create(ctx context.Context, record BFFSessionRecord) error

	// Get retrieves the session record by RequestID. Returns
	// ErrBFFSessionNotFound if no such session exists, or ErrBFFSessionExpired
	// if the session has exceeded its TTL.
	Get(ctx context.Context, requestID string) (BFFSessionRecord, error)

	// SetUser updates the UserID field of an existing session. This is called
	// after FinishAssertion to record the authenticated identity. Returns
	// ErrBFFSessionNotFound if the session does not exist.
	SetUser(ctx context.Context, requestID string, userID string) error

	// Delete removes the session record. This is called after the auth code is
	// issued (one-time use). A no-op if the session does not exist.
	Delete(ctx context.Context, requestID string) error
}

// InMemoryBFFSessionStore is a development/testing BFFSessionStore. It is NOT
// for production use — sessions are held in process memory with no encryption
// at rest and no cross-replica sharing.
type InMemoryBFFSessionStore struct {
	mu       sync.Mutex
	sessions map[string]BFFSessionRecord
	now      func() time.Time
}

// NewInMemoryBFFSessionStore returns an empty in-memory BFF session store.
func NewInMemoryBFFSessionStore() *InMemoryBFFSessionStore {
	return &InMemoryBFFSessionStore{
		sessions: make(map[string]BFFSessionRecord),
		now:      time.Now,
	}
}

// Create implements BFFSessionStore.
func (s *InMemoryBFFSessionStore) Create(_ context.Context, record BFFSessionRecord) error {
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
func (s *InMemoryBFFSessionStore) Get(_ context.Context, requestID string) (BFFSessionRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.sessions[requestID]
	if !ok {
		return BFFSessionRecord{}, ErrBFFSessionNotFound
	}
	if s.now().After(record.ExpiresAt) {
		// Expired sessions are treated as not found for security, but we return
		// a distinct error so callers can log appropriately.
		delete(s.sessions, requestID)
		return BFFSessionRecord{}, ErrBFFSessionExpired
	}
	return record, nil
}

// SetUser implements BFFSessionStore.
func (s *InMemoryBFFSessionStore) SetUser(_ context.Context, requestID string, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.sessions[requestID]
	if !ok {
		return ErrBFFSessionNotFound
	}
	if s.now().After(record.ExpiresAt) {
		delete(s.sessions, requestID)
		return ErrBFFSessionExpired
	}
	record.UserID = userID
	s.sessions[requestID] = record
	return nil
}

// Delete implements BFFSessionStore.
func (s *InMemoryBFFSessionStore) Delete(_ context.Context, requestID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, requestID)
	return nil
}
