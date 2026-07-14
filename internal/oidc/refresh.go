package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// defaultRefreshTTL is the refresh-token lifetime (14 days; docs/DESIGN.md §3.5).
const defaultRefreshTTL = 14 * 24 * time.Hour

// refreshTokenBytes is the raw-random byte length of an opaque refresh token.
// 32 bytes = 256 bits of entropy, well above the RFC 6749 minimum.
const refreshTokenBytes = 32

// RefreshSession is the server-side record for a single opaque refresh token.
// Only the SHA-256 hash of the plaintext token is stored (docs/DESIGN.md §7.4,
// §3.5) — the plaintext is returned to the client exactly once and then
// discarded.
type RefreshSession struct {
	ID          string // UUID string
	Region      string // user's home jurisdiction (§5)
	UserID      string // internal user UUID
	GrantID     string // associated consent grant UUID — always "" until a DB column is added (no persistence yet). The copy-through in Refresh() (newSession.GrantID = session.GrantID) is a placeholder.
	ClientID    string // the RP this session belongs to
	DeviceLabel string // optional: UA string / device name
	TokenHash   []byte // SHA-256 of the opaque plaintext — NEVER the plaintext
	ExpiresAt   time.Time
	RevokedAt   time.Time // zero when active; non-zero once the session is revoked
}

// ErrRefreshTokenNotFound is returned by SessionStore when no active session
// matches the presented token hash (unknown or expired).
var ErrRefreshTokenNotFound = errors.New("oidc: refresh token not found or expired")

// ErrRefreshTokenRevoked is returned when the hash is found but the session has
// been revoked — distinct from not-found so the theft detector can act
// (docs/DESIGN.md §3.5, §11.7).
var ErrRefreshTokenRevoked = errors.New("oidc: refresh token has been revoked (possible theft)")

// SessionStore persists and rotates refresh-token sessions (docs/DESIGN.md §3.5,
// §10). The sqlc-backed implementation is in internal/clients; an in-memory
// stub is available for unit tests.
type SessionStore interface {
	// CreateSession stores a new session. The caller supplies the hash; plaintext
	// is NEVER passed to the store.
	CreateSession(ctx context.Context, s RefreshSession) error

	// GetSessionByTokenHash looks up a session by the SHA-256 of the opaque
	// token. Returns ErrRefreshTokenNotFound when expired/unknown, and
	// ErrRefreshTokenRevoked (with the found session populated) when the session
	// exists but has been revoked.
	GetSessionByTokenHash(ctx context.Context, hash []byte) (RefreshSession, error)

	// RevokeSession soft-deletes a session by ID.
	RevokeSession(ctx context.Context, id string) error

	// RotateSession atomically revokes oldID and stores newSession in a single
	// operation. This prevents the crash window between a separate RevokeSession
	// and CreateSession where a user could be permanently locked out
	// (docs/DESIGN.md §3.5, §11.7).
	RotateSession(ctx context.Context, oldID string, newSession RefreshSession) error

	// RevokeSessionsByUserClient revokes every active session for a
	// (userID, clientID) pairing — the theft-signal family revoke (§3.5, §11.7).
	RevokeSessionsByUserClient(ctx context.Context, userID, clientID string) error
}

// sessionEntry is a stored session plus its revoked flag (in-memory store).
type sessionEntry struct {
	s       RefreshSession
	revoked bool
}

// InMemorySessionStore is a dev/test SessionStore. NOT for production — a real
// store persists sessions durably (internal/clients.DBSessionStore).
//
// Time: expiry checks use time.Now() directly (wall-clock), not an injectable
// clock. Use ForceExpireAllForTest() to fast-forward expiry in tests rather
// than sleeping. A future refactor could inject a clock via the constructor, but
// the current test-helper approach is sufficient for the existing test surface.
type InMemorySessionStore struct {
	mu     sync.Mutex
	byID   map[string]*sessionEntry
	byHash map[string]*sessionEntry // key: base64url(sha256(token))
}

// NewInMemorySessionStore returns an empty store.
func NewInMemorySessionStore() *InMemorySessionStore {
	return &InMemorySessionStore{
		byID:   make(map[string]*sessionEntry),
		byHash: make(map[string]*sessionEntry),
	}
}

// CreateSession implements SessionStore.
func (s *InMemorySessionStore) CreateSession(_ context.Context, rs RefreshSession) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry := &sessionEntry{s: rs}
	s.byID[rs.ID] = entry
	s.byHash[base64.RawURLEncoding.EncodeToString(rs.TokenHash)] = entry
	return nil
}

// GetSessionByTokenHash implements SessionStore.
func (s *InMemorySessionStore) GetSessionByTokenHash(_ context.Context, hash []byte) (RefreshSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := base64.RawURLEncoding.EncodeToString(hash)
	entry, ok := s.byHash[key]
	if !ok {
		return RefreshSession{}, ErrRefreshTokenNotFound
	}
	if entry.revoked {
		return entry.s, ErrRefreshTokenRevoked
	}
	if time.Now().After(entry.s.ExpiresAt) {
		return RefreshSession{}, ErrRefreshTokenNotFound
	}
	return entry.s, nil
}

// RevokeSession implements SessionStore.
func (s *InMemorySessionStore) RevokeSession(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.byID[id]; ok {
		e.revoked = true
		e.s.RevokedAt = time.Now()
	}
	return nil
}

// RotateSession implements SessionStore. Revoke + create happen under a single
// lock acquisition, so there is no crash window between them.
func (s *InMemorySessionStore) RotateSession(_ context.Context, oldID string, newSession RefreshSession) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Revoke old — under the lock, so no crash window between revoke and create.
	if e, ok := s.byID[oldID]; ok {
		e.revoked = true
		e.s.RevokedAt = time.Now()
	}
	// Create new.
	entry := &sessionEntry{s: newSession}
	s.byID[newSession.ID] = entry
	s.byHash[base64.RawURLEncoding.EncodeToString(newSession.TokenHash)] = entry
	return nil
}

// ForceExpireAllForTest immediately back-dates every active session's ExpiresAt
// to one second in the past, simulating TTL expiry without sleeping.
// For use in tests only — not called from production code paths.
//
// NOTE: This method intentionally lives in non-test code (not export_test.go)
// because internal/oidcapi tests call it cross-package on a *InMemorySessionStore
// value imported from internal/oidc. Moving it to export_test.go would make it
// invisible to external test packages (Go test exports are intra-package only)
// without introducing a separate testutil package. Accept as a test-helper
// with a sufficiently obvious name to prevent accidental production use.
func (s *InMemorySessionStore) ForceExpireAllForTest() {
	s.mu.Lock()
	defer s.mu.Unlock()
	past := time.Now().Add(-time.Second)
	for _, e := range s.byID {
		if !e.revoked {
			e.s.ExpiresAt = past
		}
	}
}

// RevokeSessionsByUserClient implements SessionStore (theft signal family revoke).
func (s *InMemorySessionStore) RevokeSessionsByUserClient(_ context.Context, userID, clientID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.byID {
		if e.s.UserID == userID && e.s.ClientID == clientID {
			e.revoked = true
			e.s.RevokedAt = time.Now()
		}
	}
	return nil
}

// hashRefreshToken returns the SHA-256 digest of plaintext. Only the digest is
// persisted — the plaintext is ephemeral (docs/DESIGN.md §7.4).
func hashRefreshToken(plaintext []byte) []byte {
	h := sha256.Sum256(plaintext)
	return h[:]
}

// newOpaqueToken generates a CSPRNG opaque token and returns both the raw
// plaintext (returned once to the caller) and its SHA-256 hash (stored in DB).
func newOpaqueToken() (plaintext []byte, hash []byte, err error) {
	plaintext = make([]byte, refreshTokenBytes)
	if _, err = rand.Read(plaintext); err != nil {
		return nil, nil, fmt.Errorf("refresh: generate token: %w", err)
	}
	hash = hashRefreshToken(plaintext)
	return plaintext, hash, nil
}

// encodeRefreshToken encodes a raw plaintext token as a URL-safe string
// suitable for returning to the client.
func encodeRefreshToken(plaintext []byte) string {
	return base64.RawURLEncoding.EncodeToString(plaintext)
}

// decodeRefreshToken decodes a URL-safe refresh token string back to raw bytes.
func decodeRefreshToken(s string) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("refresh: decode token: %w", err)
	}
	return b, nil
}

// noopSessionStore is the default when no SessionStore is wired (dev/test
// scaffolds that never issue a refresh token).
type noopSessionStore struct{}

func (noopSessionStore) CreateSession(context.Context, RefreshSession) error { return nil }
func (noopSessionStore) GetSessionByTokenHash(context.Context, []byte) (RefreshSession, error) {
	return RefreshSession{}, ErrRefreshTokenNotFound
}
func (noopSessionStore) RevokeSession(context.Context, string) error { return nil }
func (noopSessionStore) RotateSession(context.Context, string, RefreshSession) error { return nil }
func (noopSessionStore) RevokeSessionsByUserClient(context.Context, string, string) error {
	return nil
}
