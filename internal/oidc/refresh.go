package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
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
	GrantID     string // associated consent grant UUID; persisted via the grant_id FK column (migration 0006). Empty for legacy sessions created before the column was added.
	ClientID    string // the RP this session belongs to
	DeviceLabel string // optional: UA string / device name
	TokenHash   []byte // SHA-256 of the opaque plaintext — NEVER the plaintext
	ExpiresAt   time.Time
	RevokedAt   time.Time // zero when active; non-zero once the session is revoked
	AuthTime    int64     // Unix timestamp when user originally authenticated (OIDC Core §2)
	ACR         string    // authentication context class reference (OIDC Core §2)
	AMR         []string  // authentication methods references (OIDC Core §2)
}

// ErrRefreshTokenNotFound is returned by SessionStore when no active session
// matches the presented token hash (unknown or expired).
var ErrRefreshTokenNotFound = errors.New("oidc: refresh token not found or expired")

// ErrRefreshTokenRevoked is returned when the hash is found but the session has
// been revoked — distinct from not-found so the theft detector can act
// (docs/DESIGN.md §3.5, §11.7).
var ErrRefreshTokenRevoked = errors.New("oidc: refresh token has been revoked (possible theft)")

// SessionStore persists and rotates refresh-token sessions (docs/DESIGN.md §3.5,
// §10). The sqlc-backed implementation is in internal/clients; test fixtures
// live outside this production package.
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

	// RevokeSessionsByGrant revokes every active session for a specific grant,
	// enabling the §11.3 user-initiated disconnect flow where a user can revoke
	// access to a single connected app without affecting other grants.
	RevokeSessionsByGrant(ctx context.Context, grantID string) error
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
func (noopSessionStore) RevokeSession(context.Context, string) error                 { return nil }
func (noopSessionStore) RotateSession(context.Context, string, RefreshSession) error { return nil }
func (noopSessionStore) RevokeSessionsByUserClient(context.Context, string, string) error {
	return nil
}
func (noopSessionStore) RevokeSessionsByGrant(context.Context, string) error { return nil }
