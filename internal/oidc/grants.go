package oidc

import (
	"context"
	"time"
)

// Grant is the domain representation of a user<->RP consent record
// (docs/DESIGN.md §10, §11.3). It carries only stdlib types so internal/oidc
// remains free of DB-layer dependencies (internal/clients does the mapping).
type Grant struct {
	ID          string   // UUID string
	Region      string   // user's home jurisdiction (DESIGN §5.4)
	UserID      string   // UUID string
	ClientID    string   // relying_parties.client_id
	PairwiseSub string   // PPID this RP sees for this user (DESIGN §3.2)
	Scopes      []string // consented scopes
	CreatedAt   time.Time
	RevokedAt   *time.Time // nil = active grant
}

// NewGrant is the input to GrantStore.CreateGrant. The store is responsible for
// minting the ID and setting CreatedAt; the caller supplies the region so the
// row satisfies the user-owned-row contract (DESIGN §10).
type NewGrant struct {
	Region      string
	UserID      string
	ClientID    string
	PairwiseSub string
	Scopes      []string
}

// GrantStore persists and queries consent grants (user<->RP relationships).
// The sqlc-backed implementation is in internal/clients; test fixtures live
// outside this production package.
//
// FindGrant mirrors the (T, bool, error) convention of ClientRegistry.Lookup:
// found=false means no active grant exists (not an error).
type GrantStore interface {
	// FindGrant looks up the active (non-revoked) grant for a (userID, clientID)
	// pair. found=false means the user has not (yet) consented.
	FindGrant(ctx context.Context, userID, clientID string) (Grant, bool, error)

	// FindGrantByPPID looks up the active (non-revoked) grant by pairwise_sub
	// (PPID) and clientID. Used during RP-Initiated Logout to reverse-lookup
	// the userID from the id_token_hint's sub claim. found=false means no
	// active grant exists for this PPID+client pair.
	FindGrantByPPID(ctx context.Context, ppid, clientID string) (Grant, bool, error)

	// CreateGrant records a new consent. The store mints the grant ID.
	CreateGrant(ctx context.Context, g NewGrant) (Grant, error)

	// RevokeGrant soft-deletes a grant by its UUID string ID.
	RevokeGrant(ctx context.Context, id string) error

	// ListGrantsByUser returns all active (non-revoked) grants for a user,
	// newest first — powers the "connected apps" dashboard (DESIGN §11.3).
	ListGrantsByUser(ctx context.Context, userID string) ([]Grant, error)
}

// GrantScopeUpdater updates an already-established canonical grant in place.
// Scope approval must not revoke and recreate the grant because refresh
// sessions are bound to its stable ID.
type GrantScopeUpdater interface {
	UpdateGrantScopes(ctx context.Context, userID, clientID string, scopes []string) (Grant, error)
}

// GrantDisconnector atomically revokes a canonical grant and every refresh
// session bound to it. The boolean reports whether an active grant was won by
// this caller, making concurrent disconnect requests idempotent.
type GrantDisconnector interface {
	RevokeGrantAndSessions(ctx context.Context, id string) (bool, error)
}

// noopGrantStore is a GrantStore that records nothing. Used as the default in
// ServiceConfig when no persistent store is wired (e.g. dev/test scaffolds that
// auto-approve consent without persisting it).
type noopGrantStore struct{}

func (noopGrantStore) FindGrant(_ context.Context, _, _ string) (Grant, bool, error) {
	// Always returns not-found. See NewService panic guard in service.go for why
	// this must NOT be paired with a real SessionStore.
	return Grant{}, false, nil
}
func (noopGrantStore) FindGrantByPPID(_ context.Context, _, _ string) (Grant, bool, error) {
	return Grant{}, false, nil
}
func (noopGrantStore) CreateGrant(_ context.Context, _ NewGrant) (Grant, error) {
	return Grant{}, nil
}
func (noopGrantStore) RevokeGrant(_ context.Context, _ string) error { return nil }
func (noopGrantStore) ListGrantsByUser(_ context.Context, _ string) ([]Grant, error) {
	return nil, nil
}
