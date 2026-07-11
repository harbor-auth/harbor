package oidc

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/harbor/harbor/internal/identity"
)

// AuthSource yields the authenticated user's internal ID for the current
// request. It is the seam over the §11.2 passkey-login + dashboard-session
// step: the real implementation reads the signed-in subject from the BFF
// session (WebAuthn login already completed), NEVER from a client-supplied
// value. Keeping it an interface lets internal/oidc stay free of
// internal/webauthn (enforced by the arch test).
type AuthSource interface {
	AuthenticatedUserID(ctx context.Context) (string, error)
}

// FixedAuthSource returns a fixed user ID. SCAFFOLD/dev only — replace with the
// real BFF-session-backed AuthSource in production.
type FixedAuthSource struct{ userID string }

// NewFixedAuthSource returns an AuthSource that always authenticates as userID.
func NewFixedAuthSource(userID string) *FixedAuthSource {
	return &FixedAuthSource{userID: userID}
}

// AuthenticatedUserID implements AuthSource.
func (a *FixedAuthSource) AuthenticatedUserID(_ context.Context) (string, error) {
	return a.userID, nil
}

// UserSecret is a user's plaintext pairwise secret plus their home region. The
// secret is the HMAC key for PPID derivation (docs/DESIGN.md §3.2). It is held
// in memory ONLY transiently during resolution — never persisted, never logged
// (§6.5.7).
type UserSecret struct {
	Region string
	Secret []byte
}

// ErrUserSecretNotFound is returned by UserSecretLoader when no user exists for
// the given ID. It is distinct from a decrypt/unwrap failure so the caller can
// map it to the right response without leaking which failure occurred.
var ErrUserSecretNotFound = errors.New("oidc: user pairwise secret not found")

// UserSecretLoader loads and decrypts a user's pairwise secret. The DB-backed
// implementation (internal/clients.DBSecretLoader) unwraps the user's DEK and
// decrypts users.pairwise_secret; an in-memory implementation is available for
// tests and dev wiring.
type UserSecretLoader interface {
	LoadUserSecret(ctx context.Context, userID string) (UserSecret, error)
}

// InMemorySecretLoader is a dev/test UserSecretLoader. NOT for production — a
// real loader decrypts from the users table (internal/clients.DBSecretLoader).
type InMemorySecretLoader struct {
	mu      sync.RWMutex
	secrets map[string]UserSecret
}

// NewInMemorySecretLoader returns an empty loader.
func NewInMemorySecretLoader() *InMemorySecretLoader {
	return &InMemorySecretLoader{secrets: make(map[string]UserSecret)}
}

// Put seeds or replaces the secret for userID.
func (l *InMemorySecretLoader) Put(userID string, us UserSecret) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.secrets[userID] = us
}

// LoadUserSecret implements UserSecretLoader.
func (l *InMemorySecretLoader) LoadUserSecret(_ context.Context, userID string) (UserSecret, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	us, ok := l.secrets[userID]
	if !ok {
		return UserSecret{}, ErrUserSecretNotFound
	}
	return us, nil
}

// PPIDSessionResolverConfig wires a PPIDSessionResolver's collaborators. All
// three are required.
type PPIDSessionResolverConfig struct {
	Auth   AuthSource
	Loader UserSecretLoader
	Grants GrantStore
}

// PPIDSessionResolver is the real SessionResolver (docs/DESIGN.md §3.2, §11.2).
// It authenticates the user, resolves the per-RP pairwise subject (PPID), and
// records consent — replacing the fixed-subject stub. It is the seam that
// finally invokes identity.DerivePPID on the hot path, so a real user gets a
// stable, non-correlating sub.
//
// FAIL-CLOSED (§11.7): on ANY error it returns an empty subject and the error,
// never a raw user_id as the subject. Leaking user_id as sub would break
// cross-RP unlinkability.
type PPIDSessionResolver struct {
	auth   AuthSource
	loader UserSecretLoader
	grants GrantStore
}

// Compile-time proof that PPIDSessionResolver implements SessionResolver.
var _ SessionResolver = (*PPIDSessionResolver)(nil)

// NewPPIDSessionResolver constructs a PPIDSessionResolver.
func NewPPIDSessionResolver(cfg PPIDSessionResolverConfig) *PPIDSessionResolver {
	return &PPIDSessionResolver{
		auth:   cfg.Auth,
		loader: cfg.Loader,
		grants: cfg.Grants,
	}
}

// Resolve runs the login + consent step and returns the per-RP PPID:
//
//  1. Authenticate the user (real user_id).
//  2. Load + decrypt the user's pairwise secret (fail closed).
//  3. Look up an existing consent grant for (userID, client).
//     - found: return the frozen grant.PairwiseSub directly — stable across
//       calls, no re-derivation (§3.2.3).
//     - not found (first consent): derive sub = DerivePPID(secret, sector, uid)
//       and record a new grant carrying that sub + the consented scopes.
//
// The resolved sub flows unchanged through /authorize → code → /token into the
// token's sub claim.
func (r *PPIDSessionResolver) Resolve(ctx context.Context, client Client, scope string) (string, string, bool, error) {
	userID, err := r.auth.AuthenticatedUserID(ctx)
	if err != nil {
		return "", "", false, err
	}

	us, err := r.loader.LoadUserSecret(ctx, userID)
	if err != nil {
		// Fail closed: never fall back to userID as the subject.
		return "", "", false, err
	}

	grant, found, err := r.grants.FindGrant(ctx, userID, client.ID)
	if err != nil {
		return "", "", false, err
	}
	if found {
		return grant.PairwiseSub, userID, true, nil
	}

	// First consent: derive the PPID now. The sector_id groups the RP's redirect
	// URIs for pairwise derivation (§3.2); without it we cannot produce a
	// non-correlating sub, so we fail closed rather than guess.
	if client.SectorID == "" {
		return "", "", false, fmt.Errorf("session: client %q has no sector_id", client.ID)
	}
	sub, err := identity.DerivePPID(us.Secret, client.SectorID, userID)
	if err != nil {
		return "", "", false, err
	}

	if _, err := r.grants.CreateGrant(ctx, NewGrant{
		Region:      us.Region,
		UserID:      userID,
		ClientID:    client.ID,
		PairwiseSub: sub,
		Scopes:      strings.Fields(scope),
	}); err != nil {
		return "", "", false, err
	}

	return sub, userID, true, nil
}
