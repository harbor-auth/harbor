package oidc

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/harbor-auth/harbor/internal/identity"
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
// decrypts users.pairwise_secret; test fixtures live outside this production
// package.
type UserSecretLoader interface {
	LoadUserSecret(ctx context.Context, userID string) (UserSecret, error)
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
// records explicit consent through Approve. Resolve is read-only. It is the seam that
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

// Resolve authenticates and derives a stable pairwise subject. It never records
// consent: authentication and an authorization request are not an approval.
func (r *PPIDSessionResolver) Resolve(ctx context.Context, client Client, _ string) (string, string, bool, error) {
	userID, err := r.auth.AuthenticatedUserID(ctx)
	if err != nil {
		return "", "", false, err
	}
	grant, found, err := r.grants.FindGrant(ctx, userID, client.ID)
	if err != nil {
		return "", "", false, err
	}
	if found {
		return grant.PairwiseSub, userID, true, nil
	}
	us, err := r.loader.LoadUserSecret(ctx, userID)
	if err != nil {
		return "", "", false, err
	}
	if client.SectorID == "" {
		return "", "", false, fmt.Errorf("session: client has no sector_id")
	}
	sub, err := identity.DerivePPID(us.Secret, client.SectorID, userID)
	return sub, userID, err == nil, err
}

// Approve is called only after the browser's explicit consent decision. The
// database merges concurrent approvals without losing scopes or changing the
// active grant ID. After revocation it creates a fresh lifetime, with the same
// stable pairwise subject.
func (r *PPIDSessionResolver) Approve(ctx context.Context, client Client, scope string) (Grant, error) {
	sub, userID, approved, err := r.Resolve(ctx, client, scope)
	if err != nil {
		return Grant{}, err
	}
	if !approved {
		return Grant{}, fmt.Errorf("session: user did not approve")
	}
	us, err := r.loader.LoadUserSecret(ctx, userID)
	if err != nil {
		return Grant{}, err
	}
	scopes := CanonicalizeScopes(strings.Fields(scope))
	return r.grants.CreateGrant(ctx, NewGrant{Region: us.Region, UserID: userID,
		ClientID: client.ID, PairwiseSub: sub, Scopes: scopes, EmailConsent: containsScope(scopes, "email")})
}

func containsScope(scopes []string, wanted string) bool {
	for _, scope := range scopes {
		if scope == wanted {
			return true
		}
	}
	return false
}

// ConsentedScopes excludes the old relay-worded email permission until the
// user explicitly approves sharing their verified real email address.
func ConsentedScopes(grant Grant) []string {
	scopes := make([]string, 0, len(grant.Scopes))
	for _, scope := range grant.Scopes {
		if scope != "email" || grant.EmailConsent {
			scopes = append(scopes, scope)
		}
	}
	return scopes
}
