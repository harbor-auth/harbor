package clients

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/harbor-auth/harbor/internal/crypto"
	"github.com/harbor-auth/harbor/internal/gen/db"
	"github.com/harbor-auth/harbor/internal/mfa"
)

// mfaKeyResolverQuerier is the narrow interface over *db.Queries that
// DBMFAKeyResolver needs. Production code passes *db.Queries; tests pass a small
// fake.
type mfaKeyResolverQuerier interface {
	GetUser(ctx context.Context, id pgtype.UUID) (db.User, error)
}

// DBMFAKeyResolver implements mfa.KeyResolver by reading a user's home region
// and wrapped DEK from the users table and unwrapping the DEK under the
// regional KEK (docs/DESIGN.md §7.3, §10). It is the seam between the pure
// mfa.Service verification core and the user/key storage: the service uses the
// returned DEK + region to envelope-encrypt/decrypt the TOTP secret.
//
// The unwrapped DEK is returned to the caller (the mfa.Service), which is
// responsible for using it and letting it fall out of scope; this resolver adds
// no persistence or logging of the key material (fail-closed on any error).
type DBMFAKeyResolver struct {
	q    mfaKeyResolverQuerier
	keys crypto.KeyProvider
}

// Compile-time proof that DBMFAKeyResolver implements mfa.KeyResolver.
var _ mfa.KeyResolver = (*DBMFAKeyResolver)(nil)

// NewDBMFAKeyResolver returns a KeyResolver backed by q and keys. q is typically
// *db.Queries; keys is the regional KeyProvider (HSM in prod).
func NewDBMFAKeyResolver(q mfaKeyResolverQuerier, keys crypto.KeyProvider) *DBMFAKeyResolver {
	return &DBMFAKeyResolver{q: q, keys: keys}
}

// ResolveDEK implements mfa.KeyResolver:
//  1. Resolve the user row (unknown/invalid ID → error).
//  2. Unwrap the DEK under the user's region.
//
// It returns the user's home region alongside the DEK so the mfa.Service can
// bind the region into the TOTP secret's AAD. Any unwrap failure propagates
// as-is — never a partial key.
func (r *DBMFAKeyResolver) ResolveDEK(ctx context.Context, userID string) (crypto.DEK, string, error) {
	uid, err := parseUUID(userID)
	if err != nil {
		return crypto.DEK{}, "", fmt.Errorf("clients: ResolveDEK: invalid userID: %w", err)
	}

	user, err := r.q.GetUser(ctx, uid)
	if err != nil {
		return crypto.DEK{}, "", fmt.Errorf("clients: ResolveDEK: get user: %w", err)
	}

	dek, err := r.keys.UnwrapDEK(ctx, user.Region, user.DekWrapped)
	if err != nil {
		return crypto.DEK{}, "", fmt.Errorf("clients: ResolveDEK: unwrap DEK: %w", err)
	}

	return dek, user.Region, nil
}
