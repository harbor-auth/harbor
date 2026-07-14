package clients

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/harbor/harbor/internal/crypto"
	"github.com/harbor/harbor/internal/gen/db"
	"github.com/harbor/harbor/internal/identity"
	"github.com/harbor/harbor/internal/oidc"
)

// secretLoaderQuerier is the narrow interface over *db.Queries that
// DBSecretLoader needs. Production code passes *db.Queries; tests pass a small
// fake.
type secretLoaderQuerier interface {
	GetUser(ctx context.Context, id pgtype.UUID) (db.User, error)
}

// DBSecretLoader implements oidc.UserSecretLoader by decrypting the user's
// pairwise_secret from the users table (docs/DESIGN.md §4.4, §10). It unwraps
// the user's DEK under the regional KEK, then AES-256-GCM-decrypts the stored
// secret with the user-bound AAD.
//
// The plaintext secret is NEVER persisted and NEVER logged — it exists only in
// memory for the duration of a resolution (§6.5.7). On any failure it returns
// the error and no partial secret (fail-closed).
type DBSecretLoader struct {
	q      secretLoaderQuerier
	keys   crypto.KeyProvider
	cipher crypto.Decryptor
}

// Compile-time proof that DBSecretLoader implements oidc.UserSecretLoader.
var _ oidc.UserSecretLoader = (*DBSecretLoader)(nil)

// NewDBSecretLoader returns a UserSecretLoader backed by q, keys, and cipher.
// q is typically *db.Queries; keys is the regional KeyProvider (HSM in prod);
// cipher is a crypto.Cipher.
func NewDBSecretLoader(q secretLoaderQuerier, keys crypto.KeyProvider, cipher crypto.Decryptor) *DBSecretLoader {
	return &DBSecretLoader{q: q, keys: keys, cipher: cipher}
}

// LoadUserSecret implements oidc.UserSecretLoader:
//  1. Resolve the user row (unknown → oidc.ErrUserSecretNotFound).
//  2. Unwrap the DEK under the user's region.
//  3. Decrypt users.pairwise_secret with the user-bound AAD.
//
// A decrypt/unwrap failure propagates as-is — never a partial secret.
func (l *DBSecretLoader) LoadUserSecret(ctx context.Context, userID string) (oidc.UserSecret, error) {
	uUID, err := parseUUID(userID)
	if err != nil {
		return oidc.UserSecret{}, fmt.Errorf("clients: LoadUserSecret: invalid userID: %w", err)
	}

	user, err := l.q.GetUser(ctx, uUID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return oidc.UserSecret{}, oidc.ErrUserSecretNotFound
		}
		return oidc.UserSecret{}, fmt.Errorf("clients: LoadUserSecret: get user: %w", err)
	}

	dek, err := l.keys.UnwrapDEK(ctx, user.Region, user.DekWrapped)
	if err != nil {
		return oidc.UserSecret{}, fmt.Errorf("clients: LoadUserSecret: unwrap DEK: %w", err)
	}
	// Zero the DEK bytes once LoadUserSecret returns. DEK is [32]byte (a value
	// type), so clear(dek[:]) uses the Go 1.21+ builtin for compiler-resistant
	// zeroing. Two inherent limitations accepted as §7.3 best-effort hygiene:
	//   (a) Decrypt receives dek by value — that stack-frame copy cannot be
	//       zeroed from here (Go value-type semantics; would require *DEK).
	//   (b) The defer runs post-facto — AFTER Decrypt returns — so the DEK is
	//       live in this frame's memory for the full duration of the Decrypt call.
	// What the defer DOES protect: the local variable's stack slot is zeroed
	// before the goroutine's stack page is reused, preventing the plaintext DEK
	// from leaking into future allocations on this goroutine.
	defer func() { clear(dek[:]) }()

	secret, err := l.cipher.Decrypt(dek, user.PairwiseSecret, identity.PairwiseSecretAAD(userID))
	if err != nil {
		return oidc.UserSecret{}, fmt.Errorf("clients: LoadUserSecret: decrypt pairwise secret: %w", err)
	}

	return oidc.UserSecret{Region: user.Region, Secret: secret}, nil
}
