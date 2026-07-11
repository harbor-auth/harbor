package identity

import (
	"context"
	"crypto/rand"
	"fmt"

	"github.com/google/uuid"
	"github.com/harbor/harbor/internal/crypto"
	"github.com/harbor/harbor/internal/region"
)

// UserRecord is the set of fields to be written to the users table during
// enrollment. DekWrapped is the DEK sealed under the regional KEK;
// PairwiseSecret is the raw random secret encrypted under that same DEK —
// neither is ever stored in plaintext (docs/DESIGN.md §4.4, §10).
type UserRecord struct {
	ID             string // UUID v4 string
	Region         string // validated region string
	DekWrapped     []byte // KeyProvider.WrapDEK output
	PairwiseSecret []byte // Cipher.Encrypt(dek, rawSecret, aad) output
}

// UserPersister writes a UserRecord to durable storage. The single-method
// interface is deliberately narrow — only the enrollment path needs it.
type UserPersister interface {
	PersistUser(ctx context.Context, r UserRecord) error
}

// EnrollResult is returned on successful enrollment.
type EnrollResult struct {
	UserID string
	Region string
}

// Enroller orchestrates user enrollment: it assigns a region, generates a
// fresh DEK and pairwise secret, wraps/encrypts them under the regional KEK,
// and delegates persistence. The logic is pure: it has no database client —
// that lives behind UserPersister (docs/DESIGN.md §1.7).
type Enroller struct {
	keys    crypto.KeyProvider
	cipher  crypto.Encryptor
	persist UserPersister
}

// NewEnroller constructs an Enroller. All three arguments must be non-nil.
func NewEnroller(keys crypto.KeyProvider, cipher crypto.Encryptor, persist UserPersister) *Enroller {
	return &Enroller{keys: keys, cipher: cipher, persist: persist}
}

// pairwiseSecretAAD binds the encrypted pairwise secret to a specific user ID,
// so a blob created for user A cannot pass GCM authentication when opened as
// user B (docs/DESIGN.md §4.4).
func pairwiseSecretAAD(userID string) []byte {
	return []byte("harbor-pairwise-v1:" + userID)
}

// Enroll creates a new user record in the given region:
//  1. Resolve and validate the region.
//  2. Generate a stable user UUID.
//  3. Generate a fresh 256-bit DEK.
//  4. Generate a 32-byte per-user pairwise secret.
//  5. Wrap the DEK under the regional KEK.
//  6. Encrypt the pairwise secret with the DEK (AAD = user ID).
//  7. Delegate persistence of the sealed record to UserPersister.
func (e *Enroller) Enroll(ctx context.Context, rawRegion string) (EnrollResult, error) {
	r, err := region.Resolve(rawRegion)
	if err != nil {
		return EnrollResult{}, fmt.Errorf("identity: invalid region %q: %w", rawRegion, err)
	}

	id := uuid.New()
	userID := id.String()

	dek, err := crypto.GenerateDEK()
	if err != nil {
		return EnrollResult{}, fmt.Errorf("identity: generate DEK: %w", err)
	}

	rawPS := make([]byte, 32)
	if _, err := rand.Read(rawPS); err != nil {
		return EnrollResult{}, fmt.Errorf("identity: generate pairwise secret: %w", err)
	}

	dekWrapped, err := e.keys.WrapDEK(ctx, string(r), dek)
	if err != nil {
		return EnrollResult{}, fmt.Errorf("identity: wrap DEK: %w", err)
	}

	encPS, err := e.cipher.Encrypt(dek, rawPS, pairwiseSecretAAD(userID))
	if err != nil {
		return EnrollResult{}, fmt.Errorf("identity: encrypt pairwise secret: %w", err)
	}

	rec := UserRecord{
		ID:             userID,
		Region:         string(r),
		DekWrapped:     dekWrapped,
		PairwiseSecret: encPS,
	}
	if err := e.persist.PersistUser(ctx, rec); err != nil {
		return EnrollResult{}, fmt.Errorf("identity: persist user: %w", err)
	}

	return EnrollResult{UserID: userID, Region: string(r)}, nil
}
