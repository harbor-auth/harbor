package identity

import (
	"context"
	"crypto/rand"
	"fmt"

	"github.com/google/uuid"
	"github.com/harbor-auth/harbor/internal/crypto"
	"github.com/harbor-auth/harbor/internal/region"
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
	// RecoveryRequired records whether the user must complete account recovery
	// setup before normal use (REQ-005). Enrollment always sets this true — a
	// freshly enrolled user has no recovery credential yet.
	RecoveryRequired bool
}

// UserPersister writes a UserRecord to durable storage. The single-method
// interface is deliberately narrow — only the enrollment path needs it.
type UserPersister interface {
	PersistUser(ctx context.Context, r UserRecord) error
}

// FederatedUserPersister writes a corporate-SSO UserRecord to durable
// storage. It is a SEPARATE interface from UserPersister, not a second
// method on it, deliberately: clients.DBUserPersister's PersistUser refuses
// RecoveryRequired=false (REQ-005's guard — every non-federated enrollment
// path relies on that refusal). Splitting persistence into two interfaces
// means EnrollFederated's RecoveryRequired=false record is statically
// incapable of reaching that guard — there is no shared method it could be
// routed through by mistake.
type FederatedUserPersister interface {
	PersistFederatedUser(ctx context.Context, r UserRecord) error
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
	keys             crypto.KeyProvider
	cipher           crypto.Encryptor
	persist          UserPersister
	federatedPersist FederatedUserPersister
}

// NewEnroller constructs an Enroller. The first three arguments must be
// non-nil. federatedPersist is not one of them — EnrollFederated is the only
// caller that needs it, and most Enrollers (the shared, long-lived one
// harbor-mgmt wires for regular signup) never call EnrollFederated at all.
// Wire it with WithFederatedPersister.
func NewEnroller(keys crypto.KeyProvider, cipher crypto.Encryptor, persist UserPersister) *Enroller {
	return &Enroller{keys: keys, cipher: cipher, persist: persist}
}

// WithFederatedPersister wires the federated (SSO) enrollment persistence
// path onto an Enroller, enabling EnrollFederated. Returns e for chaining
// (mirrors clients.DBSessionStore.WithPool). Optional: an Enroller built
// without it can still serve Enroll normally — EnrollFederated fails closed
// if called without one configured.
func (e *Enroller) WithFederatedPersister(fp FederatedUserPersister) *Enroller {
	e.federatedPersist = fp
	return e
}

// PairwiseSecretAAD binds the encrypted pairwise secret to a specific user ID,
// so a blob created for user A cannot pass GCM authentication when opened as
// user B (docs/DESIGN.md §4.4). It is exported so the decryption path
// (internal/clients.DBSecretLoader) can reproduce the exact AAD used at
// enrollment time.
func PairwiseSecretAAD(userID string) []byte {
	return []byte("harbor-pairwise-v1:" + userID)
}

// seal validates rawRegion and produces a freshly sealed UserRecord: a new
// UUID, a fresh 256-bit DEK wrapped under the regional KEK, and a fresh
// 32-byte pairwise secret encrypted under that DEK (AAD = user ID). It does
// NOT set RecoveryRequired and does NOT persist anything — that is each
// caller's job (Enroll sets RecoveryRequired=true and persists via
// UserPersister; EnrollFederated sets it false and persists via
// FederatedUserPersister). Extracted so the two enrollment paths can never
// diverge in how secret material is generated/sealed — only in what
// recovery/persistence policy they apply afterward.
func (e *Enroller) seal(ctx context.Context, rawRegion string) (UserRecord, error) {
	r, err := region.Parse(rawRegion)
	if err != nil {
		return UserRecord{}, fmt.Errorf("identity: invalid region %q: %w", rawRegion, err)
	}

	id := uuid.New()
	userID := id.String()

	dek, err := crypto.GenerateDEK()
	if err != nil {
		return UserRecord{}, fmt.Errorf("identity: generate DEK: %w", err)
	}

	rawPS := make([]byte, 32)
	if _, err := rand.Read(rawPS); err != nil {
		return UserRecord{}, fmt.Errorf("identity: generate pairwise secret: %w", err)
	}

	dekWrapped, err := e.keys.WrapDEK(ctx, string(r), dek)
	if err != nil {
		return UserRecord{}, fmt.Errorf("identity: wrap DEK: %w", err)
	}

	encPS, err := e.cipher.Encrypt(dek, rawPS, PairwiseSecretAAD(userID))
	if err != nil {
		return UserRecord{}, fmt.Errorf("identity: encrypt pairwise secret: %w", err)
	}

	return UserRecord{
		ID:             userID,
		Region:         string(r),
		DekWrapped:     dekWrapped,
		PairwiseSecret: encPS,
	}, nil
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
	rec, err := e.seal(ctx, rawRegion)
	if err != nil {
		return EnrollResult{}, err
	}
	// A newly enrolled user has not yet set up account recovery (REQ-005).
	rec.RecoveryRequired = true
	if err := e.persist.PersistUser(ctx, rec); err != nil {
		return EnrollResult{}, fmt.Errorf("identity: persist user: %w", err)
	}

	return EnrollResult{UserID: rec.ID, Region: rec.Region}, nil
}

// EnrollFederated creates a new user record for a corporate-SSO subject.
// Identical to Enroll in every way it seals a user record — same fresh UUID,
// same region-wrapped DEK, same encrypted pairwise secret — EXCEPT:
// RecoveryRequired is false, and persistence goes through
// FederatedUserPersister, never UserPersister.
//
// RecoveryRequired is false because an SSO user has no Harbor-held
// credential to recover — their recovery path is their employer's IdP.
// Issuing Harbor recovery codes would mint a Harbor-local credential that
// BYPASSES the corporate IdP entirely, undermining the reason the
// organization federated in the first place. (`true` would also fence the
// user into SessionScopeEnrollmentOnly, where bff.RequireFullScope 403s the
// whole dashboard for a user who will never run the passkey ceremony that
// clears it.)
//
// Fails closed with an error if WithFederatedPersister was never called —
// EnrollFederated never falls back to the regular (pool-bound) UserPersister,
// which would violate PersistUser's own recovery_required=true guard.
func (e *Enroller) EnrollFederated(ctx context.Context, rawRegion string) (EnrollResult, error) {
	if e.federatedPersist == nil {
		return EnrollResult{}, fmt.Errorf("identity: EnrollFederated: no federated persister configured (call WithFederatedPersister)")
	}
	rec, err := e.seal(ctx, rawRegion)
	if err != nil {
		return EnrollResult{}, err
	}
	rec.RecoveryRequired = false
	if err := e.federatedPersist.PersistFederatedUser(ctx, rec); err != nil {
		return EnrollResult{}, fmt.Errorf("identity: persist federated user: %w", err)
	}

	return EnrollResult{UserID: rec.ID, Region: rec.Region}, nil
}
