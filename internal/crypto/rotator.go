package crypto

import (
	"context"
	"fmt"
	"time"
)

// NewKeyMaterial is the material persisted when a new signing key is created
// (in pending state) during a rotation. Private-key wrapping is handled by the
// store adapter (docs/DESIGN.md §7.3): the KeyRotator only forwards the public
// JWK and lifecycle metadata; the private key stays inside the Signer (or HSM).
type NewKeyMaterial struct {
	// Kid is the new key's identifier (RFC 7638 thumbprint).
	Kid string
	// PublicJWK is the public key published in JWKS.
	PublicJWK JWK
	// Region is the data-sovereignty jurisdiction the key belongs to.
	Region string
	// CreatedAt is when the key entered pending state.
	CreatedAt time.Time
}

// RotationStore is the persistence seam the KeyRotator depends on. It operates
// on crypto domain types so the crypto package stays free of any DB import
// (internal/clients imports crypto, not the reverse). internal/clients provides
// a DB-backed adapter that satisfies this interface.
//
// Implementations must be safe for concurrent use.
type RotationStore interface {
	// Create persists a new key in pending state.
	Create(ctx context.Context, key NewKeyMaterial) error

	// ActiveKid returns the kid of the current active key, or "" if there is
	// no active key (e.g. the very first rotation).
	ActiveKid(ctx context.Context) (string, error)

	// Promote transitions the pending key with the given kid to active, stamping
	// promotedAt. The store is responsible for enforcing the one-active-key
	// invariant.
	Promote(ctx context.Context, kid string, promotedAt time.Time) error

	// Retire transitions the key with the given kid to retired (removed from JWKS).
	Retire(ctx context.Context, kid string) error
}

// RotateOptions configures a single Rotate call.
type RotateOptions struct {
	// Emergency, when true, performs an emergency rotation (§3.5.4 "nuclear
	// option"): zero grace and overlap windows. The new key is promoted to
	// active immediately and the old key is retired (removed from JWKS)
	// immediately — every in-flight token signed with the old kid is rejected
	// on its next verify. Use only when the signing key is confirmed compromised.
	Emergency bool

	// Region is the data-sovereignty jurisdiction stamped on the new key.
	Region string
}

// RotateResult reports the outcome of a Rotate call.
type RotateResult struct {
	// NewKid is the identifier of the newly created signing key.
	NewKid string
	// OldKid is the identifier of the key being rotated out, or "" if there was
	// no prior active key.
	OldKid string
	// PromoteAt is when the new key becomes active. For an emergency rotation
	// this is "now" and the promotion has already been applied.
	PromoteAt time.Time
	// RetireOldAt is when the old key is retired (removed from JWKS). Zero if
	// there was no old key. For an emergency rotation this is "now" and the
	// retirement has already been applied.
	RetireOldAt time.Time
	// Emergency reports whether this rotation used zero grace/overlap windows.
	Emergency bool
}

// KeyRotator orchestrates the full signing-key rotation lifecycle
// (docs/DESIGN.md §7.3, §3.5.4):
//
//	generate → pending (in JWKS, not signing)
//	              │ grace period
//	              ▼
//	           active (signs new tokens; old key begins draining)
//	              │ overlap window
//	              ▼
//	           retired (old key removed from JWKS)
//
// It combines a RotationManager (timing/state-machine rules), a RotationStore
// (durable metadata), and a MultiKeyProvider (the in-memory set of signers
// published in JWKS). Rotate creates the new pending key and publishes it;
// scheduled rotations then call Promote (after the grace period) and Retire
// (after the overlap window), while an emergency rotation applies both inline.
type KeyRotator struct {
	mgr      *RotationManager
	provider *MultiKeyProvider
	store    RotationStore
	generate func() (Signer, error)
	clock    func() time.Time
}

// NewKeyRotator constructs a KeyRotator. By default it generates dev-only
// LocalSigners and reads wall-clock time; use WithGenerator / WithClock to
// inject an HSM-backed generator or a controllable clock (tests).
func NewKeyRotator(mgr *RotationManager, provider *MultiKeyProvider, store RotationStore) *KeyRotator {
	return &KeyRotator{
		mgr:      mgr,
		provider: provider,
		store:    store,
		generate: func() (Signer, error) { return NewLocalSigner() },
		clock:    time.Now,
	}
}

// WithGenerator returns a copy of the rotator that mints new signers via gen.
func (r *KeyRotator) WithGenerator(gen func() (Signer, error)) *KeyRotator {
	cp := *r
	cp.generate = gen
	return &cp
}

// WithClock returns a copy of the rotator using clock as its time source.
func (r *KeyRotator) WithClock(clock func() time.Time) *KeyRotator {
	cp := *r
	cp.clock = clock
	return &cp
}

// Rotate initiates a key rotation. It generates a new key, persists it in
// pending state, and publishes it in JWKS. For a scheduled rotation it returns
// the computed promotion and retirement times for the caller's scheduler to act
// on; for an emergency rotation it promotes the new key and retires the old key
// inline before returning.
func (r *KeyRotator) Rotate(ctx context.Context, opts RotateOptions) (RotateResult, error) {
	// 1. Generate the new key.
	signer, err := r.generate()
	if err != nil {
		return RotateResult{}, fmt.Errorf("crypto: rotate: generate key: %w", err)
	}
	newKid := signer.KeyID()
	now := r.clock()

	// 2. Identify the key being rotated out (may be empty on first rotation).
	oldKid, err := r.store.ActiveKid(ctx)
	if err != nil {
		return RotateResult{}, fmt.Errorf("crypto: rotate: lookup active key: %w", err)
	}

	// 3. Persist the new key in pending state.
	if err := r.store.Create(ctx, NewKeyMaterial{
		Kid:       newKid,
		PublicJWK: signer.PublicJWK(),
		Region:    opts.Region,
		CreatedAt: now,
	}); err != nil {
		return RotateResult{}, fmt.Errorf("crypto: rotate: persist pending key %q: %w", newKid, err)
	}

	// 4. Publish the new key in JWKS immediately (pending: present but not signing).
	if err := r.provider.Add(signer); err != nil {
		return RotateResult{}, fmt.Errorf("crypto: rotate: publish pending key %q: %w", newKid, err)
	}

	// 5. Compute the schedule. Emergency rotations use zero grace/overlap.
	mgr := r.mgr
	if opts.Emergency {
		mgr = NewRotationManager(EmergencyRotationConfig())
	}
	schedule := mgr.ComputeSchedule(newKid, now, oldKid, nil)

	result := RotateResult{
		NewKid:      newKid,
		OldKid:      oldKid,
		PromoteAt:   schedule.PromoteAt,
		RetireOldAt: schedule.RetireOldAt,
		Emergency:   schedule.IsEmergency,
	}

	// 6. Emergency (zero grace + overlap): apply promotion and retirement inline.
	if schedule.IsEmergency {
		if err := r.promote(ctx, newKid, now); err != nil {
			return RotateResult{}, err
		}
		if oldKid != "" {
			if err := r.retire(ctx, oldKid); err != nil {
				return RotateResult{}, err
			}
		}
	}

	return result, nil
}

// Promote transitions the pending key with the given kid to active: it becomes
// the signer for new tokens, and the previously active key begins draining
// (it stays in JWKS during the overlap window so in-flight tokens still verify).
// Callers (a scheduler) invoke this once the grace period has elapsed.
func (r *KeyRotator) Promote(ctx context.Context, kid string) error {
	return r.promote(ctx, kid, r.clock())
}

func (r *KeyRotator) promote(ctx context.Context, kid string, at time.Time) error {
	if err := r.store.Promote(ctx, kid, at); err != nil {
		return fmt.Errorf("crypto: promote key %q: %w", kid, err)
	}
	if err := r.provider.SetActive(kid); err != nil {
		return fmt.Errorf("crypto: promote key %q: %w", kid, err)
	}
	return nil
}

// Retire transitions the key with the given kid to retired: it is removed from
// both the store and JWKS, so tokens signed with it no longer verify. Callers
// (a scheduler) invoke this once the overlap window has elapsed.
func (r *KeyRotator) Retire(ctx context.Context, kid string) error {
	return r.retire(ctx, kid)
}

func (r *KeyRotator) retire(ctx context.Context, kid string) error {
	if err := r.store.Retire(ctx, kid); err != nil {
		return fmt.Errorf("crypto: retire key %q: %w", kid, err)
	}
	if err := r.provider.Remove(kid); err != nil {
		return fmt.Errorf("crypto: retire key %q: %w", kid, err)
	}
	return nil
}
