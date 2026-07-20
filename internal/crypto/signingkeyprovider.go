package crypto

import (
	"fmt"
	"sync"
)

// SigningKeyProvider supplies the signer(s) used for JWT issuance and the full
// set of signers whose public keys must appear in JWKS (docs/DESIGN.md §7.3,
// §3.5.4). It is the read-side seam the JWT issuer and the JWKS endpoint depend
// on: the issuer signs with ActiveSigner; the JWKS handler publishes the public
// JWK of every signer returned by AllSigners.
//
// During key rotation there is exactly one active signer (signing new tokens)
// plus zero or more additional live signers (a freshly rotated "pending" key
// awaiting promotion, or a just-rotated-out key still inside its overlap
// window). Implementations must be safe for concurrent use.
type SigningKeyProvider interface {
	// ActiveSigner returns the signer used to sign all new tokens. It never
	// returns nil for a validly constructed provider.
	ActiveSigner() Signer

	// AllSigners returns every live signer whose public key should be published
	// in JWKS: the active signer plus any pending / overlapping signers. The
	// active signer is always included.
	AllSigners() []Signer
}

// MultiKeyProvider is an in-memory SigningKeyProvider that wraps multiple
// signers (typically LocalSigner instances in dev, or HSM-backed signers in
// prod). Exactly one signer is active; the rest are pending or overlapping keys
// kept live so their public keys remain in JWKS during a rotation window.
//
// MultiKeyProvider is safe for concurrent use: the active signer can be swapped
// (SetActive) and new signers added (Add) while readers call ActiveSigner /
// AllSigners.
type MultiKeyProvider struct {
	mu     sync.RWMutex
	active Signer            // the signer for new tokens; never nil after construction
	byKid  map[string]Signer // all live signers keyed by kid (includes active)
	order  []string          // kids in insertion order for deterministic AllSigners output
}

// Compile-time proof that MultiKeyProvider implements SigningKeyProvider.
var _ SigningKeyProvider = (*MultiKeyProvider)(nil)

// NewMultiKeyProvider constructs a provider with active as the signing key and
// any pending signers kept live in JWKS. It returns an error if active is nil
// or if any two signers (active or pending) share a kid — duplicate kids would
// make JWKS ambiguous and break kid-based verification.
func NewMultiKeyProvider(active Signer, pending ...Signer) (*MultiKeyProvider, error) {
	if active == nil {
		return nil, fmt.Errorf("crypto: NewMultiKeyProvider: active signer must not be nil")
	}
	p := &MultiKeyProvider{
		active: active,
		byKid:  make(map[string]Signer, 1+len(pending)),
	}
	p.addLocked(active)
	for _, s := range pending {
		if s == nil {
			return nil, fmt.Errorf("crypto: NewMultiKeyProvider: pending signer must not be nil")
		}
		if err := p.addLocked(s); err != nil {
			return nil, err
		}
	}
	return p, nil
}

// ActiveSigner implements SigningKeyProvider.
func (p *MultiKeyProvider) ActiveSigner() Signer {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.active
}

// AllSigners implements SigningKeyProvider. The active signer is always present.
// Output order is deterministic (insertion order, active first).
func (p *MultiKeyProvider) AllSigners() []Signer {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]Signer, 0, len(p.order))
	for _, kid := range p.order {
		out = append(out, p.byKid[kid])
	}
	return out
}

// SignerByKid returns the live signer with the given kid, or (nil, false) if no
// live signer has that kid. Useful for kid-based verification against the set
// of currently published keys.
func (p *MultiKeyProvider) SignerByKid(kid string) (Signer, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	s, ok := p.byKid[kid]
	return s, ok
}

// Add registers an additional live signer (e.g. a freshly rotated pending key).
// It returns ErrDuplicateKid if a signer with the same kid is already present.
// The added signer does NOT become active — call SetActive to promote it.
func (p *MultiKeyProvider) Add(s Signer) error {
	if s == nil {
		return fmt.Errorf("crypto: MultiKeyProvider.Add: signer must not be nil")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.addLocked(s)
}

// SetActive promotes the live signer with the given kid to be the active
// signer for new tokens. It returns an error if no live signer has that kid.
// The previously active signer remains live (in JWKS) until explicitly removed
// via Remove — this preserves the overlap window for in-flight tokens.
func (p *MultiKeyProvider) SetActive(kid string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	s, ok := p.byKid[kid]
	if !ok {
		return fmt.Errorf("crypto: MultiKeyProvider.SetActive: no live signer with kid %q", kid)
	}
	p.active = s
	return nil
}

// Remove drops the live signer with the given kid from the provider (e.g. after
// its overlap window elapses). It returns an error if the kid is unknown or if
// it refers to the active signer — the active signer must not be removed while
// it is signing new tokens.
func (p *MultiKeyProvider) Remove(kid string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.byKid[kid]; !ok {
		return fmt.Errorf("crypto: MultiKeyProvider.Remove: no live signer with kid %q", kid)
	}
	if p.active.KeyID() == kid {
		return fmt.Errorf("crypto: MultiKeyProvider.Remove: cannot remove active signer %q", kid)
	}
	delete(p.byKid, kid)
	for i, k := range p.order {
		if k == kid {
			p.order = append(p.order[:i], p.order[i+1:]...)
			break
		}
	}
	return nil
}

// addLocked inserts s into the provider's maps. The caller must hold p.mu (or
// be inside the constructor before the provider is shared). Returns
// ErrDuplicateKid if s's kid is already present.
func (p *MultiKeyProvider) addLocked(s Signer) error {
	kid := s.KeyID()
	if _, exists := p.byKid[kid]; exists {
		return fmt.Errorf("%w: %q", ErrDuplicateKid, kid)
	}
	p.byKid[kid] = s
	p.order = append(p.order, kid)
	return nil
}
