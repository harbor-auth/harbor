package crypto

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"log"

	"golang.org/x/crypto/hkdf"
)

// KeyProvider wraps and unwraps a DEK under a region's Key Encryption Key (KEK).
// The KEK never leaves the provider: in production it stays inside the regional
// HSM boundary (docs/DESIGN.md §7.3); in development it is derived from an
// environment secret via HKDF.
type KeyProvider interface {
	WrapDEK(ctx context.Context, region string, dek DEK) ([]byte, error)
	UnwrapDEK(ctx context.Context, region string, wrapped []byte) (DEK, error)

	// WrapKey wraps arbitrary key material (e.g. a PKCS#8 DER-encoded EC
	// private key) under a purpose-derived regional KEK. Unlike WrapDEK — which
	// is typed to the fixed-size DEK — WrapKey operates on variable-length byte
	// slices.
	//
	// purpose is a short domain-separator (e.g. "signing-key") that makes the
	// derived KEK cryptographically independent from every other purpose, even
	// when derived from the same master secret (RFC 5869 §3.2 info-string domain
	// separation). Callers MUST use the same region+purpose to UnwrapKey.
	WrapKey(ctx context.Context, region, purpose string, keyBytes []byte) ([]byte, error)

	// UnwrapKey reverses WrapKey. It returns ErrDecryptFailed if the region,
	// purpose, secret, or ciphertext do not match the values used to wrap.
	UnwrapKey(ctx context.Context, region, purpose string, wrapped []byte) ([]byte, error)
}

// localKeyProvider derives a per-region KEK from an environment secret using
// HKDF-SHA256. It is ONLY for development and testing.
//
// NEVER use in production: the KEK is software-derived and lives in process
// memory, violating the HSM boundary required by docs/DESIGN.md §7.3.
type localKeyProvider struct {
	secret []byte
	cipher *Cipher
}

// NewLocalKeyProvider constructs a dev-only localKeyProvider from the given
// secret. Returns [ErrEmptySecret] if the secret is empty. Logs a loud warning
// on every construction — if this appears in a production log, it is a bug.
func NewLocalKeyProvider(secret string) (KeyProvider, error) {
	if secret == "" {
		return nil, ErrEmptySecret
	}
	log.Printf("[WARN] harbor/crypto: localKeyProvider(DEV-ONLY) constructed — " +
		"this provider is NOT safe for production (keys are software-derived, " +
		"not HSM-backed). See docs/DESIGN.md §7.3.")
	return &localKeyProvider{
		secret: []byte(secret),
		cipher: NewCipher(),
	}, nil
}

// String makes localKeyProvider self-identifying in debug output.
func (p *localKeyProvider) String() string { return "localKeyProvider(DEV-ONLY)" }

// deriveKEK derives a 32-byte KEK for the given region using HKDF-SHA256.
// The info string domain-separates this derivation from any other HKDF usage
// in the codebase.
func (p *localKeyProvider) deriveKEK(region string) (DEK, error) {
	info := []byte("harbor-dek-wrap-v1:" + region)
	h := hkdf.New(sha256.New, p.secret, nil, info)
	var kek DEK
	if _, err := io.ReadFull(h, kek[:]); err != nil {
		return DEK{}, fmt.Errorf("crypto: HKDF derivation failed: %w", err)
	}
	return kek, nil
}

// wrapAAD returns the GCM additional data for a DEK wrap/unwrap operation.
// Binding the region to the AAD means a blob wrapped for region A cannot pass
// GCM authentication when opened as region B (region isolation).
//
// The AAD string is intentionally identical to the HKDF info string used in
// deriveKEK: together they provide two independent layers of region binding
// (wrong region ⇒ wrong KEK AND wrong AAD tag). If you ever version this string
// (e.g. "harbor-dek-wrap-v2:"), you MUST update BOTH deriveKEK's info AND
// wrapAAD in lockstep, or existing wrapped blobs will become permanently
// unreadable.
func wrapAAD(region string) []byte {
	return []byte("harbor-dek-wrap-v1:" + region)
}

// deriveKEKForPurpose derives a 32-byte KEK for the given region and purpose
// using HKDF-SHA256. The purpose is folded into the info string so keys wrapped
// under different purposes (e.g. "dek" vs "signing-key") are cryptographically
// independent even though they share the same master secret (RFC 5869 §3.2).
func (p *localKeyProvider) deriveKEKForPurpose(region, purpose string) (DEK, error) {
	info := []byte("harbor-" + purpose + "-wrap-v1:" + region)
	h := hkdf.New(sha256.New, p.secret, nil, info)
	var kek DEK
	if _, err := io.ReadFull(h, kek[:]); err != nil {
		return DEK{}, fmt.Errorf("crypto: HKDF derivation failed: %w", err)
	}
	return kek, nil
}

// keyWrapAAD returns the GCM additional data for a WrapKey/UnwrapKey operation.
// It is intentionally identical to deriveKEKForPurpose's info string, giving two
// independent layers of region+purpose binding (wrong region/purpose ⇒ wrong KEK
// AND wrong AAD tag). If you ever version this string you MUST update both in
// lockstep or existing wrapped blobs become permanently unreadable.
func keyWrapAAD(region, purpose string) []byte {
	return []byte("harbor-" + purpose + "-wrap-v1:" + region)
}

// WrapKey implements KeyProvider. It encrypts keyBytes under the purpose-derived
// regional KEK using AES-256-GCM, binding region+purpose as GCM AAD.
func (p *localKeyProvider) WrapKey(_ context.Context, region, purpose string, keyBytes []byte) ([]byte, error) {
	kek, err := p.deriveKEKForPurpose(region, purpose)
	if err != nil {
		return nil, fmt.Errorf("crypto: WrapKey key derivation: %w", err)
	}
	return p.cipher.Encrypt(kek, keyBytes, keyWrapAAD(region, purpose))
}

// UnwrapKey implements KeyProvider. It reverses WrapKey; on any mismatch
// (region, purpose, secret, or tampered ciphertext) GCM authentication fails and
// ErrDecryptFailed is returned.
func (p *localKeyProvider) UnwrapKey(_ context.Context, region, purpose string, wrapped []byte) ([]byte, error) {
	kek, err := p.deriveKEKForPurpose(region, purpose)
	if err != nil {
		return nil, ErrDecryptFailed
	}
	return p.cipher.Decrypt(kek, wrapped, keyWrapAAD(region, purpose))
}

// WrapDEK encrypts dek under the regional KEK using AES-256-GCM. The region is
// bound as GCM AAD so the wrapped blob is cryptographically tied to that region.
func (p *localKeyProvider) WrapDEK(_ context.Context, region string, dek DEK) ([]byte, error) {
	kek, err := p.deriveKEK(region)
	if err != nil {
		return nil, fmt.Errorf("crypto: WrapDEK key derivation: %w", err)
	}
	return p.cipher.Encrypt(kek, dek[:], wrapAAD(region))
}

// UnwrapDEK decrypts a wrapped DEK. If the region is wrong, the blob is tampered,
// or the secret differs, GCM authentication fails and [ErrDecryptFailed] is returned.
func (p *localKeyProvider) UnwrapDEK(_ context.Context, region string, wrapped []byte) (DEK, error) {
	kek, err := p.deriveKEK(region)
	if err != nil {
		// HKDF failure is treated as a decryption failure (same ErrDecryptFailed
		// sentinel) so callers get a single consistent error for all unwrap failures.
		return DEK{}, ErrDecryptFailed
	}
	pt, err := p.cipher.Decrypt(kek, wrapped, wrapAAD(region))
	if err != nil {
		return DEK{}, err // already ErrDecryptFailed from Decrypt
	}
	if len(pt) != 32 {
		return DEK{}, ErrDecryptFailed
	}
	var dek DEK
	copy(dek[:], pt)
	return dek, nil
}
