package crypto

import (
	"context"
	"errors"
	"fmt"
)

// Envelope format version. Increment when the envelope layout changes.
// v1: version(1) | region_len(1) | region | kek_key_id_len(1) | kek_key_id | ciphertext
const envelopeVersion = 1

// Envelope size limits.
const (
	maxRegionLen   = 64  // AWS region names are typically <20 chars
	maxKEKKeyIDLen = 256 // AWS KMS key ARNs are typically <128 chars
	minEnvelopeLen = 4   // version + region_len + kek_key_id_len + at least 1 byte ciphertext
)

// Envelope errors.
var (
	// ErrInvalidEnvelope is returned when the wrapped DEK envelope is malformed.
	ErrInvalidEnvelope = errors.New("crypto: invalid envelope format")

	// ErrEnvelopeVersionMismatch is returned when the envelope version is unsupported.
	ErrEnvelopeVersionMismatch = errors.New("crypto: unsupported envelope version")

)

// KEKResolver resolves a region to its KEK key ID. In production, this maps
// region names (e.g., "us-east-1") to KMS key ARNs or aliases.
type KEKResolver interface {
	// ResolveKEK returns the KMS key ID (ARN or alias) for the given region.
	// Returns an error if the region is unknown or has no configured KEK.
	ResolveKEK(region string) (string, error)
}

// StaticKEKResolver is a simple KEKResolver that uses a static map.
// Useful for tests and simple configurations.
type StaticKEKResolver struct {
	keys map[string]string // region → KEK key ID
}

// NewStaticKEKResolver creates a KEKResolver from a static region-to-key map.
func NewStaticKEKResolver(keys map[string]string) *StaticKEKResolver {
	m := make(map[string]string, len(keys))
	for k, v := range keys {
		m[k] = v
	}
	return &StaticKEKResolver{keys: m}
}

// ResolveKEK implements KEKResolver.
func (r *StaticKEKResolver) ResolveKEK(region string) (string, error) {
	keyID, ok := r.keys[region]
	if !ok {
		return "", fmt.Errorf("crypto: no KEK configured for region %q", region)
	}
	return keyID, nil
}

// KMSKeyProvider is the production KeyProvider that wraps/unwraps DEKs using
// a KMS client. The KEK never leaves the KMS boundary (docs/DESIGN.md §7.3).
//
// The wrapped DEK is stored as a versioned envelope containing the region,
// KEK key ID, and KMS ciphertext. This allows:
//   - Forward compatibility: new versions can add fields without breaking old readers
//   - Region isolation: unwrap fails if envelope region doesn't match request region
//   - Key binding: envelope records which KEK was used, enabling KEK rotation detection
//
// KMSKeyProvider is safe for concurrent use.
type KMSKeyProvider struct {
	client   KMSClient
	resolver KEKResolver
}

// Compile-time proof that KMSKeyProvider implements KeyProvider.
var _ KeyProvider = (*KMSKeyProvider)(nil)

// NewKMSKeyProvider constructs a KMSKeyProvider with the given KMS client and
// KEK resolver.
func NewKMSKeyProvider(client KMSClient, resolver KEKResolver) *KMSKeyProvider {
	return &KMSKeyProvider{
		client:   client,
		resolver: resolver,
	}
}

// WrapDEK encrypts the DEK under the regional KEK and returns a versioned
// envelope. The envelope format is:
//
//	version(1) | region_len(1) | region | kek_key_id_len(1) | kek_key_id | ciphertext
//
// The region and KEK key ID are stored in the envelope for validation during
// unwrap and for operational visibility (which key was used).
func (p *KMSKeyProvider) WrapDEK(ctx context.Context, region string, dek DEK) ([]byte, error) {
	// Resolve region to KEK key ID.
	kekKeyID, err := p.resolver.ResolveKEK(region)
	if err != nil {
		return nil, fmt.Errorf("crypto: WrapDEK: %w", err)
	}

	// Validate lengths.
	if len(region) > maxRegionLen {
		return nil, fmt.Errorf("crypto: WrapDEK: region too long (%d > %d)", len(region), maxRegionLen)
	}
	if len(kekKeyID) > maxKEKKeyIDLen {
		return nil, fmt.Errorf("crypto: WrapDEK: KEK key ID too long (%d > %d)", len(kekKeyID), maxKEKKeyIDLen)
	}

	// Encrypt DEK under the KEK.
	ciphertext, err := p.client.Encrypt(ctx, kekKeyID, dek[:])
	if err != nil {
		return nil, fmt.Errorf("crypto: WrapDEK: KMS encrypt: %w", err)
	}

	// Build versioned envelope.
	envelope := make([]byte, 0, 3+len(region)+len(kekKeyID)+len(ciphertext))
	envelope = append(envelope, envelopeVersion)
	envelope = append(envelope, byte(len(region)))
	envelope = append(envelope, []byte(region)...)
	envelope = append(envelope, byte(len(kekKeyID)))
	envelope = append(envelope, []byte(kekKeyID)...)
	envelope = append(envelope, ciphertext...)

	return envelope, nil
}

// UnwrapDEK parses the versioned envelope, validates the region and KEK key ID,
// and decrypts the DEK using KMS.
//
// Returns ErrDecryptFailed for any failure to prevent information leakage about
// which specific check failed (decryption-oracle defense). The more specific
// envelope errors (ErrInvalidEnvelope, ErrEnvelopeRegionMismatch, etc.) are
// wrapped inside ErrDecryptFailed.
func (p *KMSKeyProvider) UnwrapDEK(ctx context.Context, region string, wrapped []byte) (DEK, error) {
	// Parse envelope.
	envelopeRegion, envelopeKeyID, ciphertext, err := parseEnvelope(wrapped)
	if err != nil {
		// Wrap specific error in ErrDecryptFailed for oracle defense.
		return DEK{}, ErrDecryptFailed
	}

	// Validate region matches.
	if envelopeRegion != region {
		return DEK{}, ErrDecryptFailed
	}

	// Resolve expected KEK key ID for this region.
	expectedKeyID, err := p.resolver.ResolveKEK(region)
	if err != nil {
		return DEK{}, ErrDecryptFailed
	}

	// Validate KEK key ID matches.
	if envelopeKeyID != expectedKeyID {
		return DEK{}, ErrDecryptFailed
	}

	// Decrypt DEK using KMS.
	plaintext, err := p.client.Decrypt(ctx, envelopeKeyID, ciphertext)
	if err != nil {
		return DEK{}, ErrDecryptFailed
	}

	// Validate DEK length.
	if len(plaintext) != 32 {
		return DEK{}, ErrDecryptFailed
	}

	var dek DEK
	copy(dek[:], plaintext)
	return dek, nil
}

// parseEnvelope extracts the region, KEK key ID, and ciphertext from a
// versioned envelope. Returns specific errors for diagnostic purposes;
// callers should wrap these in ErrDecryptFailed before returning to users.
func parseEnvelope(envelope []byte) (region, kekKeyID string, ciphertext []byte, err error) {
	if len(envelope) < minEnvelopeLen {
		return "", "", nil, ErrInvalidEnvelope
	}

	offset := 0

	// Version byte.
	version := envelope[offset]
	offset++
	if version != envelopeVersion {
		return "", "", nil, fmt.Errorf("%w: got %d, want %d", ErrEnvelopeVersionMismatch, version, envelopeVersion)
	}

	// Region length and region.
	if offset >= len(envelope) {
		return "", "", nil, ErrInvalidEnvelope
	}
	regionLen := int(envelope[offset])
	offset++
	if regionLen > maxRegionLen || offset+regionLen > len(envelope) {
		return "", "", nil, ErrInvalidEnvelope
	}
	region = string(envelope[offset : offset+regionLen])
	offset += regionLen

	// KEK key ID length and key ID.
	if offset >= len(envelope) {
		return "", "", nil, ErrInvalidEnvelope
	}
	keyIDLen := int(envelope[offset])
	offset++
	if keyIDLen > maxKEKKeyIDLen || offset+keyIDLen > len(envelope) {
		return "", "", nil, ErrInvalidEnvelope
	}
	kekKeyID = string(envelope[offset : offset+keyIDLen])
	offset += keyIDLen

	// Remaining bytes are ciphertext.
	if offset >= len(envelope) {
		return "", "", nil, ErrInvalidEnvelope
	}
	ciphertext = envelope[offset:]

	return region, kekKeyID, ciphertext, nil
}

// EnvelopeInfo contains metadata extracted from a wrapped DEK envelope.
// Useful for operational visibility and debugging.
type EnvelopeInfo struct {
	Version  uint8
	Region   string
	KEKKeyID string
}

// ParseEnvelopeInfo extracts metadata from a wrapped DEK envelope without
// decrypting it. Returns ErrInvalidEnvelope if the envelope is malformed.
func ParseEnvelopeInfo(envelope []byte) (EnvelopeInfo, error) {
	if len(envelope) < minEnvelopeLen {
		return EnvelopeInfo{}, ErrInvalidEnvelope
	}

	region, keyID, _, err := parseEnvelope(envelope)
	if err != nil {
		return EnvelopeInfo{}, err
	}

	return EnvelopeInfo{
		Version:  envelope[0], // Version is always the first byte
		Region:   region,
		KEKKeyID: keyID,
	}, nil
}

// String returns a human-readable description of the provider.
func (p *KMSKeyProvider) String() string {
	return "KMSKeyProvider"
}

// kmsKeyProvider is kept for backward compatibility with existing scaffold tests.
// New code should use KMSKeyProvider.
//
// Deprecated: Use NewKMSKeyProvider instead.
type kmsKeyProvider struct{}

// WrapDEK returns ErrKMSNotImplemented. Use KMSKeyProvider instead.
func (k *kmsKeyProvider) WrapDEK(_ context.Context, _ string, _ DEK) ([]byte, error) {
	return nil, ErrKMSNotImplemented
}

// UnwrapDEK returns ErrKMSNotImplemented. Use KMSKeyProvider instead.
func (k *kmsKeyProvider) UnwrapDEK(_ context.Context, _ string, _ []byte) (DEK, error) {
	return DEK{}, ErrKMSNotImplemented
}


