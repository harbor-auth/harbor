package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	cryptorand "crypto/rand"
	"fmt"
	"io"
)

const (
	// gcmNonceSize is the standard AES-GCM nonce length.
	gcmNonceSize = 12
	// minCipherLen is the shortest valid sealed message: nonce + empty-plaintext + GCM tag.
	minCipherLen = gcmNonceSize + 16
)

// DEK is a 256-bit per-user data encryption key. It is held in memory only
// transiently; at rest only the KEK-wrapped form (users.dek_wrapped) is stored
// (docs/DESIGN.md §4.4, §10).
type DEK [32]byte

// Encryptor seals plaintext under a DEK using AES-256-GCM.
// Output layout: nonce ‖ ciphertext ‖ GCM-tag.
type Encryptor interface {
	Encrypt(dek DEK, plaintext, aad []byte) ([]byte, error)
}

// Decryptor opens ciphertext (nonce ‖ ciphertext ‖ GCM-tag) under a DEK.
// It fails CLOSED: any tag mismatch or malformed input returns [ErrDecryptFailed]
// and never partial plaintext.
type Decryptor interface {
	Decrypt(dek DEK, ciphertext, aad []byte) ([]byte, error)
}

// Cipher implements [Encryptor] and [Decryptor] using AES-256-GCM.
// Obtain one via [NewCipher]; the rand field is unexported so only this package
// (and its tests) can inject a deterministic reader for golden-vector tests.
type Cipher struct {
	rand io.Reader
}

// NewCipher returns a Cipher backed by crypto/rand.
func NewCipher() *Cipher {
	return &Cipher{rand: cryptorand.Reader}
}

// GenerateDEK returns a fresh 256-bit DEK drawn from crypto/rand. It returns
// [ErrRandFailure] if the RNG fails or (defense-in-depth) returns an all-zero key.
func GenerateDEK() (DEK, error) {
	var dek DEK
	if _, err := io.ReadFull(cryptorand.Reader, dek[:]); err != nil {
		return DEK{}, ErrRandFailure
	}
	if dek == (DEK{}) {
		return DEK{}, ErrRandFailure
	}
	return dek, nil
}

// Encrypt seals plaintext under dek using AES-256-GCM. A fresh nonce is drawn
// from the Cipher's rand reader for each call. dek must be non-zero; callers
// SHOULD use [GenerateDEK] to ensure this.
// Output layout: nonce ‖ ciphertext ‖ GCM-tag.
func (c *Cipher) Encrypt(dek DEK, plaintext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(dek[:])
	if err != nil {
		// DEK is always 32 bytes (AES-256); this branch is unreachable in correct usage.
		return nil, fmt.Errorf("crypto: internal AES setup failure: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		// AES block size is always 16; this branch is unreachable in correct usage.
		return nil, fmt.Errorf("crypto: internal GCM setup failure: %w", err)
	}
	nonce := make([]byte, gcmNonceSize)
	if _, err := io.ReadFull(c.rand, nonce); err != nil {
		return nil, ErrRandFailure
	}
	// gcm.Seal appends the ciphertext+tag after the nonce slice, giving the
	// nonce ‖ ciphertext ‖ tag layout.
	return gcm.Seal(nonce, nonce, plaintext, aad), nil
}

// Decrypt opens ciphertext (nonce ‖ ciphertext ‖ GCM-tag) under dek.
// Any authentication failure, short input, or internal error returns
// [ErrDecryptFailed] with nil plaintext (fail-closed).
func (c *Cipher) Decrypt(dek DEK, ciphertext, aad []byte) ([]byte, error) {
	if len(ciphertext) < minCipherLen {
		return nil, ErrDecryptFailed
	}
	block, err := aes.NewCipher(dek[:])
	if err != nil {
		return nil, ErrDecryptFailed
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrDecryptFailed
	}
	nonce, ct := ciphertext[:gcmNonceSize], ciphertext[gcmNonceSize:]
	pt, err := gcm.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, ErrDecryptFailed
	}
	return pt, nil
}
