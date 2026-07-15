package bff

import (
	"crypto/rand"
	"encoding/base64"
)

// NewRequestID generates a 256-bit CSPRNG request ID, base64url-encoded.
// This is the opaque identifier for a BFF session, carried in the
// __Host-harbor-bff cookie and the request_id query parameter.
func NewRequestID() (string, error) {
	b := make([]byte, 32) // 256 bits
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
