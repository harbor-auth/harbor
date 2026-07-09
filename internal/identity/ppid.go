// Package identity holds Harbor's user/credential logic, including the
// derivation of pairwise pseudonymous identifiers (PPIDs). The core here is
// pure and deterministic (no I/O), so it is trivially unit-testable without
// mocks — the ideal described in docs/DESIGN.md §1.7.
package identity

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
)

// Input length bounds. These are defense-in-depth guards for the hot path
// (DerivePPID runs per token issuance): they cap attacker-influenced input so a
// pathologically large sector/user id can't turn HMAC into a cheap DoS vector,
// while staying far above any legitimate value.
const (
	// MaxSecretLen bounds the per-user pairwise secret (an HMAC key; 32–64 bytes
	// in practice).
	MaxSecretLen = 1024
	// MaxSectorLen bounds the RP sector identifier (a hostname/URL).
	MaxSectorLen = 2048
	// MaxUserIDLen bounds the internal user id (a UUID in practice).
	MaxUserIDLen = 256
)

// Errors returned by DerivePPID for invalid input.
var (
	ErrEmptySecret = errors.New("identity: user pairwise secret must be non-empty")
	ErrEmptySector = errors.New("identity: sector identifier must be non-empty")
	ErrEmptyUserID = errors.New("identity: user id must be non-empty")

	ErrSecretTooLong = errors.New("identity: user pairwise secret exceeds maximum length")
	ErrSectorTooLong = errors.New("identity: sector identifier exceeds maximum length")
	ErrUserIDTooLong = errors.New("identity: user id exceeds maximum length")
)

// DerivePPID computes the pairwise pseudonymous identifier (the OIDC `sub`) for
// a (user, RP-sector) pair, exactly per docs/DESIGN.md §3.2:
//
//	ppid = Base64URL( HMAC-SHA256( key = user_pairwise_secret,
//	                               msg = sector_identifier || user_id ) )
//
// Properties this gives us (see the tests):
//   - Deterministic: same inputs always yield the same sub, so logins are stable
//     without storing a row per (user, RP) up front.
//   - Keyed & one-way: the per-user secret is the HMAC *key*, so nobody can
//     compute or reverse a sub without it. A per-user secret (not a global salt)
//     means a key compromise deanonymizes one user, never the whole population.
//   - Non-correlating: different sectors yield unrelated subs, so two RPs cannot
//     join a user across services.
//
// Ambiguity note: a naive `sector || userID` byte concatenation is unsafe
// because ("a","bc") and ("ab","c") would produce the *same* message and thus the
// same sub — letting one RP potentially predict another RP's sub. We defend
// against this by length-prefixing the sector with a fixed 8-byte big-endian
// length before appending the user id, making the encoding injective.
func DerivePPID(userPairwiseSecret []byte, sectorIdentifier, userID string) (string, error) {
	if len(userPairwiseSecret) == 0 {
		return "", ErrEmptySecret
	}
	if len(userPairwiseSecret) > MaxSecretLen {
		return "", ErrSecretTooLong
	}
	if sectorIdentifier == "" {
		return "", ErrEmptySector
	}
	if len(sectorIdentifier) > MaxSectorLen {
		return "", ErrSectorTooLong
	}
	if userID == "" {
		return "", ErrEmptyUserID
	}
	if len(userID) > MaxUserIDLen {
		return "", ErrUserIDTooLong
	}

	msg := encodeMessage(sectorIdentifier, userID)

	mac := hmac.New(sha256.New, userPairwiseSecret)
	mac.Write(msg)
	sum := mac.Sum(nil)

	return base64.RawURLEncoding.EncodeToString(sum), nil
}

// encodeMessage builds an unambiguous (injective) HMAC message for a
// (sector, userID) pair: len(sector) as 8-byte big-endian, then sector, then
// userID. Because the length prefix is fixed-width, no two distinct pairs can
// encode to the same byte slice.
func encodeMessage(sectorIdentifier, userID string) []byte {
	sector := []byte(sectorIdentifier)
	uid := []byte(userID)

	msg := make([]byte, 0, 8+len(sector)+len(uid))
	var lenPrefix [8]byte
	binary.BigEndian.PutUint64(lenPrefix[:], uint64(len(sector)))
	msg = append(msg, lenPrefix[:]...)
	msg = append(msg, sector...)
	msg = append(msg, uid...)
	return msg
}
