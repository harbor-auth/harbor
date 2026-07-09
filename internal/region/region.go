// Package region holds region resolution and routing helpers (docs/DESIGN.md
// §4.2, §5). Data sovereignty means a user's data and keys live in exactly one
// region; resolving/validating the region string is pure logic and lives here.
package region

import (
	"errors"
	"strings"
)

// Region is a validated jurisdiction identifier.
type Region string

// Known regions. Extend as jurisdictions are onboarded.
const (
	EU   Region = "EU"
	US   Region = "US"
	APAC Region = "APAC"
)

// ErrUnknownRegion is returned when a raw string does not name a known region.
var ErrUnknownRegion = errors.New("region: unknown region")

var known = map[string]Region{
	string(EU):   EU,
	string(US):   US,
	string(APAC): APAC,
}

// Resolve normalizes and validates a raw region string (case-insensitive,
// surrounding whitespace trimmed). It returns ErrUnknownRegion for empty or
// unrecognized input.
func Resolve(raw string) (Region, error) {
	normalized := strings.ToUpper(strings.TrimSpace(raw))
	if r, ok := known[normalized]; ok {
		return r, nil
	}
	return "", ErrUnknownRegion
}
