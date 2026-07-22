package region

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// ErrUnknownHost is returned by Resolve when a request host (or issuer prefix)
// does not map to any known region. Resolution is TOTAL and fail-closed: an
// unrecognised host yields this error and MUST NOT be defaulted to any region
// (docs/DESIGN.md §5; OpenSpec regional-data-residency-routing REQ-001,
// Decision 1). A silent default region would mis-route a user's PII across a
// jurisdiction boundary.
var ErrUnknownHost = errors.New("region: unknown host")

// ErrInvalidHostMap is returned by ValidateHostMap (and panicked at startup via
// init) when the configured host→region map is empty or ambiguous. Booting with
// a broken map is refused loudly rather than served with a silent default.
var ErrInvalidHostMap = errors.New("region: invalid host->region map")

// hostMap is the authoritative host→region table. Keys are bare, lowercased
// hosts (no scheme, no port); values are known regions. It is validated at
// startup by init via ValidateHostMap. Extend as jurisdictions are onboarded.
var hostMap = map[string]Region{
	"eu.harbor.id":   EU,
	"us.harbor.id":   US,
	"apac.harbor.id": APAC,
}

func init() {
	if err := ValidateHostMap(hostMap); err != nil {
		panic(err)
	}
}

// Resolve maps an inbound request host — or a full issuer URL such as
// "https://eu.harbor.id" — to its region. It is total: an unrecognised host
// returns ErrUnknownHost and never defaults to a region. The host is normalised
// (scheme and path stripped, port removed, lowercased) before lookup so that
// "https://eu.harbor.id/token", "eu.harbor.id:443", and "EU.harbor.id" all
// resolve identically.
func Resolve(host string) (Region, error) {
	normalized, err := normalizeHost(host)
	if err != nil {
		return "", err
	}
	if r, ok := hostMap[normalized]; ok {
		return r, nil
	}
	return "", fmt.Errorf("%w: %q", ErrUnknownHost, normalized)
}

// ValidateHostMap checks that a host→region map is safe to serve with: it MUST
// be non-empty, every host MUST normalise to a non-empty DNS host, every value
// MUST be a known region, and no two distinct keys may normalise to the same
// host (ambiguous mapping). It returns ErrInvalidHostMap otherwise.
func ValidateHostMap(m map[string]Region) error {
	if len(m) == 0 {
		return fmt.Errorf("%w: map is empty", ErrInvalidHostMap)
	}
	seen := make(map[string]string, len(m))
	for host, r := range m {
		normalized, err := normalizeHost(host)
		if err != nil {
			return fmt.Errorf("%w: host %q: %w", ErrInvalidHostMap, host, err)
		}
		if _, ok := known[string(r)]; !ok {
			return fmt.Errorf("%w: host %q maps to unknown region %q", ErrInvalidHostMap, host, r)
		}
		if prev, dup := seen[normalized]; dup {
			return fmt.Errorf("%w: host %q is ambiguous (already mapped via %q)", ErrInvalidHostMap, normalized, prev)
		}
		seen[normalized] = host
	}
	return nil
}

// normalizeHost reduces a host or issuer URL to a bare, lowercased DNS host with
// no scheme, path, or port. It returns ErrUnknownHost for empty input so that
// callers uniformly treat un-mappable input as an unknown host.
func normalizeHost(host string) (string, error) {
	h := strings.TrimSpace(host)
	if h == "" {
		return "", fmt.Errorf("%w: empty host", ErrUnknownHost)
	}
	if strings.Contains(h, "://") {
		u, err := url.Parse(h)
		if err != nil {
			return "", fmt.Errorf("%w: %w", ErrUnknownHost, err)
		}
		h = u.Host
	}
	h = strings.ToLower(strings.TrimSpace(h))
	// Strip a trailing :port. Hosts here are DNS names, never bracketless IPv6.
	if i := strings.LastIndex(h, ":"); i >= 0 {
		h = h[:i]
	}
	if h == "" {
		return "", fmt.Errorf("%w: empty host", ErrUnknownHost)
	}
	return h, nil
}
