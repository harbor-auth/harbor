package region

import (
	"context"
	"errors"
)

// ErrNoRegion is returned by FromContext when no region has been pinned onto
// the context. It is the fail-closed signal: a handler that cannot determine
// its request's region MUST NOT proceed to any user-data read (docs/DESIGN.md
// §5; OpenSpec regional-data-residency-routing REQ-002, Decision 2). An unset
// region is treated as a residency failure, never as "any region".
var ErrNoRegion = errors.New("region: no region pinned on context")

// contextKey is a private type for the region context key so it cannot collide
// with keys set by other packages (the standard library recommends an
// unexported, package-local key type for context values).
type contextKey struct{}

// regionKey is the singleton key under which the pinned region is stored.
var regionKey = contextKey{}

// WithRegion pins a resolved region onto the request context. Downstream
// handlers recover it via FromContext, which binds datastore selection to this
// region so a handler physically cannot reach another region's store
// (REQ-002, Decision 2).
func WithRegion(ctx context.Context, r Region) context.Context {
	return context.WithValue(ctx, regionKey, r)
}

// FromContext returns the region pinned by WithRegion. It fails closed: if no
// region is present (or the stored value is empty/unknown), it returns
// ErrNoRegion and the caller MUST NOT proceed to a user-data read. A stored
// value that is not a known region is likewise rejected, so a malformed pin can
// never be mistaken for a valid residency decision.
func FromContext(ctx context.Context) (Region, error) {
	v := ctx.Value(regionKey)
	r, ok := v.(Region)
	if !ok {
		return "", ErrNoRegion
	}
	if _, known := known[string(r)]; !known {
		return "", ErrNoRegion
	}
	return r, nil
}
