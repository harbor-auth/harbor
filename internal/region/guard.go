package region

import (
	"context"
	"errors"
)

// ErrCrossRegionAccess is returned by AssertRegion when a handler would read a
// user (or any user-scoped data) from a region other than the one pinned on the
// request context. It is the fail-closed signal for the residency boundary: on
// this error the caller MUST return NO data — not even a partial record
// (docs/DESIGN.md §5; OpenSpec regional-data-residency-routing REQ-003,
// Decision 3).
var ErrCrossRegionAccess = errors.New("region: cross-region access denied")

// CrossRegionDeniedCode is the stable, non-PII error code a caller emits when
// metering an AssertRegion cross-region denial. It is exported so the
// middleware/handler layer — which owns denial metering now that the guard is
// pure (see AssertRegion) — can reference it instead of re-hardcoding the
// string. It is safe for aggregate metering and is on the telemetry allow-list.
const CrossRegionDeniedCode = "cross_region_denied"

// AssertRegion asserts that dataRegion — the region of the store or record a
// handler is about to read — matches the region pinned on ctx by the region
// middleware. It is the cross-region PII guard and MUST be called BEFORE any
// user-data read so that a residency violation is caught before a single byte
// of a foreign-region record is touched.
//
// It fails closed:
//
//   - If no region is pinned on ctx (FromContext fails), the residency decision
//     cannot be made, so access is denied and ErrNoRegion is returned.
//   - If the pinned region differs from dataRegion (or dataRegion is not a
//     known region), access is denied and ErrCrossRegionAccess is returned.
//
// On a match it returns nil and the caller may proceed. In every denial case it
// returns a typed error and NO partial data.
//
// AssertRegion is intentionally PURE: it performs no telemetry, no logging, and
// no I/O — it is a total, deterministic comparison of the pinned region against
// the caller-supplied dataRegion. This keeps the region package free of a
// dependency on telemetry (which itself types its metric labels on
// region.Region, so a region -> telemetry edge would form an import cycle).
// Metering a cross-region denial is the CALLER's responsibility at the
// middleware/handler layer (which already imports both region and telemetry);
// callers should emit the stable, non-PII CrossRegionDeniedCode on this error
// with aggregate fields only (event, error_code, component, and the request's
// own pinned region) — never the foreign dataRegion or any user identity.
//
// The guard performs NO global user_id -> region lookup (REQ-005, Decision 5):
// it compares only the host-derived pinned region against the caller-supplied
// dataRegion, so it can never itself become the cross-region PII access it
// exists to prevent.
func AssertRegion(ctx context.Context, dataRegion Region) error {
	pinned, err := FromContext(ctx)
	if err != nil {
		// No pinned region -> residency decision cannot be made -> deny.
		return err
	}
	if _, ok := known[string(dataRegion)]; !ok {
		// An unknown/empty data region cannot match a valid pinned region and
		// is treated as a mismatch -> deny.
		return ErrCrossRegionAccess
	}
	if pinned != dataRegion {
		return ErrCrossRegionAccess
	}
	return nil
}
