package region

import (
	"context"
	"errors"
	"log/slog"

	"github.com/harbor/harbor/internal/telemetry"
)

// ErrCrossRegionAccess is returned by AssertRegion when a handler would read a
// user (or any user-scoped data) from a region other than the one pinned on the
// request context. It is the fail-closed signal for the residency boundary: on
// this error the caller MUST return NO data — not even a partial record
// (docs/DESIGN.md §5; OpenSpec regional-data-residency-routing REQ-003,
// Decision 3).
var ErrCrossRegionAccess = errors.New("region: cross-region access denied")

// crossRegionDeniedCode is the stable, non-PII error code emitted when a
// cross-region access is denied. It is safe for aggregate metering and for the
// telemetry allow-list.
const crossRegionDeniedCode = "cross_region_denied"

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
// On a match it returns nil and the caller may proceed. In every denial case
// the event is metered through the allow-listed telemetry wrapper using only
// aggregate, non-PII fields (event, error_code, component, and the request's
// own pinned region) — neither user identity nor the foreign region's data is
// ever logged, and no partial data is returned.
//
// The guard performs NO global user_id -> region lookup (REQ-005, Decision 5):
// it compares only the host-derived pinned region against the caller-supplied
// dataRegion, so it can never itself become the cross-region PII access it
// exists to prevent.
func AssertRegion(ctx context.Context, dataRegion Region) error {
	pinned, err := FromContext(ctx)
	if err != nil {
		// No pinned region -> residency decision cannot be made -> deny.
		meterCrossRegionDenied("")
		return err
	}
	if _, ok := known[string(dataRegion)]; !ok {
		// An unknown/empty data region cannot match a valid pinned region and
		// is treated as a mismatch -> deny.
		meterCrossRegionDenied(pinned)
		return ErrCrossRegionAccess
	}
	if pinned != dataRegion {
		meterCrossRegionDenied(pinned)
		return ErrCrossRegionAccess
	}
	return nil
}

// meterCrossRegionDenied records a cross-region denial with aggregate, non-PII
// fields only. The request's pinned region is on the telemetry allow-list and
// is safe to emit; the foreign dataRegion and any user identity are
// deliberately NOT logged so no cross-region or user detail leaks into
// telemetry. The telemetry logger is constructed at call time so the (rare)
// denial path always meters through the current slog default handler.
func meterCrossRegionDenied(pinned Region) {
	attrs := []slog.Attr{
		slog.String("event", "cross_region_denied"),
		slog.String("error_code", crossRegionDeniedCode),
		slog.String("component", "region"),
	}
	if pinned != "" {
		attrs = append(attrs, slog.String("region", string(pinned)))
	}
	telemetry.New(nil).Warn("cross-region access denied", attrs...)
}
