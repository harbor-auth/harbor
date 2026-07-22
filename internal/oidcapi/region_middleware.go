package oidcapi

import (
	"log/slog"
	"net/http"

	"github.com/harbor/harbor/internal/region"
	"github.com/harbor/harbor/internal/telemetry"
)

// regionUnknownCode is the error envelope code returned when an inbound
// request's Host does not resolve to any known region. It is a stable,
// non-PII identifier suitable for both the API response and aggregate metering.
const regionUnknownCode = "region_unknown"

// RegionMiddleware resolves the request's region from its Host header, pins it
// onto the request context, and rejects any host that does not map to a known
// region. It MUST be wired ahead of every user-data handler so that
// region.FromContext (fail-closed) always finds a pinned region downstream
// (docs/DESIGN.md §5; OpenSpec regional-data-residency-routing REQ-001,
// REQ-002, REQ-004).
//
// Resolution is TOTAL (region.Resolve): an unrecognised host yields a defined
// 400 error (regionUnknownCode) and NEVER a default region — a silent default
// would mis-route a user's PII across a jurisdiction boundary. The rejection is
// metered through the allow-listed telemetry logger with NO PII: only
// aggregate, non-identifying fields (event, error_code, component,
// http_status) are emitted; the offending host is never logged.
//
// The *telemetry.Logger is required so metering is explicit and testable, in
// keeping with the deny-by-default privacy wrapper (Foundation F10).
func RegionMiddleware(logger *telemetry.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reg, err := region.Resolve(r.Host)
			if err != nil {
				// Meter the rejection with aggregate, non-PII fields only. The
				// host is deliberately omitted — even if not itself PII, it is
				// not on the allow-list and would only ever be REDACTED.
				logger.Warn("region rejected",
					slog.String("event", "region_rejected"),
					slog.String("error_code", regionUnknownCode),
					slog.String("component", "oidcapi"),
					slog.Int("http_status", http.StatusBadRequest),
				)
				writeError(w, http.StatusBadRequest, regionUnknownCode,
					"request host does not map to a known region")
				return
			}
			ctx := region.WithRegion(r.Context(), reg)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
