package oidcapi

import (
	"log/slog"
	"net/http"

	"github.com/harbor-auth/harbor/internal/region"
	"github.com/harbor-auth/harbor/internal/telemetry"
)

// regionUnknownCode is the error envelope code returned when an inbound
// request's Host does not resolve to any known region. It is a stable,
// non-PII identifier suitable for both the API response and aggregate metering.
const regionUnknownCode = "region_unknown"

// regionExemptPaths are the region-agnostic infrastructure endpoints that MUST
// NOT be region-gated: they serve no user PII and are probed by hosts that need
// not map to any jurisdiction (e.g. a container healthcheck on "localhost", a
// load balancer, or a discovery client hitting a bare service address). For
// these paths the middleware resolves the region best-effort — pinning it when
// the host is known, passing through un-pinned when it is not — but NEVER
// returns the fail-closed 400. Every user-data route (/authorize, /token,
// /userinfo, /admin/*) is deliberately absent from this set and keeps the total,
// fail-closed enforcement (docs/DESIGN.md §5; OpenSpec
// regional-data-residency-routing REQ-001, REQ-002).
var regionExemptPaths = map[string]struct{}{
	"/healthz":                          {},
	"/.well-known/openid-configuration": {},
	"/jwks.json":                        {},
}

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
				// Region-agnostic infra endpoints (healthz, discovery, jwks)
				// carry no PII and are reached by non-region hosts (container
				// healthchecks on localhost, load balancers, discovery clients).
				// They pass through un-pinned instead of failing closed — the
				// 400 is reserved for user-data routes, which are absent from
				// regionExemptPaths and still reject an unknown host.
				if _, exempt := regionExemptPaths[r.URL.Path]; exempt {
					next.ServeHTTP(w, r)
					return
				}
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
