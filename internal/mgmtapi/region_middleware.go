package mgmtapi

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/harbor-auth/harbor/internal/region"
	"github.com/harbor-auth/harbor/internal/telemetry"
)

// regionUnknownCode is the error envelope code returned when an inbound
// request's Host does not resolve to any known region. It is a stable, non-PII
// identifier suitable for both the API response and aggregate metering.
const regionUnknownCode = "region_unknown"

// regionExemptPaths are exact-match, region-agnostic infrastructure endpoints
// that MUST NOT be region-gated: they serve no user PII and are probed by
// hosts that need not map to any jurisdiction (e.g. a container liveness
// probe on a bare pod IP). For these paths the middleware passes through
// un-pinned instead of failing closed — the 400 is reserved for user-data
// routes which are absent from this set and from regionExemptPrefixes
// (docs/DESIGN.md §5; OpenSpec regional-data-residency-routing REQ-001,
// REQ-002). This mirrors oidcapi.regionExemptPaths.
var regionExemptPaths = map[string]struct{}{
	"/healthz": {},
}

// regionExemptPrefixes are path prefixes whose entire subtree is exempt from
// the region gate, for endpoints with variable path segments that an
// exact-match regionExemptPaths entry cannot enumerate.
//
// /admin/v1/* (internal/cloudapi) is Harbor Cloud's namespace/session/
// key-rotation provisioning surface — it carries no user PII, and it is
// reached over the separate mgmt-cloud WireGuard NodePort
// (deploy/helm/templates/service-mgmt.yaml) rather than the public,
// region-bound WEBAUTHN_RP_ORIGINS host, so its Host header need not resolve
// to a region. Its own scoped service-JWT verifier (audience, scope, replay
// resistance) is the actual authorization boundary for these routes, not the
// region gate.
var regionExemptPrefixes = []string{
	"/admin/v1/",
}

// regionExempt reports whether path is exempt from the region gate, either
// via an exact match in regionExemptPaths or a prefix match in
// regionExemptPrefixes.
func regionExempt(path string) bool {
	if _, ok := regionExemptPaths[path]; ok {
		return true
	}
	for _, prefix := range regionExemptPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// RegionMiddleware resolves the request's region from its Host header, pins it
// onto the request context, and rejects any host that does not map to a known
// region. It MUST be wired ahead of every user-data handler (enrollment,
// consent, client management) so that region.FromContext (fail-closed) always
// finds a pinned region downstream (docs/DESIGN.md §5; OpenSpec
// regional-data-residency-routing REQ-001, REQ-002).
//
// Resolution is TOTAL (region.Resolve): an unrecognised host yields a defined
// 400 error (regionUnknownCode) and NEVER a default region — a silent default
// would mis-route a user's PII across a jurisdiction boundary. The rejection is
// metered through the allow-listed telemetry logger with NO PII: only
// aggregate, non-identifying fields (event, error_code, component,
// http_status) are emitted; the offending host is never logged.
//
// The *telemetry.Logger is required so metering is explicit and testable, in
// keeping with the deny-by-default privacy wrapper (Foundation F10). This is
// the cold-path twin of oidcapi.RegionMiddleware.
func RegionMiddleware(logger *telemetry.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reg, err := region.Resolve(r.Host)
			if err != nil {
				// Infrastructure probes (liveness, readiness) and the cloudapi
				// provisioning surface (/admin/v1/*) hit hosts that don't map to
				// any region — a bare pod IP, or the separate mgmt-cloud
				// WireGuard NodePort. Pass them through un-pinned rather than
				// failing closed — they carry no user PII.
				if regionExempt(r.URL.Path) {
					next.ServeHTTP(w, r)
					return
				}
				// Meter the rejection with aggregate, non-PII fields only. The
				// host is deliberately omitted — even if not itself PII, it is
				// not on the allow-list and would only ever be REDACTED.
				logger.Warn("region rejected",
					slog.String("event", "region_rejected"),
					slog.String("error_code", regionUnknownCode),
					slog.String("component", "mgmtapi"),
					slog.Int("http_status", http.StatusBadRequest),
				)
				writeRegionError(w)
				return
			}
			ctx := region.WithRegion(r.Context(), reg)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// writeRegionError renders the cold-path error envelope for an unresolved
// region. It mirrors Server.writeError but is standalone so the middleware
// needs no *Server receiver — it runs ahead of and independently of any handler.
func writeRegionError(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(errorResponse{
		Error:   regionUnknownCode,
		Message: "request host does not map to a known region",
	})
}
