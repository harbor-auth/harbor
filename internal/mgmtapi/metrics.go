package mgmtapi

// metrics.go wires the harbor-mgmt cold-path handlers into the zero-PII
// telemetry facade (internal/telemetry). Every instrument here is
// aggregate-only and partitioned STRICTLY by allow-listed, non-PII dimensions
// (telemetry.Dim*), so no management request path can attach a user identifier
// to a metric (docs/DESIGN.md §6.5, observability-metrics REQ-001/REQ-002).
//
// It also exposes the label-bounded meter HOOKS the later Wave-5 features consume
// (relay accept/bounce, export/erase counts, cross-region-guard rejections) so
// those features meter through the same safe seam rather than reaching for a raw
// backend (docs/plans/observability-metrics.md).

import (
	"time"

	"github.com/harbor/harbor/internal/region"
	"github.com/harbor/harbor/internal/telemetry"
)

var (
	// mgmtRequestsTotal counts cold-path requests by endpoint and coarse outcome.
	mgmtRequestsTotal = telemetry.NewCounter(
		"harbor_mgmt_requests_total",
		"Management API requests by endpoint and outcome.",
		telemetry.DimEndpoint, telemetry.DimOutcome,
	)
	// mgmtRequestDuration observes cold-path request latency (seconds) by endpoint.
	mgmtRequestDuration = telemetry.NewHistogram(
		"harbor_mgmt_request_duration_seconds",
		"Management API request duration in seconds by endpoint.",
		telemetry.DimEndpoint,
	)
	// mgmtErrorsTotal counts failed requests by endpoint and (bounded) error_code.
	mgmtErrorsTotal = telemetry.NewCounter(
		"harbor_mgmt_errors_total",
		"Management API errors by endpoint and error_code.",
		telemetry.DimEndpoint, telemetry.DimErrorCode,
	)
	// mgmtRateLimitedTotal counts 429 rate-limit rejections by endpoint and
	// region. It is aggregate-only — NO per-IP series is ever emitted, so abuse
	// is visible without PII (docs/plans/observability-metrics.md, §6.5).
	mgmtRateLimitedTotal = telemetry.NewCounter(
		"harbor_mgmt_rate_limited_total",
		"Management API 429 rate-limit rejections by endpoint and region.",
		telemetry.DimEndpoint, telemetry.DimRegion,
	)
)

// Recovery-attempt meters. These are aggregate-only, region-partitioned volume
// signals for the account-recovery ceremony (user-account-recovery). They are
// deliberately partitioned ONLY by region — NEVER by user, code, or ceremony id
// — so operators get recovery volume/success/lockout trends per region without
// any per-user time series (docs/DESIGN.md §6.5, observability-metrics
// REQ-002/REQ-003). The region is the request's middleware-validated regional
// host, which is bounded and non-PII.
var (
	// mgmtRecoveryAttemptsTotal counts every /recovery/complete attempt by region.
	mgmtRecoveryAttemptsTotal = telemetry.NewCounter(
		"harbor_mgmt_recovery_attempts_total",
		"Account-recovery completion attempts by region.",
		telemetry.DimRegion,
	)
	// mgmtRecoverySuccessTotal counts successful recoveries by region.
	mgmtRecoverySuccessTotal = telemetry.NewCounter(
		"harbor_mgmt_recovery_success_total",
		"Successful account recoveries by region.",
		telemetry.DimRegion,
	)
	// mgmtRecoveryLockoutTotal counts recovery attempts rejected by the
	// fail-closed lockout policy, by region.
	mgmtRecoveryLockoutTotal = telemetry.NewCounter(
		"harbor_mgmt_recovery_lockout_total",
		"Account-recovery attempts rejected by lockout, by region.",
		telemetry.DimRegion,
	)
)

// Wave-5 meter hooks. These are label-bounded, aggregate-only counters the later
// Wave-5 features emit through — never a raw metrics backend — so the zero-PII
// contract holds for every feature that meters (docs/plans/observability-metrics.md).
var (
	// mgmtRelayEventsTotal counts inbound-relay accept/bounce events by region and
	// outcome (success = accepted, error = bounced). No per-address series is ever
	// emitted — relay addresses are PII and are not a metric dimension.
	mgmtRelayEventsTotal = telemetry.NewCounter(
		"harbor_mgmt_relay_events_total",
		"Inbound relay accept/bounce events by region and outcome.",
		telemetry.DimRegion, telemetry.DimOutcome,
	)
	// mgmtDataRightsTotal counts data-subject export/erase operations by region
	// and outcome. It is a volume counter only — no user is identifiable from it.
	mgmtDataRightsTotal = telemetry.NewCounter(
		"harbor_mgmt_data_rights_total",
		"Data-subject export/erase operations by region and outcome.",
		telemetry.DimRegion, telemetry.DimOutcome,
	)
	// mgmtCrossRegionRejectedTotal counts cross-region-guard rejections by region
	// and endpoint — an aggregate safety signal with no per-user dimension.
	mgmtCrossRegionRejectedTotal = telemetry.NewCounter(
		"harbor_mgmt_cross_region_rejected_total",
		"Cross-region-guard rejections by region and endpoint.",
		telemetry.DimRegion, telemetry.DimEndpoint,
	)
)

// recordRequest emits the per-endpoint request count and duration for a cold-path
// handler. Call it once per request with the terminal outcome (a defer with a
// mutable outcome variable, defaulting to error, is the idiomatic pattern).
func recordRequest(endpoint telemetry.EndpointName, outcome telemetry.OutcomeKind, start time.Time) {
	mgmtRequestsTotal.Inc(telemetry.Endpoint(endpoint), telemetry.Outcome(outcome))
	mgmtRequestDuration.Observe(time.Since(start).Seconds(), telemetry.Endpoint(endpoint))
}

// recordError emits an endpoint×error_code counter for a failed request. The
// handler's error-code string is mapped onto the bounded telemetry error-code
// allow-list, so an arbitrary code can never inflate metric cardinality (REQ-004).
func recordError(endpoint telemetry.EndpointName, code string) {
	mgmtErrorsTotal.Inc(telemetry.Endpoint(endpoint), telemetry.ErrorCode(mapMgmtErrorCode(code)))
}

// recordRateLimited emits an aggregate 429 rate-limit counter by endpoint and
// region. IP is PII and is NEVER a dimension — only aggregate counts are kept,
// so abuse is visible without a per-IP time series (docs/plans/observability-metrics.md).
func recordRateLimited(endpoint telemetry.EndpointName, reg region.Region) {
	mgmtRateLimitedTotal.Inc(telemetry.Endpoint(endpoint), telemetry.Region(reg))
}

// recordRecoveryAttempt meters a single account-recovery completion attempt by
// region. Aggregate-only: the region is the sole dimension — no user, code, or
// ceremony id is ever attached (docs/DESIGN.md §6.5).
func recordRecoveryAttempt(reg region.Region) {
	mgmtRecoveryAttemptsTotal.Inc(telemetry.Region(reg))
}

// recordRecoverySuccess meters a successful account recovery by region.
func recordRecoverySuccess(reg region.Region) {
	mgmtRecoverySuccessTotal.Inc(telemetry.Region(reg))
}

// recordRecoveryLockout meters a recovery attempt rejected by the fail-closed
// lockout policy, by region.
func recordRecoveryLockout(reg region.Region) {
	mgmtRecoveryLockoutTotal.Inc(telemetry.Region(reg))
}

// mapMgmtErrorCode maps a management-API error-code string onto the bounded
// telemetry error-code allow-list; anything unrecognised buckets to server_error
// so the label set stays fixed (REQ-004).
func mapMgmtErrorCode(code string) telemetry.ErrorCodeValue {
	switch code {
	case "invalid_request", "invalid_region", "invalid_client_metadata", "invalid_redirect_uri":
		return telemetry.ErrInvalidRequest
	case "invalid_token":
		return telemetry.ErrInvalidToken
	case "unauthorized":
		return telemetry.ErrAccessDenied
	case "unavailable", "service_unavailable":
		return telemetry.ErrTemporarilyUnavail
	default:
		return telemetry.ErrServerError
	}
}

// --- Wave-5 meter hooks (exported API) -------------------------------------
//
// These are the ONLY way the later Wave-5 features should emit their
// domain metrics, so every one of them goes through the zero-PII,
// aggregate-only seam. Each hook takes a validated region.Region and a coarse,
// bounded value — never a per-user identifier.

// RecordRelayEvent meters an inbound-relay accept/bounce event by region.
// accepted=true records a success (accepted); false records a bounce. No relay
// address (PII) is ever a metric dimension.
func RecordRelayEvent(r region.Region, accepted bool) {
	outcome := telemetry.OutcomeError
	if accepted {
		outcome = telemetry.OutcomeSuccess
	}
	mgmtRelayEventsTotal.Inc(telemetry.Region(r), telemetry.Outcome(outcome))
}

// RecordDataRightsOp meters a data-subject export/erase operation by region.
// succeeded=true records success, false records failure. It is a volume signal
// only — no user is identifiable from it.
func RecordDataRightsOp(r region.Region, succeeded bool) {
	outcome := telemetry.OutcomeError
	if succeeded {
		outcome = telemetry.OutcomeSuccess
	}
	mgmtDataRightsTotal.Inc(telemetry.Region(r), telemetry.Outcome(outcome))
}

// RecordCrossRegionRejected meters a cross-region-guard rejection by region and
// endpoint — an aggregate safety signal with no per-user dimension.
func RecordCrossRegionRejected(r region.Region, endpoint telemetry.EndpointName) {
	mgmtCrossRegionRejectedTotal.Inc(telemetry.Region(r), telemetry.Endpoint(endpoint))
}
