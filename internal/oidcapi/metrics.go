package oidcapi

// metrics.go wires the OIDC hot-path handlers into the zero-PII telemetry
// facade (internal/telemetry). Every instrument here is aggregate-only and
// partitioned STRICTLY by allow-listed, non-PII dimensions (telemetry.Dim*),
// so no request path can attach a user identifier to a metric
// (docs/DESIGN.md §6.5, observability-metrics REQ-001/REQ-002).

import (
	"time"

	"github.com/harbor/harbor/internal/telemetry"
)

var (
	// oidcRequestsTotal counts hot-path requests by endpoint and coarse outcome.
	oidcRequestsTotal = telemetry.NewCounter(
		"harbor_oidc_requests_total",
		"OIDC hot-path requests by endpoint and outcome.",
		telemetry.DimEndpoint, telemetry.DimOutcome,
	)
	// oidcRequestDuration observes hot-path request latency (seconds) by endpoint.
	oidcRequestDuration = telemetry.NewHistogram(
		"harbor_oidc_request_duration_seconds",
		"OIDC hot-path request duration in seconds by endpoint.",
		telemetry.DimEndpoint,
	)
	// oidcErrorsTotal counts failed requests by endpoint and (bounded) error_code.
	oidcErrorsTotal = telemetry.NewCounter(
		"harbor_oidc_errors_total",
		"OIDC hot-path errors by endpoint and error_code.",
		telemetry.DimEndpoint, telemetry.DimErrorCode,
	)
	// oidcTokensIssuedTotal counts token endpoint results by grant_type and outcome.
	oidcTokensIssuedTotal = telemetry.NewCounter(
		"harbor_oidc_tokens_issued_total",
		"Token endpoint results by grant_type and outcome.",
		telemetry.DimGrantType, telemetry.DimOutcome,
	)
)

// recordRequest emits the per-endpoint request count and duration for a hot-path
// handler. Call it once per request with the terminal outcome (a defer with a
// mutable outcome variable, defaulting to error, is the idiomatic pattern).
func recordRequest(endpoint telemetry.EndpointName, outcome telemetry.OutcomeKind, start time.Time) {
	oidcRequestsTotal.Inc(telemetry.Endpoint(endpoint), telemetry.Outcome(outcome))
	oidcRequestDuration.Observe(time.Since(start).Seconds(), telemetry.Endpoint(endpoint))
}

// recordError emits an endpoint×error_code counter for a failed request. The
// OAuth/OIDC error string is mapped onto the bounded telemetry error-code
// allow-list, so an arbitrary client-supplied code can never inflate metric
// cardinality (REQ-004).
func recordError(endpoint telemetry.EndpointName, code string) {
	oidcErrorsTotal.Inc(telemetry.Endpoint(endpoint), telemetry.ErrorCode(mapErrorCode(code)))
}

// mapErrorCode maps an OAuth/OIDC error code string onto the bounded telemetry
// error-code allow-list; anything unrecognised buckets to server_error so the
// label set stays fixed (REQ-004).
func mapErrorCode(code string) telemetry.ErrorCodeValue {
	switch code {
	case "invalid_request":
		return telemetry.ErrInvalidRequest
	case "invalid_client":
		return telemetry.ErrInvalidClient
	case "invalid_grant":
		return telemetry.ErrInvalidGrant
	case "unauthorized_client":
		return telemetry.ErrUnauthorizedClient
	case "unsupported_grant_type":
		return telemetry.ErrUnsupportedGrantType
	case "invalid_scope":
		return telemetry.ErrInvalidScope
	case "access_denied":
		return telemetry.ErrAccessDenied
	case "temporarily_unavailable":
		return telemetry.ErrTemporarilyUnavail
	case "invalid_token":
		return telemetry.ErrInvalidToken
	default:
		return telemetry.ErrServerError
	}
}

// mapGrantType maps a request grant_type onto the bounded grant-kind allow-list.
// The bool is false for an unrecognised grant, so the caller skips emitting a
// grant-labelled series for it (keeping cardinality bounded).
func mapGrantType(gt string) (telemetry.GrantKind, bool) {
	switch gt {
	case "authorization_code":
		return telemetry.GrantAuthorizationCode, true
	case "refresh_token":
		return telemetry.GrantRefreshToken, true
	case "client_credentials":
		return telemetry.GrantClientCredentials, true
	default:
		return "", false
	}
}
