package telemetry

// labels.go is the compile-time label allow-list for Harbor metrics
// (observability-metrics REQ-001). It realises Decision 1 of the design: PII
// labels are made *unexpressible*, not merely discouraged.
//
// The privacy contract:
//
//   - A metric label may only be built through one of the allow-listed builders
//     below (Region, Endpoint, Outcome, GrantType, ErrorCode, ClientID). Each
//     builder pins the dimension KEY to a member of the allow-list and takes a
//     typed, low-cardinality VALUE — there is NO exported constructor and NO
//     free-form label API, so a user_id / email / PPID / IP / subject label
//     cannot be built and the code that tries will not compile.
//   - The dimensions are low-cardinality and non-PII: region, endpoint,
//     outcome, grant_type, error_code, and the RP-scoped (never user-scoped)
//     client_id.
//
// See openspec/changes/observability-metrics for the full requirements and
// docs/DESIGN.md §5/§6.5/§11.2 for the privacy model this enforces.

import "github.com/harbor/harbor/internal/region"

// LabelKey is the compile-time allow-list of non-PII metric dimension keys.
// It is a closed set: adding a key here is a deliberate, reviewed act, and no
// key outside this set can ever reach a metric (there is no API that accepts a
// free-form key).
type LabelKey string

const (
	// KeyRegion is the pinned request region (low-cardinality, non-PII).
	KeyRegion LabelKey = "region"
	// KeyEndpoint is an allow-listed route name, never a concrete path with ids.
	KeyEndpoint LabelKey = "endpoint"
	// KeyOutcome is the coarse result of an operation.
	KeyOutcome LabelKey = "outcome"
	// KeyGrantType is the OAuth grant type of a token request.
	KeyGrantType LabelKey = "grant_type"
	// KeyErrorCode is an allow-listed protocol error code.
	KeyErrorCode LabelKey = "error_code"
	// KeyClientID is an RP identifier — NEVER a user identifier (see ClientID).
	KeyClientID LabelKey = "client_id"
)

// Label is a phantom-typed, allow-listed metric dimension. Its fields are
// unexported, so a value with a populated key/value can ONLY be produced by one
// of the allow-listed builders in this file — external packages cannot
// construct a Label literal carrying an arbitrary (e.g. PII) key or value.
//
// This is the type-system half of the defence-in-depth described in the design;
// the companion internal/arch test guards against a future bypass of the
// facade.
type Label struct {
	key   LabelKey
	value string
}

// Key returns the allow-listed dimension key this label carries.
func (l Label) Key() LabelKey { return l.key }

// Value returns the (typed, low-cardinality) dimension value.
func (l Label) Value() string { return l.value }

// EndpointName is the allow-list of route names usable as an `endpoint` label.
// Values are route TEMPLATES / logical names, never concrete paths with ids, so
// cardinality stays bounded and no path segment can smuggle in an identifier.
type EndpointName string

const (
	EndpointAuthorize    EndpointName = "authorize"
	EndpointToken        EndpointName = "token"
	EndpointIntrospect   EndpointName = "introspect"
	EndpointRevoke       EndpointName = "revoke"
	EndpointUserinfo     EndpointName = "userinfo"
	EndpointJWKS         EndpointName = "jwks"
	EndpointDiscovery    EndpointName = "discovery"
	EndpointHealth       EndpointName = "health"
	EndpointRegister     EndpointName = "register"
	EndpointConsent      EndpointName = "consent"
	EndpointEnroll       EndpointName = "enroll"
	EndpointSession      EndpointName = "session"
	EndpointWebAuthn     EndpointName = "webauthn"
)

// OutcomeKind is the closed set of coarse operation outcomes.
type OutcomeKind string

const (
	OutcomeSuccess OutcomeKind = "success"
	OutcomeError   OutcomeKind = "error"
	OutcomeDenied  OutcomeKind = "denied"
	OutcomeLimited OutcomeKind = "limited"
)

// GrantKind is the closed set of OAuth grant types Harbor issues against.
type GrantKind string

const (
	GrantAuthorizationCode GrantKind = "authorization_code"
	GrantRefreshToken      GrantKind = "refresh_token"
	GrantClientCredentials GrantKind = "client_credentials"
)

// ErrorCodeValue is the allow-list of protocol error codes safe to label. These
// are OAuth/OIDC error codes (RFC 6749 §5.2 and friends) — bounded and non-PII.
type ErrorCodeValue string

const (
	ErrInvalidRequest       ErrorCodeValue = "invalid_request"
	ErrInvalidClient        ErrorCodeValue = "invalid_client"
	ErrInvalidGrant         ErrorCodeValue = "invalid_grant"
	ErrUnauthorizedClient   ErrorCodeValue = "unauthorized_client"
	ErrUnsupportedGrantType ErrorCodeValue = "unsupported_grant_type"
	ErrInvalidScope         ErrorCodeValue = "invalid_scope"
	ErrAccessDenied         ErrorCodeValue = "access_denied"
	ErrServerError          ErrorCodeValue = "server_error"
	ErrTemporarilyUnavail   ErrorCodeValue = "temporarily_unavailable"
	ErrInvalidToken         ErrorCodeValue = "invalid_token"
)

// Region builds a `region` label from a validated region.Region. Region is
// low-cardinality and non-PII; it gives operators per-region aggregates without
// any per-user breakdown (REQ-003).
func Region(r region.Region) Label {
	return Label{key: KeyRegion, value: string(r)}
}

// Endpoint builds an `endpoint` label from an allow-listed route name. The
// EndpointName type prevents a concrete path (which could carry an id) from
// being used as the value.
func Endpoint(name EndpointName) Label {
	return Label{key: KeyEndpoint, value: string(name)}
}

// Outcome builds an `outcome` label from the closed OutcomeKind enum.
func Outcome(o OutcomeKind) Label {
	return Label{key: KeyOutcome, value: string(o)}
}

// GrantType builds a `grant_type` label from the closed GrantKind enum.
func GrantType(g GrantKind) Label {
	return Label{key: KeyGrantType, value: string(g)}
}

// ErrorCode builds an `error_code` label from the allow-listed protocol error
// codes.
func ErrorCode(c ErrorCodeValue) Label {
	return Label{key: KeyErrorCode, value: string(c)}
}

// ClientID builds a `client_id` label for an RP (relying party) identifier.
//
// PRIVACY RULE — client_id is NEVER a user dimension:
//
//   - client_id identifies a registered CLIENT (an RP), not a user (§5.3). It
//     MUST only appear on client-scoped metrics and MUST NEVER be combined with
//     any user-linked dimension — doing so would recreate per-user tracking.
//   - Because a client with a single user makes every client_id row effectively
//     per-user, client_id is a *quasi-identifier* (design Decision 5 / REQ-005).
//     It is emitted only for registered clients above a small-count floor and is
//     bucketed/omitted below it. That small-n suppression is enforced at emit
//     time by the metrics facade — this builder only produces the label value.
func ClientID(id string) Label {
	return Label{key: KeyClientID, value: id}
}
