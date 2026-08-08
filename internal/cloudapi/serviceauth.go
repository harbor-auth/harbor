// Package cloudapi implements the internal, authenticated management API
// harbor-mgmt exposes to Harbor Cloud (session minting, namespace lifecycle,
// signing-key rotation) over the private WireGuard ingress path only. See
// openspec/changes/harbor-cloud-management-api-contract-2ee993ea/design.md.
package cloudapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/harbor-auth/harbor/internal/telemetry"
)

// ExpectedAudience is the required `aud` claim on every cloudServiceAuth JWT
// (api/openapi/harbor-cloud.yaml `cloudServiceAuth` scheme).
const ExpectedAudience = "harbor-mgmt-cloudapi"

// Sentinel errors returned by ServiceAuthVerifier.Verify. Every one of them
// maps to a fail-closed 401 at the HTTP layer (the `Unauthorized` response in
// api/openapi/harbor-cloud.yaml covers "missing, malformed, expired,
// replayed, or wrong-audience... or the trust anchor is unconfigured").
var (
	// ErrTrustAnchorUnconfigured is returned when no trust-anchor public key
	// (CLOUD_SERVICE_AUTH_PUBLIC_KEY) is configured. Fail-closed: every
	// request is rejected, never allowed through.
	ErrTrustAnchorUnconfigured = errors.New("cloudapi: service auth trust anchor is not configured")

	// ErrReplayGuardUnavailable is returned when the replay guard is missing
	// or cannot answer (e.g. Redis is unreachable). Fail-closed: a replay
	// guard that cannot make a determination must never be treated as an
	// implicit pass.
	ErrReplayGuardUnavailable = errors.New("cloudapi: service auth replay guard unavailable")

	// ErrInvalidToken covers a malformed token, an unsupported/mismatched
	// algorithm, a bad signature, or a missing required claim (sub/exp/jti).
	ErrInvalidToken = errors.New("cloudapi: invalid service token")

	// ErrWrongAudience is returned when the `aud` claim does not equal
	// ExpectedAudience.
	ErrWrongAudience = errors.New("cloudapi: service token audience mismatch")

	// ErrMissingScope is returned when the `scope` claim is empty or absent.
	ErrMissingScope = errors.New("cloudapi: service token has no scope")

	// ErrExpired is returned when the `exp` claim is not in the future.
	ErrExpired = errors.New("cloudapi: service token expired")

	// ErrReplayed is returned when the token's `jti` has already been
	// presented (RedisReplayGuard SETNX on Verify.jti).
	ErrReplayed = errors.New("cloudapi: service token replayed")

	// ErrScopeNotPermittedForAnchor is returned when a token's signature
	// verifies against a configured trust anchor, but the token's `scope`
	// claim names a scope that anchor is not permitted to assert (§7 —
	// per-key scope binding). Maps to the same 403 insufficient_scope a
	// caller sees when its token simply lacks a route's required scope: the
	// two are indistinguishable from the outside by design.
	ErrScopeNotPermittedForAnchor = errors.New("cloudapi: token scope not permitted for signing key")
)

// ServiceClaims holds the validated claims of a cloudServiceAuth JWT.
type ServiceClaims struct {
	Audience  string
	Subject   string
	Scopes    []string
	ExpiresAt time.Time
	JTI       string

	// allNamespaces and allowedNamespaces mirror the matched anchor's
	// AllowedNamespaces (M5 — per-anchor namespace binding). Unexported: a
	// caller must go through NamespacePermitted rather than range over the
	// set itself, mirroring why trustAnchor.permits (not allowedScopes) is
	// what Verify consults for scopes.
	allNamespaces     bool
	allowedNamespaces map[string]struct{}
}

// NamespacePermitted reports whether the anchor that verified this token is
// permitted to act on namespaceID (M5 — per-anchor namespace binding).
//
// This cannot be checked inside Verify itself: namespace_id is a field of
// the request BODY (e.g. POST /admin/v1/user-sessions), not a JWT claim, so
// it isn't known until well after the bearer token has already been
// verified. A handler that needs this check retrieves ServiceClaims from its
// request context (see WithServiceClaims) once it has parsed namespace_id
// out of the body, then calls this method.
//
// An anchor configured with no AllowedNamespaces restriction permits every
// namespace (nil = unrestricted, matching AllowedScopes' back-compat
// convention — a deployment with a single, unrestricted bridge key keeps
// working unmodified).
func (c ServiceClaims) NamespacePermitted(namespaceID string) bool {
	if c.allNamespaces {
		return true
	}
	_, ok := c.allowedNamespaces[namespaceID]
	return ok
}

// serviceClaimsContextKey is the unexported context key ServiceClaims are
// attached under after a successful Verify, mirroring routeContextKey.
type serviceClaimsContextKey struct{}

// WithServiceClaims attaches the ServiceClaims from a successful Verify call
// to ctx. HTTP wiring (cmd/harbor-mgmt/cloudapi.go's cloudAuthorized) sets
// this immediately after Verify (and the route's own required-scope check)
// succeed, so a downstream handler can retrieve the caller's identity —
// e.g. for the M5 namespace check above — without re-verifying the bearer
// token, which would consume its jti a second time and reject it as a
// replay of itself.
func WithServiceClaims(ctx context.Context, claims ServiceClaims) context.Context {
	return context.WithValue(ctx, serviceClaimsContextKey{}, claims)
}

// ServiceClaimsFromContext reads the ServiceClaims set by WithServiceClaims.
// ok is false when none were set (e.g. a unit test that calls a handler
// directly, bypassing the HTTP auth middleware that sets it in production).
// This function itself takes no position on what a caller should DO with
// ok=false — that is a per-caller policy decision. Its one caller today,
// usersessions.go's PostUserSessions, deliberately treats ok=false as
// unrestricted (an implicit grant): there is no anchor in context to bind a
// restriction to, so the M5 namespace check is a no-op, identical to this
// handler's behavior before M5 existed. See that call site's own comment for
// the reasoning; do not assume every future caller of this function should
// make the same choice.
func ServiceClaimsFromContext(ctx context.Context) (ServiceClaims, bool) {
	claims, ok := ctx.Value(serviceClaimsContextKey{}).(ServiceClaims)
	return claims, ok
}

// HasScope reports whether scope is present among the token's granted
// scopes.
func (c ServiceClaims) HasScope(scope string) bool {
	for _, s := range c.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// ReplayGuard enforces single-use of a JWT's jti claim across every mgmt
// replica. Implementations must be safe for concurrent use.
type ReplayGuard interface {
	// Claim atomically marks jti as seen for ttl. It returns true the first
	// time a given jti is claimed and false on every later call within ttl (a
	// replay). A non-nil error means the guard could not make the
	// determination (e.g. its backing store is unreachable); callers must
	// treat that as a rejection — never as an implicit claim.
	Claim(ctx context.Context, jti string, ttl time.Duration) (bool, error)
}

// replayGuardKeyPrefix namespaces jti records in the shared Redis keyspace
// mgmt already uses for BFF/enrollment sessions.
const replayGuardKeyPrefix = "cloudapi:jti:"

// RedisReplayGuard is a Redis-backed ReplayGuard. It uses SETNX so the first
// caller to present a given jti wins; the TTL is set to the token's own
// remaining lifetime (design.md §2), so a jti record never outlives the
// token it guards and Redis memory use is self-bounding.
type RedisReplayGuard struct {
	client *redis.Client
}

// NewRedisReplayGuard builds a RedisReplayGuard over an existing Redis
// client.
func NewRedisReplayGuard(client *redis.Client) *RedisReplayGuard {
	return &RedisReplayGuard{client: client}
}

// Claim implements ReplayGuard.
func (g *RedisReplayGuard) Claim(ctx context.Context, jti string, ttl time.Duration) (bool, error) {
	ok, err := g.client.SetNX(ctx, replayGuardKeyPrefix+jti, "1", ttl).Result()
	if err != nil {
		return false, fmt.Errorf("cloudapi: redis SETNX jti: %w", err)
	}
	return ok, nil
}

// routeContextKey is the unexported context key for the audit-log route
// template, mirroring internal/region/context.go's WithX/FromContext idiom.
type routeContextKey struct{}

// WithRoute attaches an audit-log route template (e.g.
// "POST /admin/v1/sessions" — a template, never a concrete path with ids) to
// ctx so ServiceAuthVerifier.Verify can attribute its audit event without
// widening the Verify(ctx, bearer) signature. HTTP wiring sets this before
// calling Verify; if unset, the audit event's route is logged as "unknown".
func WithRoute(ctx context.Context, route string) context.Context {
	return context.WithValue(ctx, routeContextKey{}, route)
}

// routeFromContext reads the route template set by WithRoute.
func routeFromContext(ctx context.Context) string {
	if route, ok := ctx.Value(routeContextKey{}).(string); ok && route != "" {
		return route
	}
	return "unknown"
}

// TrustAnchorConfig describes one accepted cloudServiceAuth signing key and
// the scopes a token signed by it is permitted to assert (§7 — per-key scope
// binding). It is what CLOUD_SERVICE_AUTH_PUBLIC_KEYS parses into
// (ParseTrustAnchorsEnv) and what ServiceAuthVerifierConfig.Anchors accepts
// directly for tests.
type TrustAnchorConfig struct {
	// PublicKeyPEM is the PEM-encoded SPKI public key (ES256/P-256 or
	// Ed25519).
	PublicKeyPEM string

	// AllowedScopes is the exact set of scopes a token signed by this key is
	// permitted to assert. A token whose `scope` claim names ANY scope
	// outside this set is rejected in full (ErrScopeNotPermittedForAnchor) —
	// never partially honoured by dropping just the disallowed scope.
	//
	// nil (as opposed to a non-nil empty slice) means UNRESTRICTED: every
	// scope is permitted. This is reserved for the single legacy
	// CLOUD_SERVICE_AUTH_PUBLIC_KEY anchor (back-compat with the pre-§7
	// behavior, where the one configured key could assert any scope) — every
	// anchor parsed from CLOUD_SERVICE_AUTH_PUBLIC_KEYS carries an explicit,
	// non-nil scope set, since restricting scopes is that variable's entire
	// purpose.
	AllowedScopes []string

	// AllowedNamespaces is the exact set of namespace_id values this anchor
	// is permitted to act on for namespace-scoped operations — today, only
	// user-sessions:mint (M5 — per-anchor namespace binding). A token whose
	// request body names a namespace_id outside this set is rejected
	// (ServiceClaims.NamespacePermitted), independent of whether the token's
	// own scope claims would otherwise permit the call.
	//
	// nil (as opposed to a non-nil empty slice) means UNRESTRICTED: every
	// namespace is permitted — the back-compat default for both the legacy
	// CLOUD_SERVICE_AUTH_PUBLIC_KEY anchor and any CLOUD_SERVICE_AUTH_PUBLIC_KEYS
	// anchor that omits the optional "ns=" token, so a deployment with a
	// single bridge key serving every tenant keeps working unmodified. Only
	// once an operator configures a SECOND anchor for a second tenant's
	// bridge does restricting each one to its own namespace(s) become
	// possible — and necessary.
	AllowedNamespaces []string
}

// trustAnchor is a TrustAnchorConfig after its PEM has been parsed into a
// live public key and its scope list into a lookup set.
type trustAnchor struct {
	ecKey             *ecdsa.PublicKey
	edKey             ed25519.PublicKey
	allScopes         bool // true only for the legacy single-anchor back-compat path
	allowedScopes     map[string]struct{}
	allNamespaces     bool // true when AllowedNamespaces was nil (M5 — unrestricted)
	allowedNamespaces map[string]struct{}
	spkiDER           []byte // the exact SPKI DER decoded from PublicKeyPEM; used only for the boot-time duplicate-key check
}

// permits reports whether every scope in scopes is permitted for this
// anchor. An anchor with allScopes permits everything (back-compat). An
// empty scopes slice trivially passes (Verify already rejects an empty
// `scope` claim with ErrMissingScope before this is ever consulted).
func (a trustAnchor) permits(scopes []string) bool {
	if a.allScopes {
		return true
	}
	for _, s := range scopes {
		if _, ok := a.allowedScopes[s]; !ok {
			return false
		}
	}
	return true
}

// buildTrustAnchor parses cfg into a live trustAnchor. Returns an error for
// a missing/malformed/unsupported PEM, or an explicitly-empty (non-nil)
// AllowedScopes or AllowedNamespaces — a deployment that means "unrestricted"
// must say so with nil, never an empty list, so a config typo can never
// silently produce a scope-less or namespace-less (and therefore
// always-rejecting) anchor.
func buildTrustAnchor(cfg TrustAnchorConfig) (trustAnchor, error) {
	pemStr := strings.TrimSpace(cfg.PublicKeyPEM)
	if pemStr == "" {
		return trustAnchor{}, errors.New("empty public key PEM")
	}
	pub, der, err := parseTrustAnchorPEM(pemStr)
	if err != nil {
		return trustAnchor{}, err
	}
	a := trustAnchor{spkiDER: der}
	switch key := pub.(type) {
	case *ecdsa.PublicKey:
		if key.Curve != elliptic.P256() {
			return trustAnchor{}, errors.New("EC key must be P-256 (ES256)")
		}
		a.ecKey = key
	case ed25519.PublicKey:
		a.edKey = key
	default:
		return trustAnchor{}, fmt.Errorf("unsupported trust-anchor key type %T (want ES256 or Ed25519)", pub)
	}
	if cfg.AllowedScopes == nil {
		a.allScopes = true
	} else {
		a.allowedScopes = make(map[string]struct{}, len(cfg.AllowedScopes))
		for _, s := range cfg.AllowedScopes {
			s = strings.TrimSpace(s)
			if s == "" {
				return trustAnchor{}, errors.New("AllowedScopes contains an empty scope")
			}
			a.allowedScopes[s] = struct{}{}
		}
		if len(a.allowedScopes) == 0 {
			return trustAnchor{}, errors.New("AllowedScopes must not be empty (use nil for an unrestricted anchor)")
		}
	}
	if cfg.AllowedNamespaces == nil {
		a.allNamespaces = true
	} else {
		a.allowedNamespaces = make(map[string]struct{}, len(cfg.AllowedNamespaces))
		for _, ns := range cfg.AllowedNamespaces {
			ns = strings.TrimSpace(ns)
			if ns == "" {
				return trustAnchor{}, errors.New("AllowedNamespaces contains an empty namespace id")
			}
			a.allowedNamespaces[ns] = struct{}{}
		}
		if len(a.allowedNamespaces) == 0 {
			return trustAnchor{}, errors.New("AllowedNamespaces must not be empty (use nil for an unrestricted anchor)")
		}
	}
	return a, nil
}

// ParseTrustAnchorsEnv parses CLOUD_SERVICE_AUTH_PUBLIC_KEYS: one trust
// anchor per line, formatted as
//
//	<scope>[,<scope>...] [ns=<namespace>[,<namespace>...]] <SPKI PEM, with its line breaks escaped as literal \n>
//
// The "ns=" token (M5 — per-anchor namespace binding) is optional and, when
// present, restricts which namespace_id this anchor's user-sessions:mint
// tokens may act on; omitting it leaves the anchor namespace-unrestricted
// (TrustAnchorConfig.AllowedNamespaces nil), matching pre-M5 behavior. It is
// detected by its "ns=" prefix, never by field position, so it can never be
// confused with the PEM — which always starts with "-----BEGIN" (RFC 7468)
// and is otherwise taken wholesale, spaces and all, exactly as before.
//
// Blank lines and lines starting with "#" are skipped. This is a boot-time,
// fail-fast parse: a malformed line is a hard error, never a silently
// dropped anchor — a dropped anchor would leave a deployment believing a
// caller is authorized when it silently is not.
func ParseTrustAnchorsEnv(raw string) ([]TrustAnchorConfig, error) {
	var anchors []TrustAnchorConfig
	for i, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.SplitN(line, " ", 2)
		if len(fields) != 2 {
			return nil, fmt.Errorf("cloudapi: CLOUD_SERVICE_AUTH_PUBLIC_KEYS line %d: expected \"<scopes> [ns=<namespaces>] <pem>\"", i+1)
		}
		scopesPart, rest := strings.TrimSpace(fields[0]), strings.TrimSpace(fields[1])
		if scopesPart == "" {
			return nil, fmt.Errorf("cloudapi: CLOUD_SERVICE_AUTH_PUBLIC_KEYS line %d: missing scopes", i+1)
		}
		var scopes []string
		for _, s := range strings.Split(scopesPart, ",") {
			s = strings.TrimSpace(s)
			if s == "" {
				return nil, fmt.Errorf("cloudapi: CLOUD_SERVICE_AUTH_PUBLIC_KEYS line %d: empty scope in scope list", i+1)
			}
			// Reject anything shaped like a "ns=" token that ended up here
			// instead of in its own space-delimited field — e.g. an operator
			// writing "user-sessions:mint,ns=acme <pem>" (comma instead of
			// the required space before ns=) intends a namespace
			// restriction but, without this check, silently gets an anchor
			// with an extra (harmless, never-matching) "ns=acme" scope AND
			// no namespace restriction at all — the exact "operator intends
			// to restrict, silently gets permissive" shape as H2. No real
			// scope name legitimately contains "=", so this can never reject
			// a valid anchor.
			if strings.Contains(s, "=") {
				return nil, fmt.Errorf("cloudapi: CLOUD_SERVICE_AUTH_PUBLIC_KEYS line %d: %q looks like a misplaced ns= restriction (needs its own space-separated field, not a comma-separated scope) — see ParseTrustAnchorsEnv's doc comment for the line format", i+1, s)
			}
			scopes = append(scopes, s)
		}

		pemPart := rest
		var namespaces []string
		if strings.HasPrefix(rest, "ns=") {
			nsFields := strings.SplitN(rest, " ", 2)
			if len(nsFields) != 2 {
				return nil, fmt.Errorf("cloudapi: CLOUD_SERVICE_AUTH_PUBLIC_KEYS line %d: ns= token present but no PEM follows", i+1)
			}
			nsPart := strings.TrimPrefix(nsFields[0], "ns=")
			pemPart = strings.TrimSpace(nsFields[1])
			if nsPart == "" {
				return nil, fmt.Errorf("cloudapi: CLOUD_SERVICE_AUTH_PUBLIC_KEYS line %d: empty ns= namespace list", i+1)
			}
			for _, ns := range strings.Split(nsPart, ",") {
				ns = strings.TrimSpace(ns)
				if ns == "" {
					return nil, fmt.Errorf("cloudapi: CLOUD_SERVICE_AUTH_PUBLIC_KEYS line %d: empty namespace in ns= list", i+1)
				}
				namespaces = append(namespaces, ns)
			}
		}

		pemStr := strings.ReplaceAll(pemPart, `\n`, "\n")
		if pemStr == "" {
			return nil, fmt.Errorf("cloudapi: CLOUD_SERVICE_AUTH_PUBLIC_KEYS line %d: missing PEM", i+1)
		}
		anchors = append(anchors, TrustAnchorConfig{PublicKeyPEM: pemStr, AllowedScopes: scopes, AllowedNamespaces: namespaces})
	}
	return anchors, nil
}

// ServiceAuthVerifierConfig configures a ServiceAuthVerifier.
type ServiceAuthVerifierConfig struct {
	// PublicKeyPEM is the PEM-encoded SPKI trust-anchor public key
	// (CLOUD_SERVICE_AUTH_PUBLIC_KEY) used to verify Harbor Cloud's
	// self-issued service JWTs. Must be an ES256 (P-256) or Ed25519 key.
	// When set, it is treated as ONE anchor permitted to assert every scope
	// (back-compat with the pre-§7 single-key behavior) — combine with
	// Anchors to add additional, scope-restricted keys. Empty AND an empty
	// Anchors means the trust anchor is unconfigured: every Verify call
	// fails closed with ErrTrustAnchorUnconfigured.
	PublicKeyPEM string

	// Anchors lists additional trust anchors, each restricted to its own
	// permitted scope set (§7 — typically parsed from
	// CLOUD_SERVICE_AUTH_PUBLIC_KEYS via ParseTrustAnchorsEnv). May be
	// combined with PublicKeyPEM, or used alone.
	Anchors []TrustAnchorConfig

	// ReplayGuard rejects a jti that has already been presented. A nil
	// ReplayGuard also fails closed (ErrReplayGuardUnavailable).
	ReplayGuard ReplayGuard

	// Logger receives a PII-free audit event on every accept/reject. If nil,
	// a default telemetry.Logger is used.
	Logger *telemetry.Logger

	// Now overrides the clock for deterministic tests. Defaults to time.Now.
	Now func() time.Time
}

// ServiceAuthVerifier parses and validates the cloudServiceAuth bearer JWT
// (api/openapi/harbor-cloud.yaml). It never accepts ADMIN_API_TOKEN or the
// RFC 7591 client initial-access token (internal/mgmtapi/register.go) — it
// has no code path that reads either of those credentials, only the bearer
// JWT it is handed.
type ServiceAuthVerifier struct {
	anchors     []trustAnchor
	replayGuard ReplayGuard
	logger      *telemetry.Logger
	now         func() time.Time
}

// NewServiceAuthVerifier builds a ServiceAuthVerifier. It returns an error
// only for a malformed/unsupported configured public key (a fail-fast boot
// error); an empty PublicKeyPEM with no Anchors is accepted and instead
// makes every subsequent Verify call fail closed with
// ErrTrustAnchorUnconfigured.
func NewServiceAuthVerifier(cfg ServiceAuthVerifierConfig) (*ServiceAuthVerifier, error) {
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	logger := cfg.Logger
	if logger == nil {
		logger = telemetry.New(nil)
	}

	var anchors []trustAnchor
	// seenSPKI maps a raw SPKI DER encoding to the label of the anchor that
	// first configured it, so a key reused across two anchors is rejected at
	// boot instead of silently changing which scope set governs it (H2: the
	// same key present as both the unrestricted legacy anchor and a
	// scope-restricted CLOUD_SERVICE_AUTH_PUBLIC_KEYS entry would let
	// matchAnchor's first-match resolve to the unrestricted one, defeating
	// per-key scope binding entirely).
	seenSPKI := make(map[string]string)
	checkDuplicate := func(a trustAnchor, label string) error {
		key := string(a.spkiDER)
		if prior, ok := seenSPKI[key]; ok {
			return fmt.Errorf("cloudapi: %s configures the same public key as %s — each trust anchor must hold a distinct key, or the more permissive anchor's scope set silently governs the other (see H2)", label, prior)
		}
		seenSPKI[key] = label
		return nil
	}

	if pemStr := strings.TrimSpace(cfg.PublicKeyPEM); pemStr != "" {
		a, err := buildTrustAnchor(TrustAnchorConfig{PublicKeyPEM: pemStr})
		if err != nil {
			return nil, fmt.Errorf("cloudapi: parse CLOUD_SERVICE_AUTH_PUBLIC_KEY: %w", err)
		}
		if err := checkDuplicate(a, "CLOUD_SERVICE_AUTH_PUBLIC_KEY"); err != nil {
			return nil, err
		}
		anchors = append(anchors, a)
	}
	for i, ac := range cfg.Anchors {
		a, err := buildTrustAnchor(ac)
		if err != nil {
			return nil, fmt.Errorf("cloudapi: parse CLOUD_SERVICE_AUTH_PUBLIC_KEYS anchor %d: %w", i, err)
		}
		if err := checkDuplicate(a, fmt.Sprintf("CLOUD_SERVICE_AUTH_PUBLIC_KEYS anchor %d", i)); err != nil {
			return nil, err
		}
		anchors = append(anchors, a)
	}

	return &ServiceAuthVerifier{
		anchors:     anchors,
		replayGuard: cfg.ReplayGuard,
		logger:      logger,
		now:         now,
	}, nil
}

// parseTrustAnchorPEM decodes a PEM block and parses its DER payload as an
// SPKI (X.509 PKIX) public key. It also returns the raw SPKI DER bytes so
// callers can detect the same key configured under two different anchors
// (see the duplicate-key check in NewServiceAuthVerifier).
func parseTrustAnchorPEM(pemStr string) (any, []byte, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, nil, errors.New("no PEM block found")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, nil, err
	}
	return pub, block.Bytes, nil
}

// rawServiceClaims is the on-the-wire JSON shape of a cloudServiceAuth JWT
// payload (api/openapi/harbor-cloud.yaml `cloudServiceAuth` scheme).
type rawServiceClaims struct {
	Issuer   string `json:"iss"`
	Subject  string `json:"sub"`
	Audience string `json:"aud"`
	Scope    string `json:"scope"`
	Expiry   int64  `json:"exp"`
	JTI      string `json:"jti"`
}

// serviceJWTHeader is the on-the-wire JSON shape of a cloudServiceAuth JWT
// header.
type serviceJWTHeader struct {
	Alg string `json:"alg"`
}

// Verify parses and validates bearer as a cloudServiceAuth JWT: it checks
// the signature against the configured trust anchor, that `aud` equals
// ExpectedAudience, that `scope` is present, that `exp` has not passed, and
// that `jti` has not been replayed. It fails closed (ErrTrustAnchorUnconfigured
// or ErrReplayGuardUnavailable) when either dependency is unconfigured, and
// emits a PII-free audit event via internal/telemetry on every outcome.
//
//harbor:invariant INV-CONSTANT-TIME-COMPARE
func (v *ServiceAuthVerifier) Verify(ctx context.Context, bearer string) (ServiceClaims, error) {
	if len(v.anchors) == 0 {
		v.audit(ctx, "", "trust_anchor_unconfigured")
		return ServiceClaims{}, ErrTrustAnchorUnconfigured
	}

	parts := strings.Split(bearer, ".")
	if len(parts) != 3 {
		v.audit(ctx, "", "invalid_token")
		return ServiceClaims{}, fmt.Errorf("%w: malformed compact JWT", ErrInvalidToken)
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		v.audit(ctx, "", "invalid_token")
		return ServiceClaims{}, fmt.Errorf("%w: header decode: %w", ErrInvalidToken, err)
	}
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		v.audit(ctx, "", "invalid_token")
		return ServiceClaims{}, fmt.Errorf("%w: payload decode: %w", ErrInvalidToken, err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		v.audit(ctx, "", "invalid_token")
		return ServiceClaims{}, fmt.Errorf("%w: signature decode: %w", ErrInvalidToken, err)
	}

	var header serviceJWTHeader
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		v.audit(ctx, "", "invalid_token")
		return ServiceClaims{}, fmt.Errorf("%w: header parse: %w", ErrInvalidToken, err)
	}

	signingInput := []byte(parts[0] + "." + parts[1])
	anchor, matched := v.matchAnchor(header.Alg, signingInput, sig)
	if !matched {
		v.audit(ctx, "", "invalid_token")
		return ServiceClaims{}, fmt.Errorf("%w: signature verification failed", ErrInvalidToken)
	}

	var claims rawServiceClaims
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		v.audit(ctx, "", "invalid_token")
		return ServiceClaims{}, fmt.Errorf("%w: claims parse: %w", ErrInvalidToken, err)
	}

	if claims.Subject == "" || claims.JTI == "" || claims.Expiry <= 0 {
		v.audit(ctx, claims.Subject, "invalid_token")
		return ServiceClaims{}, fmt.Errorf("%w: required claim missing", ErrInvalidToken)
	}

	// Audience is compared via fixed-size SHA-256 digests in constant time so
	// neither the presented audience's length nor content is distinguishable
	// via timing (INV-CONSTANT-TIME-COMPARE).
	if !constantTimeStringEqual(claims.Audience, ExpectedAudience) {
		v.audit(ctx, claims.Subject, "wrong_audience")
		return ServiceClaims{}, ErrWrongAudience
	}

	scopes := strings.Fields(claims.Scope)
	if len(scopes) == 0 {
		v.audit(ctx, claims.Subject, "missing_scope")
		return ServiceClaims{}, ErrMissingScope
	}

	// §7 — per-key scope binding: the SIGNING KEY that produced this
	// signature (anchor, resolved above) must permit every scope the token
	// claims to have, independent of whatever the token's own `scope` claim
	// self-asserts. Without this, any holder of a single shared signing key
	// could mint a token claiming keys:rotate even if that caller was only
	// ever meant to hold user-sessions:mint. Rejected in full — never by
	// silently dropping just the disallowed scope.
	if !anchor.permits(scopes) {
		v.audit(ctx, claims.Subject, "insufficient_scope")
		return ServiceClaims{}, ErrScopeNotPermittedForAnchor
	}

	expiresAt := time.Unix(claims.Expiry, 0)
	now := v.now()
	if !now.Before(expiresAt) {
		v.audit(ctx, claims.Subject, "expired")
		return ServiceClaims{}, ErrExpired
	}

	if v.replayGuard == nil {
		v.audit(ctx, claims.Subject, "replay_guard_unavailable")
		return ServiceClaims{}, ErrReplayGuardUnavailable
	}
	claimed, err := v.replayGuard.Claim(ctx, claims.JTI, expiresAt.Sub(now))
	if err != nil {
		v.audit(ctx, claims.Subject, "replay_guard_unavailable")
		return ServiceClaims{}, fmt.Errorf("%w: %w", ErrReplayGuardUnavailable, err)
	}
	if !claimed {
		v.audit(ctx, claims.Subject, "token_replayed")
		return ServiceClaims{}, ErrReplayed
	}

	v.audit(ctx, claims.Subject, "")
	return ServiceClaims{
		Audience:          claims.Audience,
		Subject:           claims.Subject,
		Scopes:            scopes,
		ExpiresAt:         expiresAt,
		JTI:               claims.JTI,
		allNamespaces:     anchor.allNamespaces,
		allowedNamespaces: anchor.allowedNamespaces,
	}, nil
}

// matchAnchor returns the first configured anchor whose key verifies sig
// over signingInput for the given alg, and whether one was found. An
// algorithm that matches no configured key (including "none" or any
// algorithm-confusion attempt) is rejected. NewServiceAuthVerifier rejects
// any configuration where two anchors share a key (H2), so at most one
// anchor is ever able to match a well-formed signature — "first" is never
// asked to arbitrate between two anchors with different permitted scopes for
// the same key.
func (v *ServiceAuthVerifier) matchAnchor(alg string, signingInput, sig []byte) (trustAnchor, bool) {
	for _, a := range v.anchors {
		switch alg {
		case "ES256":
			if a.ecKey != nil && verifyES256Signature(a.ecKey, signingInput, sig) {
				return a, true
			}
		case "EdDSA":
			if a.edKey != nil && ed25519.Verify(a.edKey, signingInput, sig) {
				return a, true
			}
		}
	}
	return trustAnchor{}, false
}

// verifyES256Signature verifies an ES256 (ECDSA P-256 SHA-256) signature.
// sig must be the raw R||S format (64 bytes total, 32 bytes each, RFC 7518
// §3.4) — the format Harbor's own crypto.Signer produces.
func verifyES256Signature(pubKey *ecdsa.PublicKey, signingInput, sig []byte) bool {
	if len(sig) != 64 {
		return false
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	digest := sha256.Sum256(signingInput)
	return ecdsa.Verify(pubKey, digest[:], r, s)
}

// constantTimeStringEqual reports whether a and b are equal without leaking
// their lengths or content via timing: both are hashed to a fixed-size
// digest before comparison, so the comparison cost never depends on the
// (attacker-controlled) length of the presented value.
func constantTimeStringEqual(a, b string) bool {
	ah := sha256.Sum256([]byte(a))
	bh := sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(ah[:], bh[:]) == 1
}

// audit emits a single PII-free audit log line via internal/telemetry for
// every Verify outcome. errorCode is empty on acceptance. sub is the
// caller's service identity (JWT `sub`), a machine identifier — never an
// end-user identifier — allow-listed as the `caller` telemetry field.
func (v *ServiceAuthVerifier) audit(ctx context.Context, sub, errorCode string) {
	result := "accepted"
	if errorCode != "" {
		result = "rejected"
	}
	attrs := []slog.Attr{
		slog.String("path_template", routeFromContext(ctx)),
		slog.String("result", result),
	}
	if sub != "" {
		attrs = append(attrs, slog.String("caller", sub))
	}
	if errorCode != "" {
		attrs = append(attrs, slog.String("error_code", errorCode))
	}
	if result == "accepted" {
		v.logger.Info("cloudapi service auth", attrs...)
		return
	}
	v.logger.Warn("cloudapi service auth", attrs...)
}
