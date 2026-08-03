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
)

// ServiceClaims holds the validated claims of a cloudServiceAuth JWT.
type ServiceClaims struct {
	Audience  string
	Subject   string
	Scopes    []string
	ExpiresAt time.Time
	JTI       string
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

// ServiceAuthVerifierConfig configures a ServiceAuthVerifier.
type ServiceAuthVerifierConfig struct {
	// PublicKeyPEM is the PEM-encoded SPKI trust-anchor public key
	// (CLOUD_SERVICE_AUTH_PUBLIC_KEY) used to verify Harbor Cloud's
	// self-issued service JWTs. Must be an ES256 (P-256) or Ed25519 key.
	// Empty means the trust anchor is unconfigured: every Verify call fails
	// closed with ErrTrustAnchorUnconfigured.
	PublicKeyPEM string

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
	ecKey       *ecdsa.PublicKey
	edKey       ed25519.PublicKey
	replayGuard ReplayGuard
	logger      *telemetry.Logger
	now         func() time.Time
}

// NewServiceAuthVerifier builds a ServiceAuthVerifier. It returns an error
// only for a malformed/unsupported configured public key (a fail-fast boot
// error); an empty PublicKeyPEM is accepted and instead makes every
// subsequent Verify call fail closed with ErrTrustAnchorUnconfigured.
func NewServiceAuthVerifier(cfg ServiceAuthVerifierConfig) (*ServiceAuthVerifier, error) {
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	logger := cfg.Logger
	if logger == nil {
		logger = telemetry.New(nil)
	}

	var ecKey *ecdsa.PublicKey
	var edKey ed25519.PublicKey
	if pemStr := strings.TrimSpace(cfg.PublicKeyPEM); pemStr != "" {
		pub, err := parseTrustAnchorPEM(pemStr)
		if err != nil {
			return nil, fmt.Errorf("cloudapi: parse CLOUD_SERVICE_AUTH_PUBLIC_KEY: %w", err)
		}
		switch key := pub.(type) {
		case *ecdsa.PublicKey:
			if key.Curve != elliptic.P256() {
				return nil, errors.New("cloudapi: trust-anchor EC key must be P-256 (ES256)")
			}
			ecKey = key
		case ed25519.PublicKey:
			edKey = key
		default:
			return nil, fmt.Errorf("cloudapi: unsupported trust-anchor key type %T (want ES256 or Ed25519)", pub)
		}
	}

	return &ServiceAuthVerifier{
		ecKey:       ecKey,
		edKey:       edKey,
		replayGuard: cfg.ReplayGuard,
		logger:      logger,
		now:         now,
	}, nil
}

// parseTrustAnchorPEM decodes a PEM block and parses its DER payload as an
// SPKI (X.509 PKIX) public key.
func parseTrustAnchorPEM(pemStr string) (any, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	return x509.ParsePKIXPublicKey(block.Bytes)
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
	if v.ecKey == nil && v.edKey == nil {
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
	if !v.verifySignature(header.Alg, signingInput, sig) {
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
		Audience:  claims.Audience,
		Subject:   claims.Subject,
		Scopes:    scopes,
		ExpiresAt: expiresAt,
		JTI:       claims.JTI,
	}, nil
}

// verifySignature dispatches to the algorithm matching the configured trust
// anchor. An algorithm that doesn't match a configured key (including "none"
// or any algorithm confusion attempt) is rejected.
func (v *ServiceAuthVerifier) verifySignature(alg string, signingInput, sig []byte) bool {
	switch alg {
	case "ES256":
		return v.ecKey != nil && verifyES256Signature(v.ecKey, signingInput, sig)
	case "EdDSA":
		return v.edKey != nil && ed25519.Verify(v.edKey, signingInput, sig)
	default:
		return false
	}
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
