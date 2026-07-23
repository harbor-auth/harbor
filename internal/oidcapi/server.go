// Package oidcapi implements the spec-generated OpenAPI ServerInterface
// (internal/gen/openapi) for Harbor's hot-path HTTP surface.
//
// The OpenAPI contract in api/openapi/harbor.yaml is the source of truth
// (docs/DESIGN.md §1.2). This package is the hand-written business logic that
// *satisfies* the generated interface — the generated stubs are never edited by
// hand (§1.3); if code and spec disagree, the spec wins and we regenerate.
package oidcapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"time"

	"github.com/harbor-auth/harbor/internal/bff"
	"github.com/harbor-auth/harbor/internal/crypto"
	"github.com/harbor-auth/harbor/internal/gen/openapi"
	"github.com/harbor-auth/harbor/internal/identity"
	"github.com/harbor-auth/harbor/internal/oidc"
	"github.com/harbor-auth/harbor/internal/region"
	"github.com/harbor-auth/harbor/internal/telemetry"
)

// DefaultBFFSessionTTL is the default lifetime of BFF session records in the
// oidcapi Server (docs/plans/bff-session-middleware.md — 5 min, matching the
// PKCE state lifetime).
const DefaultBFFSessionTTL = 5 * time.Minute

// TokenAuditRecorder records token-lifecycle audit events on a best-effort
// basis (token.issued, token.refreshed, token.revoked). It is satisfied
// directly by *identity.AuditRecorder. Emission is always non-blocking
// (RecordAsync detaches from the request context) so a slow/failing audit
// write never stalls the /token or /revoke hot path (DESIGN §2.1, Decision 3).
type TokenAuditRecorder interface {
	RecordAsync(ctx context.Context, userID string, et identity.EventType, clientID *string, detail any)
}

// Server implements openapi.ServerInterface for the harbor-hot binary.
type Server struct {
	issuer    string
	svc       *oidc.Service
	jwksBytes []byte
	// signers are the public signing keys used to verify inbound access tokens
	// on the /userinfo endpoint. The first is the active signer; additional
	// entries support rotation overlap (§7.3).
	signers       []crypto.Signer
	bffSessions   bff.BFFSessionStore
	loginURL      *url.URL // parsed at construction; nil if BFF not configured
	bffSessionTTL time.Duration
	// rotator drives POST /admin/keys/rotate (§7.3, §3.5.4). May be nil, in
	// which case the rotate endpoint reports 501 Not Implemented.
	rotator *crypto.KeyRotator

	// Emergency JWT revocation (docs/DESIGN.md §3.5). All three may be nil in
	// discovery-only tests, in which case POST /admin/revoke-jwt returns 503.
	revoked    RevokedJTIStore
	filter     oidc.RevocationFilter
	publisher  RevocationPublisher
	revChannel string

	// introspector handles RFC 7662 token introspection. May be nil if
	// introspection is not configured (no signers).
	introspector *oidc.Introspector

	// RP-Initiated Logout (end_session) dependencies (OIDC RP-Initiated Logout
	// 1.0). All four may be nil (e.g. discovery-only tests), in which case
	// /end_session simply redirects to the issuer's default logged-out page
	// without revoking anything.
	logoutVerifier LogoutVerifier
	grants         oidc.GrantStore
	clients        oidc.ClientRegistry
	sessionRevoker SessionRevoker

	// auditRecorder emits best-effort token-lifecycle audit events. May be nil
	// (dev/test scaffold), in which case no audit events are recorded.
	auditRecorder TokenAuditRecorder
}

// Config holds the settings needed to serve the OIDC surface.
type Config struct {
	// Issuer is this region's OIDC issuer URL (docs/DESIGN.md §3.4), e.g.
	// https://eu.harbor.id. It anchors every endpoint in the discovery document.
	Issuer string
	// Service runs the /authorize + /token flow logic. May be nil for the
	// discovery-only tests, which never exercise those endpoints.
	Service *oidc.Service
	// Signers are the public signing keys published at /jwks.json. The first is
	// the active signer; additional entries support rotation overlap (§7.3).
	// May be empty for discovery-only tests (served as {"keys":[]}).
	Signers []crypto.Signer
	// BFFSessions is the BFF session store. When non-nil, /authorize creates a
	// BFF session and redirects to LoginURL rather than issuing a code directly.
	BFFSessions bff.BFFSessionStore
	// LoginURL is the URL of the login UI (e.g. "https://mgmt.harbor.id/login").
	// Required when BFFSessions is non-nil.
	LoginURL string
	// BFFSessionTTL overrides DefaultBFFSessionTTL when non-zero.
	BFFSessionTTL time.Duration
	// Rotator drives POST /admin/keys/rotate (§7.3, §3.5.4). May be nil, in
	// which case the rotate endpoint reports 501 Not Implemented.
	Rotator *crypto.KeyRotator
	// RevokedJTIStore persists emergency JWT revocations (docs/DESIGN.md §3.5).
	// May be nil, in which case POST /admin/revoke-jwt returns 503.
	RevokedJTIStore RevokedJTIStore
	// RevocationFilter is this replica's in-process bloom filter. When set, a
	// successful revocation is applied locally for immediate effect. May be nil.
	RevocationFilter oidc.RevocationFilter
	// RevocationPublisher broadcasts revoked JTIs to sibling replicas via Redis
	// pub/sub. May be nil (single-replica dev) — propagation then relies on
	// periodic rehydration from the revoked_jtis table.
	RevocationPublisher RevocationPublisher
	// RevocationChannel is the Redis pub/sub channel for revocations. Defaults
	// to "revocation_channel" when empty.
	RevocationChannel string
	// RevokedJTIChecker performs DB introspection on bloom filter hits for
	// token introspection. May be nil (filter hits treated as revoked).
	RevokedJTIChecker oidc.RevokedJTIChecker

	// LogoutVerifier verifies an id_token_hint's signature (expiry ignored) for
	// RP-Initiated Logout. May be nil, in which case /end_session redirects to
	// the default logged-out page without revoking sessions.
	LogoutVerifier LogoutVerifier
	// Grants reverse-looks-up the internal userID from an id_token_hint's PPID
	// (sub) claim during RP-Initiated Logout. May be nil.
	Grants oidc.GrantStore
	// Clients validates post_logout_redirect_uri against a client's registered
	// logout_uris during RP-Initiated Logout. May be nil.
	Clients oidc.ClientRegistry
	// SessionRevoker revokes the user's sessions at the initiating RP during
	// RP-Initiated Logout. May be nil.
	SessionRevoker SessionRevoker

	// AuditRecorder records token-lifecycle events (best-effort). May be nil,
	// in which case no audit events are emitted (dev/test scaffold).
	AuditRecorder TokenAuditRecorder
}

// New returns a Server that serves the generated OpenAPI contract. The JWKS
// document is precomputed here because it changes only on key rotation.
func New(cfg Config) *Server {
	jwksBytes, err := json.Marshal(oidc.BuildJWKS(cfg.Signers))
	if err != nil {
		// Pure struct → JSON cannot fail in practice; serve an empty-keys JWKS
		// rather than panic or 500 if it somehow does.
		jwksBytes = []byte(`{"keys":[]}`)
	}
	ttl := cfg.BFFSessionTTL
	if ttl == 0 {
		ttl = DefaultBFFSessionTTL
	}
	var parsedLoginURL *url.URL
	if cfg.LoginURL != "" {
		var parseErr error
		parsedLoginURL, parseErr = url.Parse(cfg.LoginURL)
		if parseErr != nil {
			// Malformed LoginURL → treat as unconfigured; /authorize falls back
			// to the legacy immediate-code flow (docs/DESIGN.md §9).
			parsedLoginURL = nil
		}
	}
	channel := cfg.RevocationChannel
	if channel == "" {
		channel = defaultRevocationChannel
	}
	// Build the Introspector if signers are configured.
	var introspector *oidc.Introspector
	if len(cfg.Signers) > 0 {
		introspector = oidc.NewIntrospector(oidc.IntrospectConfig{
			Signers:        cfg.Signers,
			Filter:         cfg.RevocationFilter,
			RevokedChecker: cfg.RevokedJTIChecker,
		})
	}

	return &Server{
		issuer:         cfg.Issuer,
		svc:            cfg.Service,
		jwksBytes:      jwksBytes,
		signers:        cfg.Signers,
		bffSessions:    cfg.BFFSessions,
		loginURL:       parsedLoginURL,
		bffSessionTTL:  ttl,
		rotator:        cfg.Rotator,
		revoked:        cfg.RevokedJTIStore,
		filter:         cfg.RevocationFilter,
		publisher:      cfg.RevocationPublisher,
		revChannel:     channel,
		introspector:   introspector,
		logoutVerifier: cfg.LogoutVerifier,
		grants:         cfg.Grants,
		clients:        cfg.Clients,
		sessionRevoker: cfg.SessionRevoker,
		auditRecorder:  cfg.AuditRecorder,
	}
}

// Compile-time proof that Server satisfies the generated contract. If the spec
// grows a new operation, this stops compiling until we implement it — so the
// spec can never silently outrun the server.
var _ openapi.ServerInterface = (*Server)(nil)

// writeError renders the generated Error envelope as JSON. Messages must carry
// no PII (docs/DESIGN.md §6.5).
func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	// RFC 6749 §5.1/§5.2: OAuth/token-endpoint error responses MUST carry
	// Cache-Control: no-store and Pragma: no-cache so no intermediary caches an
	// error body. writeError is the generic error writer used by the region
	// middleware and other pre-handler rejections, so setting these here keeps
	// even fail-closed 400s (e.g. region_unknown on /token) spec-compliant.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(openapi.Error{Code: code, Message: message})
}

// WriteRateLimited writes a 429 Too Many Requests response and records the
// rejection as an AGGREGATE metric by endpoint and region. It is the single
// call site a rate-limiter (or edge middleware) uses so every 429 is metered
// consistently. Crucially it NEVER records a per-IP series — abuse visibility
// without PII (docs/plans/observability-metrics.md, docs/DESIGN.md §6.5). Pass
// an empty region.Region when the request region is not yet resolved.
func (s *Server) WriteRateLimited(w http.ResponseWriter, endpoint telemetry.EndpointName, reg region.Region) {
	recordRateLimited(endpoint, reg)
	writeError(w, http.StatusTooManyRequests, "rate_limited", "too many requests")
}

// EndpointRateLimit pairs an exact request path with the rate-limit middleware
// that guards it. cmd/harbor-hot builds one per hot-path endpoint
// (/introspect, /token, /authorize) so each gets an independent bucket and its
// own limit/window.
type EndpointRateLimit struct {
	// Path is the exact request path this middleware guards (e.g. "/token").
	Path string
	// Middleware is the per-endpoint RateLimitMiddleware to apply on Path.
	Middleware func(http.Handler) http.Handler
}

// WithRateLimits wraps base so that a request whose path exactly matches a
// configured EndpointRateLimit is first passed through that endpoint's
// rate-limit middleware before reaching base; every other path is served by
// base unchanged. This applies rate limiting to ONLY the listed hot-path
// endpoints without editing the spec-generated router (openapi.HandlerFromMux):
// the middleware wraps the whole router but is dispatched per path, so an
// over-limit request short-circuits with 429 while a healthz/jwks/discovery
// probe is never touched.
//
// Matching is by exact path across all HTTP methods — a wrong-method request to
// a limited path still consumes the bucket, which is the correct abuse-defense
// posture. Paths are matched before base's own routing runs.
func WithRateLimits(base http.Handler, limits []EndpointRateLimit) http.Handler {
	if len(limits) == 0 {
		return base
	}
	wrapped := make(map[string]http.Handler, len(limits))
	for _, l := range limits {
		// Each middleware wraps the full base router: when the path matches, the
		// limiter runs and (if allowed) calls base, which dispatches to the real
		// handler. Building this once per path keeps the hot path allocation-free.
		wrapped[l.Path] = l.Middleware(base)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h, ok := wrapped[r.URL.Path]; ok {
			h.ServeHTTP(w, r)
			return
		}
		base.ServeHTTP(w, r)
	})
}
