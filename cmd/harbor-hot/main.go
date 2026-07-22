// Command harbor-hot is Harbor's hot-path HTTP binary: it serves the
// spec-generated OIDC surface (/authorize, /token, /introspect, /jwks.json,
// discovery, /healthz) and guards the abuse-sensitive endpoints with per-client
// rate limiting (docs/plans/rate-limiting.md).
//
// Rate-limiter wiring:
//   - REDIS_URL set   -> RedisRateLimiter (sliding-window, Lua-atomic, shared
//     across replicas).
//   - REDIS_URL unset -> in-memory MemoryRateLimiter (single-replica dev/test
//     fallback). This keeps local runs working without Redis.
//   - RATE_LIMIT_DISABLED truthy -> limiters are nil, so RateLimitMiddleware
//     becomes a transparent passthrough (an explicit escape hatch for load
//     tests).
//
// Each hot-path endpoint gets its OWN limiter (independent bucket namespace and
// its own limit/window), configurable via environment variables with sane
// defaults. Keys are client_id (authenticated) or source IP (anonymous); the
// key is never logged or used as a metric label (docs/DESIGN.md §6.5).
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/harbor-auth/harbor/internal/clients"
	"github.com/harbor-auth/harbor/internal/gen/openapi"
	"github.com/harbor-auth/harbor/internal/httpserver"
	"github.com/harbor-auth/harbor/internal/oidc"
	"github.com/harbor-auth/harbor/internal/oidcapi"
	"github.com/harbor-auth/harbor/internal/region"
	"github.com/harbor-auth/harbor/internal/telemetry"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	// Cancel the root context on SIGINT/SIGTERM so httpserver.Run shuts down
	// gracefully (drains in-flight requests) rather than dropping connections.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, logger); err != nil {
		logger.Error("harbor-hot exited with error", "error", err)
		os.Exit(1)
	}
}

// run builds the server and serves until ctx is cancelled. It is split out from
// main so the exit path has a single error sink and stays testable.
func run(ctx context.Context, logger *slog.Logger) error {
	// Load and validate the BFF session dependencies up front so a
	// misconfiguration (malformed LOGIN_URL, non-positive TTL) fails fast at
	// startup rather than surfacing later when /authorize needs them. Wiring the
	// resolved config into the DB-backed PPIDSessionResolver lands in a later
	// task; for now this only captures and validates the inputs — the foundation
	// for replacing the insecure stub resolver (audit blocker 1.1, auth bypass).
	bffCfg, err := loadBFFConfig()
	if err != nil {
		return err
	}
	// Log presence only — never the raw DATABASE_URL (it carries credentials) or
	// LOGIN_URL, keeping startup logs PII/secret-free (docs/DESIGN.md §6.5).
	logger.Info("BFF config loaded",
		"login_url_set", bffCfg.LoginURL != "",
		"database_url_set", bffCfg.DatabaseURL != "",
		"bff_session_ttl", bffCfg.SessionTTL.String(),
	)

	// Redis powers cross-replica rate limiting. ConnectRedis returns (nil, nil)
	// when REDIS_URL is unset — we then fall back to the in-memory limiter.
	redisClient, err := clients.ConnectRedis(ctx, logger)
	if err != nil {
		return err
	}

	issuer := envString("ISSUER", "https://harbor.local")

	// Bind the issuer host to a region so the region middleware resolves it.
	// In production, the issuer is region-specific (e.g. https://eu.harbor.id);
	// in dev, REGION env var overrides to allow localhost testing.
	if reg := envString("REGION", ""); reg != "" {
		if err := region.BindIssuerHost(issuer, region.Region(reg)); err != nil {
			return err
		}
	}

	// Wire the OIDC service with scaffold implementations for dev/test.
	// In production, these are replaced with DB-backed implementations.
	clientRegistry := oidc.NewInMemoryClientRegistry()
	// Seed a demo client for e2e tests (matches e2e/flow_test.go expectations).
	clientRegistry.Put(oidc.Client{
		ID:            "demo-client",
		SectorID:      "localhost",
		RedirectURIs:  []string{"http://localhost/callback", "http://localhost:8081/callback"},
		ScopesAllowed: []string{"openid", "profile", "email", "offline_access"},
	})

	oidcSvc := oidc.NewService(oidc.ServiceConfig{
		Issuer:   issuer,
		Clients:  clientRegistry,
		Codes:    oidc.NewInMemoryAuthCodeStore(),
		Tokens:   oidc.NewPlaceholderIssuer(),
		Sessions: oidc.NewStubSessionResolver("demo-user-ppid"),
		Logger:   logger,
	})

	srv := oidcapi.New(oidcapi.Config{Issuer: issuer, Service: oidcSvc})

	// Wrap the spec-generated router with per-endpoint rate limiting. Only the
	// hot-path endpoints listed here are guarded; /healthz, /jwks.json and
	// discovery pass through untouched.
	base := openapi.Handler(srv)
	handler := oidcapi.WithRateLimits(base, buildRateLimits(redisClient, logger))

	// Support both ADDR (full address) and PORT (port-only, for docker-compose).
	addr := envString("ADDR", "")
	if addr == "" {
		port := envString("PORT", "8080")
		addr = ":" + port
	}
	return httpserver.Run(ctx, addr, handler, logger)
}

// endpointLimitSpec describes the tunable rate limit for one hot-path endpoint:
// the exact request path it guards, the telemetry endpoint name that namespaces
// its bucket and labels its aggregate metrics, and its default limit/window.
type endpointLimitSpec struct {
	path     string
	endpoint telemetry.EndpointName
	// envKey is the base for the two override variables:
	//   RATE_LIMIT_<envKey>        — max requests per window (int)
	//   RATE_LIMIT_<envKey>_WINDOW — window duration (e.g. "1m", "30s")
	envKey        string
	defaultLimit  int
	defaultWindow time.Duration
}

// hotPathLimits is the fixed set of abuse-sensitive endpoints we rate-limit.
// Introspect is the most enumeration-prone (token probing) so it gets the
// highest ceiling; /token and /authorize are tighter per-client budgets.
var hotPathLimits = []endpointLimitSpec{
	{path: "/token", endpoint: telemetry.EndpointToken, envKey: "TOKEN", defaultLimit: 60, defaultWindow: time.Minute},
	{path: "/authorize", endpoint: telemetry.EndpointAuthorize, envKey: "AUTHORIZE", defaultLimit: 120, defaultWindow: time.Minute},
	{path: "/introspect", endpoint: telemetry.EndpointIntrospect, envKey: "INTROSPECT", defaultLimit: 600, defaultWindow: time.Minute},
}

// buildRateLimits constructs one rate-limit middleware per hot-path endpoint.
// When RATE_LIMIT_DISABLED is truthy every limiter is nil, so the middleware is
// a transparent passthrough. Otherwise each endpoint gets its own limiter
// (Redis-backed when redisClient is non-nil, else in-memory) with an
// independent bucket namespace and its own configurable limit/window.
func buildRateLimits(redisClient *redis.Client, logger *slog.Logger) []oidcapi.EndpointRateLimit {
	disabled := envBool("RATE_LIMIT_DISABLED")
	if disabled {
		logger.Warn("rate limiting disabled via RATE_LIMIT_DISABLED", "component", "harbor-hot")
	}

	// A trusted upstream proxy (if any) sets the real client IP here; consulted
	// only for the anonymous bucket. Empty means "trust no forwarded header".
	trustedHeader := envString("TRUSTED_FORWARDED_HEADER", "")

	limits := make([]oidcapi.EndpointRateLimit, 0, len(hotPathLimits))
	for _, spec := range hotPathLimits {
		limit := envInt("RATE_LIMIT_"+spec.envKey, spec.defaultLimit)
		window := envDuration("RATE_LIMIT_"+spec.envKey+"_WINDOW", spec.defaultWindow)

		var limiter clients.RateLimiter
		if !disabled {
			limiter = newLimiter(redisClient, spec, limit, window, logger)
		}

		mw := oidcapi.RateLimitMiddleware(oidcapi.RateLimitConfig{
			Limiter:                limiter, // nil when disabled -> passthrough
			Endpoint:               spec.endpoint,
			Window:                 window,
			Logger:                 logger,
			TrustedForwardedHeader: trustedHeader,
		})
		limits = append(limits, oidcapi.EndpointRateLimit{Path: spec.path, Middleware: mw})
	}
	return limits
}

// newLimiter returns the backend limiter for one endpoint: Redis-backed when a
// client is available (production / multi-replica), otherwise the in-memory
// fallback for local dev. The Redis key prefix namespaces buckets per endpoint
// so /token and /authorize never share a limit.
func newLimiter(redisClient *redis.Client, spec endpointLimitSpec, limit int, window time.Duration, logger *slog.Logger) clients.RateLimiter {
	cfg := clients.RateLimiterConfig{
		KeyPrefix: "ratelimit:" + string(spec.endpoint) + ":",
		Limit:     limit,
		Window:    window,
	}
	if redisClient != nil {
		return clients.NewRedisRateLimiter(redisClient, cfg, logger)
	}
	logger.Warn("REDIS_URL unset: using in-memory rate limiter (single-replica dev only)",
		"component", "harbor-hot", "endpoint", string(spec.endpoint))
	return clients.NewMemoryRateLimiter(cfg)
}

// defaultBFFSessionTTL mirrors the harbor-mgmt BFF session writer default
// (docs/plans/bff-session-middleware.md — 5 min, matching the PKCE state
// lifetime). Kept in sync so the hot-path reader and cold-path writer agree on
// how long a BFF session is valid.
const defaultBFFSessionTTL = 5 * time.Minute

// bffConfig holds the environment-derived configuration for the BFF session
// dependencies that the hot-path /authorize flow will consume once the
// auth-bypass fix lands (docs/DESIGN.md §9). It is parsed and validated at
// startup so a misconfiguration fails loudly instead of silently degrading to
// the insecure demo-user stub resolver.
type bffConfig struct {
	// LoginURL is the absolute URL of the harbor-mgmt BFF /login endpoint that
	// /authorize redirects unauthenticated users to. Empty in dev (no redirect).
	LoginURL string
	// DatabaseURL is the Postgres DSN backing the PPID session resolver. Empty
	// falls back to the in-memory dev scaffold (mirrors clients.ConnectDB).
	DatabaseURL string
	// SessionTTL is the lifetime of a BFF session record. It must match the
	// harbor-mgmt writer (docs/plans/bff-session-middleware.md — 5 min).
	SessionTTL time.Duration
}

// loadBFFConfig reads the BFF dependency configuration from the environment and
// validates it. It performs no I/O — connecting the session store and resolver
// happens in later tasks; this only captures and checks the inputs so startup
// can fail fast on a bad config.
func loadBFFConfig() (bffConfig, error) {
	cfg := bffConfig{
		LoginURL:    os.Getenv("LOGIN_URL"),
		DatabaseURL: os.Getenv("DATABASE_URL"),
		SessionTTL:  envDuration("BFF_SESSION_TTL", defaultBFFSessionTTL),
	}
	if err := cfg.validate(); err != nil {
		return bffConfig{}, err
	}
	return cfg, nil
}

// validate rejects a BFF config that would misbehave at runtime. LOGIN_URL,
// when set, must be an absolute http(s) URL with a host — a relative or
// scheme-less value would produce a broken redirect. SessionTTL must be
// positive so sessions actually persist.
func (c bffConfig) validate() error {
	if c.LoginURL != "" {
		u, err := url.Parse(c.LoginURL)
		if err != nil {
			return fmt.Errorf("invalid LOGIN_URL %q: %w", c.LoginURL, err)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return fmt.Errorf("invalid LOGIN_URL %q: must be an absolute http(s) URL", c.LoginURL)
		}
		if u.Host == "" {
			return fmt.Errorf("invalid LOGIN_URL %q: missing host", c.LoginURL)
		}
	}
	if c.SessionTTL <= 0 {
		return fmt.Errorf("invalid BFF_SESSION_TTL: must be positive, got %s", c.SessionTTL)
	}
	return nil
}

// --- tiny env helpers (no external config dependency) ---

// envString returns the value of key or def when unset/empty.
func envString(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// envInt parses key as a positive int, returning def when unset or invalid.
func envInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return def
	}
	return n
}

// envDuration parses key as a Go duration (e.g. "1m", "30s"), returning def when
// unset or invalid.
func envDuration(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return def
	}
	return d
}

// envBool reports whether key is set to a truthy value (1/true/yes/on).
func envBool(key string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}
