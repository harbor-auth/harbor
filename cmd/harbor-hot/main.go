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

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/harbor-auth/harbor/internal/bff"
	"github.com/harbor-auth/harbor/internal/clients"
	"github.com/harbor-auth/harbor/internal/crypto"
	"github.com/harbor-auth/harbor/internal/gen/db"
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

	// Open the DB pool and wire the DB-backed dependencies the future
	// PPIDSessionResolver consumes (docs/DESIGN.md §9): the secret loader
	// (unwraps each user's pairwise secret for PPID derivation) and the grant
	// store (consent grants / the pairwise_sub an RP sees). Constructed here so
	// a later task can swap the insecure demo-user stub resolver for the real
	// PPIDSessionResolver without re-plumbing DB access. When DATABASE_URL is
	// unset these are nil and the stub resolver stays (dev only).
	deps, err := buildBFFDeps(ctx, logger)
	if err != nil {
		return err
	}
	if deps.pool != nil {
		defer deps.pool.Close()
	}
	logger.Info("BFF DB-backed dependencies wired",
		"secret_loader_wired", deps.secretLoader != nil,
		"grant_store_wired", deps.grantStore != nil,
	)

	// Fail-closed startup guard: production deployments MUST have the complete
	// BFF flow wired (LOGIN_URL + DATABASE_URL + REDIS_URL) or we refuse to
	// start. Without all three, /authorize would either skip the login redirect
	// entirely or fall back to the insecure demo-user stub resolver — both are
	// total auth bypasses (audit blocker 1.1). The HARBOR_DEV_MODE escape hatch
	// allows local dev and e2e tests to run without the full stack.
	if err := validateProductionReadiness(bffCfg, deps, logger); err != nil {
		return err
	}

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

	// Session resolver: the real PPIDSessionResolver when the DB-backed deps are
	// wired (production), else the dev stub. The real resolver reads the
	// authenticated user from the BFF session context (bff.BFFAuthSource — never a
	// client-supplied value), loads + decrypts that user's pairwise secret, and
	// derives a per-RP PPID while recording consent. This is the seam that closes
	// the auth bypass (audit blocker 1.1): /authorize can no longer mint tokens
	// for a fixed demo user. The stub is retained ONLY for dev/e2e (no
	// DATABASE_URL); a fail-closed startup guard rejecting it in production lands
	// in a later task.
	sessions, err := newSessionResolver(deps, logger)
	if err != nil {
		return err
	}

	oidcSvc := oidc.NewService(oidc.ServiceConfig{
		Issuer:   issuer,
		Clients:  clientRegistry,
		Codes:    oidc.NewInMemoryAuthCodeStore(),
		Tokens:   oidc.NewPlaceholderIssuer(),
		Sessions: sessions,
		Logger:   logger,
	})

	// Wire the BFF login flow when LOGIN_URL is configured: /authorize then
	// creates a BFF session and redirects to the login UI instead of issuing a
	// code for the demo user (audit blocker 1.1, auth bypass). The session store
	// shares the "bff_session:" Redis namespace with harbor-mgmt, so a login
	// completed on the cold path (harbor-mgmt /login/complete) is visible to
	// /authorize here. When LOGIN_URL is unset (dev/e2e) the BFF flow stays off
	// and /authorize keeps its current direct-issuance behavior — the real
	// PPIDSessionResolver swap and fail-closed startup guard land in later tasks.
	apiCfg := oidcapi.Config{Issuer: issuer, Service: oidcSvc}
	if bffCfg.LoginURL != "" {
		apiCfg.BFFSessions = newBFFSessionStore(redisClient, bffCfg.SessionTTL, logger)
		apiCfg.LoginURL = bffCfg.LoginURL
		apiCfg.BFFSessionTTL = bffCfg.SessionTTL
		logger.Info("BFF login flow enabled",
			"bff_session_store_redis", redisClient != nil,
			"bff_session_ttl", bffCfg.SessionTTL.String(),
		)
	} else {
		logger.Warn("LOGIN_URL not set — BFF login flow disabled; /authorize will not redirect to login (dev only)")
	}

	srv := oidcapi.New(apiCfg)

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

// bffDeps bundles the DB-backed dependencies the PPIDSessionResolver needs to
// replace the insecure demo-user stub resolver (docs/DESIGN.md §9, audit
// blocker 1.1). They are constructed once at startup so a later task can wire
// the real resolver without re-plumbing DB access. When DATABASE_URL is unset
// every field is nil and the caller errors out (no stub fallback).
type bffDeps struct {
	// pool is the pgx connection pool. nil in dev (no DATABASE_URL); the caller
	// closes it on shutdown when non-nil.
	pool *pgxpool.Pool
	// secretLoader decrypts a user's pairwise secret for PPID derivation.
	secretLoader *clients.DBSecretLoader
	// grantStore reads and writes consent grants (the pairwise_sub an RP sees).
	grantStore *clients.DBGrantStore
}

// buildBFFDeps opens the DB pool from DATABASE_URL and constructs the
// DB-backed secret loader and grant store from a shared db.Queries. It returns
// zero-value deps (all nil) when DATABASE_URL is unset — the dev path that
// errors out rather than degrading to stub.
//
// A configured DATABASE_URL REQUIRES HARBOR_KMS_SECRET: the secret loader
// unwraps DEKs that harbor-mgmt's enrollment sealed under that same KMS secret,
// so the two binaries MUST derive the regional KEK identically or every unwrap
// fails. A missing secret against a real DB is therefore fatal (mirrors the
// harbor-mgmt guard) — falling back to a hardcoded dev key would let anyone
// with the source re-derive every enrolled user's pairwise secret.
func buildBFFDeps(ctx context.Context, logger *slog.Logger) (bffDeps, error) {
	pool, err := clients.ConnectDB(ctx, logger)
	if err != nil {
		return bffDeps{}, err
	}
	if pool == nil {
		logger.Warn("DATABASE_URL not set — BFF session resolver deps unavailable (dev only; session resolver will fail)")
		return bffDeps{}, nil
	}

	kmsSecret := os.Getenv("HARBOR_KMS_SECRET")
	if kmsSecret == "" {
		pool.Close()
		return bffDeps{}, fmt.Errorf("HARBOR_KMS_SECRET must be set when DATABASE_URL is configured — refusing to unwrap user secrets with a dev key against a real DB")
	}
	keys, err := crypto.NewLocalKeyProvider(kmsSecret)
	if err != nil {
		pool.Close()
		return bffDeps{}, fmt.Errorf("create key provider: %w", err)
	}

	q := db.New(pool)
	return bffDeps{
		pool:         pool,
		secretLoader: clients.NewDBSecretLoader(q, keys, crypto.NewCipher()),
		grantStore:   clients.NewDBGrantStore(q),
	}, nil
}

// newBFFSessionStore returns the BFF session store the hot-path /authorize flow
// reads to find the user a login ceremony authenticated. It shares the
// "bff_session:" Redis namespace with harbor-mgmt's writer so a login completed
// on the cold path is visible here (docs/plans/bff-session-middleware.md).
// Redis-backed for multi-replica safety when REDIS_URL is set, otherwise an
// in-memory dev scaffold (single-replica only; not shared across replicas).
func newBFFSessionStore(redisClient *redis.Client, ttl time.Duration, logger *slog.Logger) bff.BFFSessionStore {
	if redisClient != nil {
		return bff.NewRedisBFFSessionStore(redisClient, ttl)
	}
	logger.Warn("REDIS_URL not set — using in-memory BFF session store (dev only; not shared across replicas)")
	return bff.NewInMemoryBFFSessionStore()
}

// newSessionResolver returns the SessionResolver the OIDC /authorize flow uses
// to resolve the authenticated user into a per-RP pairwise subject (PPID).
//
// When the DB-backed deps are wired (DATABASE_URL set), it returns the real
// oidc.PPIDSessionResolver: it reads the signed-in user from the BFF session
// context (bff.BFFAuthSource — never a client-supplied value), loads + decrypts
// that user's pairwise secret, and derives a stable, non-correlating sub while
// recording consent (docs/DESIGN.md §3.2, §11.2). This is what closes the auth
// bypass (audit blocker 1.1): /authorize can no longer issue tokens for a fixed
// demo user.
//
// When DATABASE_URL is unset (dev/e2e), it falls back to the demo-user stub so
// local runs keep working. A fail-closed startup guard that refuses to serve
// with the stub in production lands in a later task.
//
// The deps.secretLoader/deps.grantStore nil check gates on the CONCRETE pointer
// (both are set together only when the pool is opened), avoiding the typed-nil
// interface pitfall — a nil *DBSecretLoader wrapped in a non-nil
// oidc.UserSecretLoader would pass an `!= nil` interface check yet panic on use.
func newSessionResolver(deps bffDeps, logger *slog.Logger) (oidc.SessionResolver, error) {
	if deps.secretLoader == nil || deps.grantStore == nil {
		return nil, fmt.Errorf("session resolver requires DATABASE_URL + HARBOR_KMS_SECRET — refusing to start without a real BFF-authenticated resolver")
	}
	logger.Info("session resolver: using PPIDSessionResolver (BFF-authenticated, DB-backed)")
	return oidc.NewPPIDSessionResolver(oidc.PPIDSessionResolverConfig{
		Auth:   bff.NewBFFAuthSource(),
		Loader: deps.secretLoader,
		Grants: deps.grantStore,
	}), nil
}

// validateProductionReadiness enforces the fail-closed startup guard: in
// production (HARBOR_DEV_MODE not set), the complete BFF auth flow must be
// wired — LOGIN_URL for the redirect, DATABASE_URL for the PPIDSessionResolver
// deps, and implicitly REDIS_URL for the shared BFF session store. Without all
// three, /authorize would silently degrade to the insecure demo-user stub or
// skip the login redirect, both of which are total auth bypasses.
//
// Dev and e2e runs set HARBOR_DEV_MODE=1 to bypass this guard; they accept the
// security trade-off of running without a real identity backend.
func validateProductionReadiness(cfg bffConfig, deps bffDeps, logger *slog.Logger) error {
	if envBool("HARBOR_DEV_MODE") {
		logger.Warn("HARBOR_DEV_MODE enabled — skipping production readiness checks (NEVER use in production)")
		return nil
	}

	var missing []string
	if cfg.LoginURL == "" {
		missing = append(missing, "LOGIN_URL")
	}
	if os.Getenv("REDIS_URL") == "" {
		missing = append(missing, "REDIS_URL (required for shared BFF session store)")
	}
	if cfg.DatabaseURL == "" {
		missing = append(missing, "DATABASE_URL")
	}
	if deps.secretLoader == nil {
		missing = append(missing, "secret_loader (requires DATABASE_URL + HARBOR_KMS_SECRET)")
	}
	if deps.grantStore == nil {
		missing = append(missing, "grant_store (requires DATABASE_URL)")
	}

	if len(missing) > 0 {
		return fmt.Errorf("production startup guard failed: missing required BFF dependencies %v — set HARBOR_DEV_MODE=1 to bypass (dev/e2e only)", missing)
	}

	logger.Info("production readiness check passed",
		"login_url_set", true,
		"redis_url_set", true,
		"secret_loader_wired", true,
		"grant_store_wired", true,
	)
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
