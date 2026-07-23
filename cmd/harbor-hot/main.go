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
	"errors"
	"fmt"
	"log/slog"
	"net/http"
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
	gendb "github.com/harbor-auth/harbor/internal/gen/db"
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
	// startup rather than surfacing later when /authorize needs them.
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

	// Redis powers cross-replica rate limiting AND shared BFF session state.
	// ConnectRedis returns (nil, nil) when REDIS_URL is unset — we then fall
	// back to in-memory limiters and an in-memory BFF session store.
	redisClient, err := clients.ConnectRedis(ctx, logger)
	if err != nil {
		return err
	}

	// Open the DB pool once — shared by both the signing stack (signing keys)
	// and the BFF session resolver deps (DEK unwrapping, grant store). When
	// DATABASE_URL is unset, pool is nil and both sub-systems degrade to their
	// dev-only fallbacks.
	pool, err := clients.ConnectDB(ctx, logger)
	if err != nil {
		if ctx.Err() != nil {
			// SIGINT/SIGTERM during startup — clean shutdown, not a crash.
			logger.Info("startup cancelled by signal — exiting cleanly", "error", err)
			return nil
		}
		return err
	}
	if pool != nil {
		defer pool.Close()
	}

	// Signing stack: real ES256 JWT issuer + JWKS + rotator when a DB is wired;
	// unsigned placeholder otherwise.
	tokenIssuer := oidc.TokenIssuer(oidc.NewPlaceholderIssuer())
	var signers []crypto.Signer
	var rotator *crypto.KeyRotator
	if pool != nil {
		tokenIssuer, signers, rotator, err = buildSigningStack(ctx, pool, logger)
		if err != nil {
			return err
		}
	} else {
		logger.Warn("DATABASE_URL not set — using unsigned placeholder token issuer (dev only; NEVER for production)")
	}

	// BFF session resolver dependencies: secret loader (DEK unwrapping for PPID
	// derivation) and grant store (consent records). Reuses the already-opened
	// pool rather than re-connecting; returns zero-value deps when pool is nil.
	deps, err := buildBFFDepsFromPool(pool, logger)
	if err != nil {
		return err
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

	// Grant store for consent records. The end_session handler reverse-looks-up
	// the internal userID from an id_token_hint's PPID via this store. In
	// production this is a DB-backed clients.DBGrantStore.
	grantStore := oidc.NewInMemoryGrantStore()

	// Session resolver: the real PPIDSessionResolver when the DB-backed deps are
	// wired (production), else the demo-user stub in dev mode. The real resolver
	// reads the authenticated user from the BFF session context (bff.BFFAuthSource
	// — never a client-supplied value), loads + decrypts that user's pairwise
	// secret, and derives a per-RP PPID while recording consent. This closes the
	// auth bypass (audit blocker 1.1): /authorize can no longer mint tokens for a
	// fixed demo user.
	sessions, err := newSessionResolver(deps, logger)
	if err != nil {
		return err
	}

	oidcSvc := oidc.NewService(oidc.ServiceConfig{
		Issuer:   issuer,
		Clients:  clientRegistry,
		Codes:    oidc.NewInMemoryAuthCodeStore(),
		Tokens:   tokenIssuer,
		Sessions: sessions,
		Logger:   logger,
	})

	// RP-Initiated Logout (/end_session) dependencies. In dev/test scaffolding
	// there is no configured signer, so the LogoutVerifier is left nil and the
	// end_session handler degrades gracefully — it redirects to /logged-out
	// without revoking. Production wiring supplies a JWTVerifier (built from the
	// active signer + region issuer) and a DB-backed SessionRevoker here.
	var logoutVerifier oidcapi.LogoutVerifier
	sessionRevoker := noopSessionRevoker{}

	apiCfg := oidcapi.Config{
		Issuer:         issuer,
		Service:        oidcSvc,
		Signers:        signers,
		Rotator:        rotator,
		LogoutVerifier: logoutVerifier,
		Grants:         grantStore,
		Clients:        clientRegistry,
		SessionRevoker: sessionRevoker,
	}

	// Wire the BFF login flow when LOGIN_URL is configured: /authorize then
	// creates a BFF session and redirects to the login UI instead of issuing a
	// code for the demo user (audit blocker 1.1, auth bypass). The session store
	// shares the "bff_session:" Redis namespace with harbor-mgmt, so a login
	// completed on the cold path is visible to /authorize here. When LOGIN_URL is
	// unset (dev/e2e) the BFF flow stays off and /authorize keeps its current
	// direct-issuance behavior.
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

	// Register custom endpoints not in the OpenAPI spec on the mux before
	// passing to HandlerFromMux so they are part of the same routing tree:
	//   /authorize/complete — resumes the OIDC flow after passkey login
	//   /logged-out         — browser-facing post-logout landing page
	mux := http.NewServeMux()
	mux.HandleFunc("GET /authorize/complete", srv.GetAuthorizeComplete)
	mux.HandleFunc("GET /logged-out", srv.GetLoggedOut)

	// Wrap the spec-generated router with per-endpoint rate limiting. Only the
	// hot-path endpoints listed here are guarded; /healthz, /jwks.json and
	// discovery pass through untouched.
	base := openapi.HandlerFromMux(srv, mux)
	handler := oidcapi.WithRateLimits(base, buildRateLimits(redisClient, logger))

	// Support both ADDR (full address) and PORT (port-only, for docker-compose).
	addr := envString("ADDR", "")
	if addr == "" {
		port := envString("PORT", "8080")
		addr = ":" + port
	}
	return httpserver.Run(ctx, addr, handler, logger)
}

// noopSessionRevoker is a dev/test scaffold implementation of
// oidcapi.SessionRevoker. It records nothing — dev runs use the stub session
// resolver and do not persist refresh sessions, so there is nothing to revoke.
// Production wiring replaces this with a DB-backed clients.DBSessionStore.
type noopSessionRevoker struct{}

func (noopSessionRevoker) RevokeSessionsByUserClient(_ context.Context, _, _ string) error {
	return nil
}

// buildSigningStack wires the real ES256 signing path for harbor-hot: it loads
// (or, on a cold start, seeds) the live signing keys from the DB, unwraps their
// private keys under the regional KEK, and returns the JWT issuer, the JWKS
// signer set, and the key rotator that drives POST /admin/keys/rotate
// (docs/DESIGN.md §7.3, §3.5).
//
// It fails closed: when a real DB is wired, KEK_SECRET MUST be set (mirrors the
// harbor-mgmt HARBOR_KMS_SECRET guard) — otherwise signing keys would be sealed
// under a derivable dev key.
func buildSigningStack(ctx context.Context, pool *pgxpool.Pool, logger *slog.Logger) (oidc.TokenIssuer, []crypto.Signer, *crypto.KeyRotator, error) {
	reg := envString("REGION", "EU")

	kekSecret := envString("KEK_SECRET", "")
	if kekSecret == "" {
		return nil, nil, nil, errors.New("KEK_SECRET must be set when DATABASE_URL is configured — refusing to seal signing keys under a derivable dev key")
	}
	kp, err := crypto.NewLocalKeyProvider(kekSecret)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("harbor-hot: build key provider: %w", err)
	}

	keyStore := clients.NewDBSigningKeyStore(gendb.New(pool))
	loader := clients.NewSigningKeyLoader(keyStore, kp, reg)

	provider, err := loader.SeedAndLoad(ctx)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("harbor-hot: load signing keys: %w", err)
	}
	signers := provider.AllSigners()
	logger.Info("signing keys loaded", "count", len(signers), "active_kid", provider.ActiveSigner().KeyID())

	issuer := oidc.NewJWTIssuer(oidc.JWTIssuerConfig{Signer: provider.ActiveSigner()})

	rotStore := clients.NewDBRotationStore(keyStore, reg)
	mgr := crypto.NewRotationManager(crypto.DefaultRotationConfig())
	rotator := crypto.NewKeyRotator(mgr, provider, rotStore).
		WithPrivateKeyWrapper(clients.NewPrivateKeyWrapper(kp, reg))

	return issuer, signers, rotator, nil
}

// bffDeps bundles the DB-backed dependencies the PPIDSessionResolver needs to
// replace the insecure demo-user stub resolver (docs/DESIGN.md §9, audit
// blocker 1.1). They are constructed once at startup so a later task can wire
// the real resolver without re-plumbing DB access. When pool is nil (no
// DATABASE_URL) every field is nil and the caller falls back to dev mode.
type bffDeps struct {
	// secretLoader decrypts a user's pairwise secret for PPID derivation.
	secretLoader *clients.DBSecretLoader
	// grantStore reads and writes consent grants (the pairwise_sub an RP sees).
	grantStore *clients.DBGrantStore
}

// buildBFFDepsFromPool constructs the BFF session resolver dependencies from an
// already-opened DB pool. The caller (run) manages the pool lifecycle; this
// function does not open or close it. When pool is nil (DATABASE_URL unset), it
// returns zero-value deps — the dev path where HARBOR_DEV_MODE skips the
// readiness guard and newSessionResolver falls back to StubSessionResolver.
//
// A configured pool REQUIRES HARBOR_KMS_SECRET: the secret loader unwraps DEKs
// that harbor-mgmt's enrollment sealed under that same KMS secret, so the two
// binaries MUST derive the regional KEK identically or every unwrap fails. A
// missing secret against a real DB is therefore fatal — falling back to a
// hardcoded dev key would let anyone with the source re-derive every enrolled
// user's pairwise secret.
func buildBFFDepsFromPool(pool *pgxpool.Pool, logger *slog.Logger) (bffDeps, error) {
	if pool == nil {
		logger.Warn("DATABASE_URL not set — BFF session resolver deps unavailable (dev only; session resolver will use stub)")
		return bffDeps{}, nil
	}

	kmsSecret := os.Getenv("HARBOR_KMS_SECRET")
	if kmsSecret == "" {
		return bffDeps{}, fmt.Errorf("HARBOR_KMS_SECRET must be set when DATABASE_URL is configured — refusing to unwrap user secrets with a dev key against a real DB")
	}
	keys, err := crypto.NewLocalKeyProvider(kmsSecret)
	if err != nil {
		return bffDeps{}, fmt.Errorf("create BFF key provider: %w", err)
	}

	q := gendb.New(pool)
	return bffDeps{
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
// When the DB-backed deps are wired (DATABASE_URL + HARBOR_KMS_SECRET set) AND
// HARBOR_DEV_MODE is NOT set, it returns the real oidc.PPIDSessionResolver: it
// reads the signed-in user from the BFF session context (bff.BFFAuthSource —
// never a client-supplied value), loads + decrypts that user's pairwise secret,
// and derives a stable, non-correlating sub while recording consent
// (docs/DESIGN.md §3.2, §11.2). This closes the auth bypass (audit blocker
// 1.1): /authorize can no longer issue tokens for a fixed demo user.
//
// When HARBOR_DEV_MODE=1 (dev/e2e), the stub resolver is used regardless of
// whether the DB is wired. This lets developers test the real ES256 signing
// stack (DATABASE_URL + KEK_SECRET) while still running the /authorize flow
// without a full BFF login ceremony. The fail-closed startup guard
// (validateProductionReadiness) ensures the stub is never served in production.
func newSessionResolver(deps bffDeps, logger *slog.Logger) (oidc.SessionResolver, error) {
	if envBool("HARBOR_DEV_MODE") {
		logger.Warn("HARBOR_DEV_MODE: using StubSessionResolver (signing stack still real when DB wired; NEVER for production)")
		return oidc.NewStubSessionResolver("demo-user-ppid"), nil
	}
	if deps.secretLoader == nil || deps.grantStore == nil {
		return nil, fmt.Errorf("session resolver requires DATABASE_URL + HARBOR_KMS_SECRET — set HARBOR_DEV_MODE=1 to bypass (dev/e2e only)")
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

// defaultBFFSessionTTL mirrors the harbor-mgmt BFF session writer default
// (docs/plans/bff-session-middleware.md — 5 min, matching the PKCE state
// lifetime). Kept in sync so the hot-path reader and cold-path writer agree on
// how long a BFF session is valid.
const defaultBFFSessionTTL = 5 * time.Minute

// bffConfig holds the environment-derived configuration for the BFF session
// dependencies that the hot-path /authorize flow consumes (docs/DESIGN.md §9).
// It is parsed and validated at startup so a misconfiguration fails loudly
// instead of silently degrading to the insecure demo-user stub resolver.
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
// happens later; this only captures and checks the inputs so startup can fail
// fast on a bad config.
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
	{path: "/revoke", endpoint: telemetry.EndpointRevoke, envKey: "REVOKE", defaultLimit: 120, defaultWindow: time.Minute},
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
