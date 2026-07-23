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
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

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

	// DB-backed signing keys plug in when DATABASE_URL is configured; otherwise
	// we fall back to the unsigned placeholder issuer for local dev (tokens are
	// obviously fake and JWKS is empty).
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

	oidcSvc := oidc.NewService(oidc.ServiceConfig{
		Issuer:   issuer,
		Clients:  clientRegistry,
		Codes:    oidc.NewInMemoryAuthCodeStore(),
		Tokens:   tokenIssuer,
		Sessions: oidc.NewStubSessionResolver("demo-user-ppid"),
		Logger:   logger,
	})

	// RP-Initiated Logout (/end_session) dependencies. In dev/test scaffolding
	// there is no configured signer, so the LogoutVerifier is left nil and the
	// end_session handler degrades gracefully — it redirects to /logged-out
	// without revoking. Production wiring supplies a JWTVerifier (built from the
	// active signer + region issuer) and a DB-backed SessionRevoker here.
	var logoutVerifier oidcapi.LogoutVerifier
	sessionRevoker := noopSessionRevoker{}

	srv := oidcapi.New(oidcapi.Config{
		Issuer:         issuer,
		Service:        oidcSvc,
		Signers:        signers,
		Rotator:        rotator,
		LogoutVerifier: logoutVerifier,
		Grants:         grantStore,
		Clients:        clientRegistry,
		SessionRevoker: sessionRevoker,
	})

	// Wrap the spec-generated router with per-endpoint rate limiting. Only the
	// hot-path endpoints listed here are guarded; /healthz, /jwks.json and
	// discovery pass through untouched.
	base := openapi.Handler(srv)

	// The /logged-out page is the default post-logout destination for
	// RP-Initiated Logout. It is NOT part of the OpenAPI contract (it is a
	// browser-facing static page, not an API), so it is registered manually here
	// rather than by the generated router. Requests that don't match /logged-out
	// fall through to the generated OIDC surface.
	mux := http.NewServeMux()
	mux.HandleFunc("GET /logged-out", srv.GetLoggedOut)
	mux.Handle("/", base)

	handler := oidcapi.WithRateLimits(mux, buildRateLimits(redisClient, logger))

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
