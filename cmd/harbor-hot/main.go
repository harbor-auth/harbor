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
//   - RATE_LIMIT_DISABLED truthy -> development-only transparent passthrough;
//     production rejects this setting at startup.
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
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
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
	runtimeCfg, err := crypto.LoadRuntimeConfigFromEnv()
	if err != nil {
		return fmt.Errorf("load runtime crypto configuration: %w", err)
	}
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

	// BFF session resolver dependencies: secret loader (DEK unwrapping for PPID
	// derivation) and grant store (consent records). Reuses the already-opened
	// pool rather than re-connecting; returns zero-value deps when pool is nil.
	var deps bffDeps
	if envBool("HARBOR_DEV_MODE") {
		deps, err = buildBFFDepsFromPool(pool, logger)
		if err != nil {
			return err
		}
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
	issuer := envString("ISSUER", "https://harbor.local")
	if !envBool("HARBOR_DEV_MODE") {
		if err := validateProductionURL("ISSUER", issuer); err != nil {
			return err
		}
		if err := validateProductionURL("LOGIN_URL", bffCfg.LoginURL); err != nil {
			return err
		}
	}

	// Bind the issuer host to a region so the region middleware resolves it.
	// In production, the issuer is region-specific (e.g. https://eu.harbor.id);
	// in dev, REGION env var overrides to allow localhost testing.
	if reg := envString("REGION", ""); reg != "" {
		if err := region.BindIssuerHost(issuer, region.Region(reg)); err != nil {
			return err
		}
	}

	// Session resolver: the real PPIDSessionResolver when the DB-backed deps are
	// wired (production), else the demo-user stub in dev mode. The real resolver
	// reads the authenticated user from the BFF session context (bff.BFFAuthSource
	// — never a client-supplied value), loads + decrypts that user's pairwise
	// secret, and derives a per-RP PPID while recording consent. This closes the
	// auth bypass (audit blocker 1.1): /authorize can no longer mint tokens for a
	// fixed demo user.
	apiCfg, graph, err := buildHotGraph(ctx, issuer, pool, redisClient, deps, runtimeCfg, logger)
	if err != nil {
		return err
	}
	if err := validateProductionReadiness(bffCfg, graph, logger); err != nil {
		return err
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

	// Admin auth boot guard and middleware wiring. The guard is fail-closed:
	// when a real DB is connected (admin endpoints are live) ADMIN_API_TOKEN
	// must be set and at least 32 bytes — refusing to boot otherwise mirrors
	// the KEK_SECRET guard above and closes the unauthenticated admin surface
	// (audit finding C2). When pool is nil (dev, no DB) the guard is skipped
	// and the middleware is still constructed; with an empty token it is
	// fail-closed and rejects every admin request with 401.
	adminToken, err := loadAdminToken(pool != nil, logger)
	if err != nil {
		return err
	}
	adminMW := oidcapi.AdminAuthMiddleware(oidcapi.AdminAuthConfig{Token: adminToken, Logger: logger})

	// Register custom endpoints not in the OpenAPI spec on the mux before
	// passing to HandlerFromMux so they are part of the same routing tree:
	//   /authorize/complete — resumes the OIDC flow after passkey login
	//   /logged-out         — browser-facing post-logout landing page
	mux := http.NewServeMux()
	mux.HandleFunc("GET /authorize/complete", srv.GetAuthorizeComplete)
	mux.HandleFunc("GET /consent", srv.GetConsent)
	mux.HandleFunc("POST /consent/complete", srv.PostConsentComplete)
	mux.HandleFunc("GET /logged-out", srv.GetLoggedOut)

	// Build the handler chain (outermost first):
	//   rate limiting → admin auth → spec-generated router
	// Rate limiting is outermost so an unauthenticated flood of admin requests
	// is throttled before the token check runs — a wrong/leaked token cannot
	// drive unbounded key-rotation or JWT-revocation attempts.
	base := openapi.HandlerFromMux(srv, mux)
	authed := oidcapi.WithAdminAuth(base, adminMW)
	handler := oidcapi.WithRateLimits(authed, buildRateLimits(redisClient, logger))

	// Support both ADDR (full address) and PORT (port-only, for docker-compose).
	addr := envString("ADDR", "")
	if addr == "" {
		port := envString("PORT", "8080")
		addr = ":" + port
	}
	return httpserver.Run(ctx, addr, handler, logger)
}

// noopSessionRevoker is a dev/test scaffold implementation of
// oidcapi.SessionRevoker. It is constructed only by buildDevHotGraph.
type noopSessionRevoker struct{}

func (noopSessionRevoker) RevokeSessionsByUserClient(_ context.Context, _, _ string) error {
	return nil
}

type redisRevocationPublisher struct{ client *redis.Client }

func (p redisRevocationPublisher) Publish(ctx context.Context, channel, message string) error {
	return p.client.Publish(ctx, channel, message).Err()
}

type revokedJTILister struct{ store *clients.DBRevokedJTIStore }

func (l revokedJTILister) ListActiveJTIs(ctx context.Context) ([]string, error) {
	rows, err := l.store.ListActive(ctx)
	if err != nil {
		return nil, err
	}
	jtis := make([]string, len(rows))
	for i := range rows {
		jtis[i] = rows[i].JTI
	}
	return jtis, nil
}

type revokedJTIChecker struct{ store *clients.DBRevokedJTIStore }

func (c revokedJTIChecker) IsRevoked(ctx context.Context, jti string) (bool, error) {
	_, found, err := c.store.GetByJTI(ctx, jti)
	return found, err
}

type codeFamilyRevoker struct{ sessions *clients.DBSessionStore }

func (r codeFamilyRevoker) RevokeCodeFamily(ctx context.Context, code oidc.AuthCode) error {
	return r.sessions.RevokeSessionsByUserClient(ctx, code.UserID, code.ClientID)
}

func buildHotGraph(ctx context.Context, issuer string, pool *pgxpool.Pool, redisClient *redis.Client, deps bffDeps, runtimeCfg crypto.RuntimeConfig, logger *slog.Logger) (oidcapi.Config, hotGraph, error) {
	if runtimeCfg.Mode == crypto.RuntimeDevelopment {
		return buildDevHotGraph(issuer, runtimeCfg, logger)
	}
	if pool == nil || redisClient == nil {
		return oidcapi.Config{}, hotGraph{}, errors.New("production harbor-hot requires PostgreSQL and Redis")
	}

	keyProvider, err := buildExternalKeyProvider(ctx, runtimeCfg.KMS)
	if err != nil {
		return oidcapi.Config{}, hotGraph{}, err
	}
	q := gendb.New(pool)
	deps = bffDeps{secretLoader: clients.NewDBSecretLoader(q, keyProvider, crypto.NewCipher()), grantStore: clients.NewDBGrantStore(q)}
	tokenIssuer, signers, rotator, err := buildSigningStackWithProvider(ctx, pool, keyProvider, logger)
	if err != nil {
		return oidcapi.Config{}, hotGraph{}, err
	}
	registry := clients.NewDBClientRegistry(q).WithLogger(logger)
	codes := clients.NewRedisAuthCodeStore(redisClient, time.Minute)
	grants := clients.NewDBGrantStore(q)
	sessionStore := clients.NewDBSessionStoreWithPool(q, pool)
	outbox := clients.NewDBRevocationOutbox(q, logger)
	revokedStore := clients.NewDBRevokedJTIStore(q)
	filter := oidc.NewBloomRevocationFilter(oidc.DefaultBloomCapacity, oidc.DefaultBloomFPRate)
	if _, err := oidc.RehydrateFilter(ctx, revokedJTILister{revokedStore}, filter, logger); err != nil {
		return oidcapi.Config{}, hotGraph{}, fmt.Errorf("harbor-hot: rehydrate revocations: %w", err)
	}
	subscriber := clients.NewRevocationSubscriber(clients.RevocationSubscriberConfig{Client: redisClient, Filter: filter, Logger: logger})
	go func() {
		if err := subscriber.Run(ctx); err != nil && ctx.Err() == nil {
			logger.Error("revocation subscriber stopped", "error", err)
		}
	}()
	worker := oidc.NewRevocationWorker(oidc.RevocationWorkerConfig{Outbox: outbox, SessionStore: sessionStore, Logger: logger})
	go worker.Run(ctx)
	verifier, err := oidc.NewJWTVerifier(oidc.JWTVerifierConfig{Signer: signers[0], Filter: filter, RevokedChecker: revokedJTIChecker{revokedStore}, ExpectedIssuer: issuer})
	if err != nil {
		return oidcapi.Config{}, hotGraph{}, fmt.Errorf("harbor-hot: build JWT verifier: %w", err)
	}
	resolver, err := newSessionResolver(deps, logger)
	if err != nil {
		return oidcapi.Config{}, hotGraph{}, err
	}
	svc := oidc.NewService(oidc.ServiceConfig{Issuer: issuer, Clients: registry, Codes: codes, Tokens: tokenIssuer, Sessions: resolver, SessionStore: sessionStore, Grants: grants, Revocations: codeFamilyRevoker{sessionStore}, Outbox: outbox, Logger: logger})
	return oidcapi.Config{Issuer: issuer, Service: svc, Signers: signers, Rotator: rotator, RevokedJTIStore: revokedStore, RevocationFilter: filter, RevocationPublisher: redisRevocationPublisher{redisClient}, RevokedJTIChecker: revokedJTIChecker{revokedStore}, LogoutVerifier: verifier, Grants: grants, Clients: registry, SessionRevoker: sessionStore}, hotGraph{postgres: true, redis: true, externalKMS: true, clientRegistry: true, authCodes: true, grants: true, sessions: true, revocations: true, outboxWorker: true, jwtVerifier: true, logoutVerifier: true, sessionRevoker: true}, nil
}

func buildDevHotGraph(issuer string, runtimeCfg crypto.RuntimeConfig, logger *slog.Logger) (oidcapi.Config, hotGraph, error) {
	if runtimeCfg.Mode != crypto.RuntimeDevelopment || runtimeCfg.DevKeySecret == "" {
		return oidcapi.Config{}, hotGraph{}, errors.New("development graph requires explicit development crypto configuration")
	}
	signer, err := crypto.NewLocalSigner()
	if err != nil {
		return oidcapi.Config{}, hotGraph{}, fmt.Errorf("build development signer: %w", err)
	}
	registry := oidc.NewInMemoryClientRegistry()
	registry.Put(oidc.Client{ID: "demo-client", SectorID: "localhost", RedirectURIs: []string{"http://localhost/callback", "http://localhost:3000/callback", "http://localhost:8081/callback"}, ScopesAllowed: []string{"openid", "profile", "email", "offline_access"}})
	grants := oidc.NewInMemoryGrantStore()
	svc := oidc.NewService(oidc.ServiceConfig{Issuer: issuer, Clients: registry, Codes: oidc.NewInMemoryAuthCodeStore(), Tokens: oidc.NewJWTIssuer(oidc.JWTIssuerConfig{Signer: signer}), Sessions: oidc.NewStubSessionResolver("demo-user-ppid"), Grants: grants, Logger: logger})
	return oidcapi.Config{Issuer: issuer, Service: svc, Signers: []crypto.Signer{signer}, Grants: grants, Clients: registry, SessionRevoker: noopSessionRevoker{}}, hotGraph{}, nil
}

func buildExternalKeyProvider(ctx context.Context, kmsConfig crypto.KMSConfig) (crypto.KeyProvider, error) {
	resolver, err := crypto.NewEnvKEKResolver(kmsConfig)
	if err != nil {
		return nil, fmt.Errorf("external KMS configuration required: %w", err)
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("external KMS client configuration: %w", err)
	}
	return crypto.NewKMSKeyProvider(crypto.NewAWSKMSClient(awskms.NewFromConfig(awsCfg)), resolver), nil
}

func buildSigningStackWithProvider(ctx context.Context, pool *pgxpool.Pool, kp crypto.KeyProvider, logger *slog.Logger) (oidc.TokenIssuer, []crypto.Signer, *crypto.KeyRotator, error) {
	reg := envString("REGION", "EU")

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
	grantStore                                                *clients.DBGrantStore
	postgres, redis, externalKMS                              bool
	clientRegistry, authCodes, grants, sessions, revocations  bool
	outboxWorker, jwtVerifier, logoutVerifier, sessionRevoker bool
}

type hotGraph = bffDeps

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
func validateProductionReadiness(cfg bffConfig, graph bffDeps, logger *slog.Logger) error {
	if envBool("HARBOR_DEV_MODE") {
		logger.Warn("HARBOR_DEV_MODE enabled — skipping production readiness checks (NEVER use in production)")
		return nil
	}
	if envBool("RATE_LIMIT_DISABLED") {
		return errors.New("RATE_LIMIT_DISABLED is not allowed in production")
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
	checks := []struct {
		ready bool
		name  string
	}{
		{graph.postgres, "PostgreSQL"}, {graph.redis, "Redis"}, {graph.externalKMS, "external KMS"},
		{graph.clientRegistry, "durable client registry"}, {graph.authCodes, "durable authorization code store"},
		{graph.grants, "durable grant store"}, {graph.sessions, "durable session store"},
		{graph.revocations, "durable revocation store"}, {graph.outboxWorker, "revocation outbox worker"},
		{graph.jwtVerifier, "JWT verifier"}, {graph.logoutVerifier, "logout verifier"},
		{graph.sessionRevoker, "session revoker"},
	}
	for _, check := range checks {
		if !check.ready {
			missing = append(missing, check.name)
		}
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
		if !envBool("HARBOR_DEV_MODE") && u.Scheme != "https" {
			hostIP := net.ParseIP(u.Hostname())
			if u.Hostname() != "localhost" && (hostIP == nil || !hostIP.IsLoopback()) {
				return fmt.Errorf("invalid LOGIN_URL %q: production login URL must use HTTPS", c.LoginURL)
			}
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
// highest ceiling; /token and /authorize are tighter per-client budgets. Admin
// endpoints get the tightest budget (10 req/min) — a leaked admin token must
// not enable unbounded key-rotation or JWT-revocation.
var hotPathLimits = []endpointLimitSpec{
	{path: "/token", endpoint: telemetry.EndpointToken, envKey: "TOKEN", defaultLimit: 60, defaultWindow: time.Minute},
	{path: "/authorize", endpoint: telemetry.EndpointAuthorize, envKey: "AUTHORIZE", defaultLimit: 120, defaultWindow: time.Minute},
	{path: "/introspect", endpoint: telemetry.EndpointIntrospect, envKey: "INTROSPECT", defaultLimit: 600, defaultWindow: time.Minute},
	{path: "/revoke", endpoint: telemetry.EndpointRevoke, envKey: "REVOKE", defaultLimit: 120, defaultWindow: time.Minute},
	{path: "/admin/keys/rotate", endpoint: telemetry.EndpointAdminRotate, envKey: "ADMIN_ROTATE", defaultLimit: 10, defaultWindow: time.Minute},
	{path: "/admin/revoke-jwt", endpoint: telemetry.EndpointAdminRevoke, envKey: "ADMIN_REVOKE", defaultLimit: 10, defaultWindow: time.Minute},
}

// buildRateLimits constructs one rate-limit middleware per hot-path endpoint.
// In explicit development mode RATE_LIMIT_DISABLED makes every limiter nil, so
// the middleware is a transparent passthrough. Production rejects the setting
// during readiness validation. Otherwise each endpoint gets its own limiter
// (Redis-backed when redisClient is non-nil, else in-memory) with an
// independent bucket namespace and its own configurable limit/window.
func buildRateLimits(redisClient *redis.Client, logger *slog.Logger) []oidcapi.EndpointRateLimit {
	disabled := envBool("RATE_LIMIT_DISABLED")
	if disabled {
		logger.Warn("rate limiting disabled via RATE_LIMIT_DISABLED", "component", "harbor-hot")
	}

	// TRUSTED_PROXY_HOPS configures the trusted-proxy-hop model for deriving the
	// real client IP from a forwarded header. Default 0 = trust nothing, use
	// RemoteAddr directly (safe for direct internet exposure).
	//
	// Set TRUSTED_PROXY_HOPS=1 when nginx-ingress is the sole proxy (it appends
	// the observed client IP to the right of X-Forwarded-For). Set =2 if an
	// additional L7 load balancer also appends. Only count proxies you control
	// that append to the header — see deploy/README.md for the footgun details.
	trustedHops := envInt("TRUSTED_PROXY_HOPS", 0)
	// TRUSTED_FORWARDED_HEADER names the header the outermost trusted proxy sets.
	// When TRUSTED_PROXY_HOPS > 0 and this is empty, X-Forwarded-For is used
	// (the nginx-ingress standard). Ignored when TRUSTED_PROXY_HOPS=0.
	trustedHeader := envString("TRUSTED_FORWARDED_HEADER", "")
	if trustedHops > 0 && trustedHeader == "" {
		trustedHeader = "X-Forwarded-For"
	}

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
			FailClosedOnError:      !envBool("HARBOR_DEV_MODE"),
			TrustedForwardedHeader: trustedHeader,
			TrustedProxyHops:       trustedHops,
		})
		limits = append(limits, oidcapi.EndpointRateLimit{Path: spec.path, Middleware: mw})
	}
	return limits
}

func validateProductionURL(name, raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid %s: %w", name, err)
	}
	if u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return fmt.Errorf("invalid %s: production requires an absolute credential-free HTTPS URL", name)
	}
	return nil
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

// minAdminTokenBytes is the minimum acceptable length for ADMIN_API_TOKEN.
// A token shorter than 32 bytes provides insufficient entropy against
// offline brute-force attacks on the SHA-256 comparison.
const minAdminTokenBytes = 32

// loadAdminToken enforces the fail-closed admin-auth boot guard. When a real
// DB is wired (databaseURLSet == true) ADMIN_API_TOKEN must be set and at
// least minAdminTokenBytes long — otherwise key-rotation and JWT-revocation
// are reachable without any credential (audit finding C2, mirrors KEK_SECRET
// guard). HARBOR_DEV_MODE bypasses the length check with a warning so that
// e2e/dev runs work without setting the token; the returned token still builds
// a fail-closed middleware (empty token → 401 on every admin request).
// The token value is never logged (docs/DESIGN.md §6.5).
func loadAdminToken(databaseURLSet bool, logger *slog.Logger) (string, error) {
	token := os.Getenv("ADMIN_API_TOKEN")
	if !databaseURLSet {
		// Admin endpoints are inert without a real DB; middleware remains
		// fail-closed regardless of token value.
		return token, nil
	}
	if envBool("HARBOR_DEV_MODE") {
		if len(token) < minAdminTokenBytes {
			logger.Warn("HARBOR_DEV_MODE: ADMIN_API_TOKEN missing or < 32 bytes — admin endpoints will reject all requests (NEVER for production)")
		}
		return token, nil
	}
	if len(token) < minAdminTokenBytes {
		return "", fmt.Errorf(
			"ADMIN_API_TOKEN must be set and at least %d bytes when DATABASE_URL is configured — "+
				"refusing to expose unauthenticated admin key-rotation/JWT-revocation endpoints",
			minAdminTokenBytes,
		)
	}
	return token, nil
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
