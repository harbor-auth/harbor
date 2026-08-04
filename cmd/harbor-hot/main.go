// Command harbor-hot is Harbor's hot-path HTTP binary: it serves the
// spec-generated OIDC surface (/authorize, /token, /introspect, /jwks.json,
// discovery, /healthz) and guards the abuse-sensitive endpoints with per-client
// rate limiting (docs/plans/rate-limiting.md).
//
// Rate-limiter wiring uses RedisRateLimiter (sliding-window, Lua-atomic, shared
// across replicas).
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
	return runWithGraphObserver(ctx, logger, nil)
}

// runWithGraphObserver is the production startup path with an optional
// integration-test observation point. The observer cannot replace any
// dependency; it only receives the fully assembled durable graph immediately
// before the HTTP server starts accepting traffic.
func runWithGraphObserver(ctx context.Context, logger *slog.Logger, observe func(hotGraph)) error {
	if os.Getenv("HARBOR_KMS_SECRET") == "" {
		return errors.New("harbor-hot requires HARBOR_KMS_SECRET for the shared user-DEK KEK")
	}
	if envBool("RATE_LIMIT_DISABLED") {
		return errors.New("RATE_LIMIT_DISABLED is not allowed in production")
	}
	kmsCfg, err := crypto.LoadKMSConfigFromEnv()
	if err != nil {
		return fmt.Errorf("load signing KMS configuration: %w", err)
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

	if os.Getenv("DATABASE_URL") == "" {
		return errors.New("harbor-hot production requires DATABASE_URL")
	}
	if os.Getenv("REDIS_URL") == "" {
		return errors.New("harbor-hot production requires REDIS_URL")
	}

	// Redis powers cross-replica rate limiting, authorization codes, revocation
	// fan-out, and shared BFF session state.
	redisClient, err := clients.ConnectRedis(ctx, logger)
	if err != nil {
		return err
	}
	if redisClient == nil {
		return errors.New("harbor-hot requires Redis")
	}
	defer func() {
		if closeErr := redisClient.Close(); closeErr != nil {
			logger.Warn("redis close error", "error", closeErr)
		}
	}()

	// Open the required DB pool once and share it across every durable store.
	pool, err := clients.ConnectDB(ctx, logger)
	if err != nil {
		if ctx.Err() != nil {
			// SIGINT/SIGTERM during startup — clean shutdown, not a crash.
			logger.Info("startup cancelled by signal — exiting cleanly", "error", err)
			return nil
		}
		return err
	}
	if pool == nil {
		return errors.New("harbor-hot requires PostgreSQL")
	}
	defer pool.Close()

	deps, err := buildBFFDepsFromPool(pool, logger)
	if err != nil {
		return err
	}
	logger.Info("BFF DB-backed dependencies wired",
		"secret_loader_wired", deps.secretLoader != nil,
		"grant_store_wired", deps.grantStore != nil,
	)

	issuer := envString("ISSUER", "https://harbor.local")
	if err := validateProductionURL("ISSUER", issuer); err != nil {
		return err
	}
	if err := validateProductionURL("LOGIN_URL", bffCfg.LoginURL); err != nil {
		return err
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
	apiCfg, graph, err := buildHotGraph(ctx, issuer, pool, redisClient, deps, kmsCfg, logger)
	if err != nil {
		return err
	}
	apiCfg.BFFSessions = newBFFSessionStore(redisClient, bffCfg.SessionTTL, logger)
	graph.implementations["bff_sessions"] = fmt.Sprintf("%T", apiCfg.BFFSessions)
	apiCfg.LoginURL = bffCfg.LoginURL
	apiCfg.BFFSessionTTL = bffCfg.SessionTTL
	logger.Info("BFF login flow enabled", "bff_session_store_redis", true, "bff_session_ttl", bffCfg.SessionTTL.String())

	srv := oidcapi.New(apiCfg)

	// The admin endpoints are always backed by the required database, so the
	// operator credential is also unconditionally required at startup. The
	// cloud-proxy credential is optional — it is only presented by
	// harbor-mgmt's cloudapi key-rotation proxy (internal/cloudapi/keys.go),
	// which is itself gated behind mgmt.cloudIntegration — so a standalone
	// harbor-hot deployment need not configure it.
	adminToken, err := loadAdminToken()
	if err != nil {
		return err
	}
	proxyToken, err := loadMgmtHotProxyToken()
	if err != nil {
		return err
	}
	adminCredentials := []oidcapi.AdminCredential{{Label: "operator", Token: adminToken}}
	if proxyToken != "" {
		adminCredentials = append(adminCredentials, oidcapi.AdminCredential{Label: "cloud-proxy", Token: proxyToken})
	}
	adminMW := oidcapi.AdminAuthMiddleware(oidcapi.AdminAuthConfig{Credentials: adminCredentials, Logger: logger})

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
	if observe != nil {
		observe(graph)
	}
	return httpserver.Run(ctx, addr, handler, logger)
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

func buildHotGraph(ctx context.Context, issuer string, pool *pgxpool.Pool, redisClient *redis.Client, deps bffDeps, kmsCfg crypto.KMSConfig, logger *slog.Logger) (oidcapi.Config, hotGraph, error) {
	if pool == nil || redisClient == nil {
		return oidcapi.Config{}, hotGraph{}, errors.New("harbor-hot requires PostgreSQL and Redis")
	}

	keyProvider, err := buildExternalKeyProvider(ctx, kmsCfg)
	if err != nil {
		return oidcapi.Config{}, hotGraph{}, err
	}
	q := gendb.New(pool)
	tokenIssuer, signers, rotator, err := buildSigningStackWithProvider(ctx, pool, keyProvider, logger)
	if err != nil {
		return oidcapi.Config{}, hotGraph{}, err
	}
	registry := clients.NewDBClientRegistry(q).WithLogger(logger)
	codes := clients.NewRedisAuthCodeStore(redisClient, time.Minute)
	grants := clients.NewDBGrantStore(q)
	consents := clients.NewDBConsentStore(q)
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
	svc, err := oidc.NewService(oidc.ServiceConfig{Issuer: issuer, Clients: registry, Codes: codes, Tokens: tokenIssuer, Sessions: resolver, SessionStore: sessionStore, Grants: grants, Consents: consents, Revocations: codeFamilyRevoker{sessionStore}, Outbox: outbox, Logger: logger})
	if err != nil {
		return oidcapi.Config{}, hotGraph{}, fmt.Errorf("harbor-hot: build OIDC service: %w", err)
	}
	return oidcapi.Config{Issuer: issuer, Service: svc, Signers: signers, Rotator: rotator, RevokedJTIStore: revokedStore, RevocationFilter: filter, RevocationPublisher: redisRevocationPublisher{redisClient}, RevokedJTIChecker: revokedJTIChecker{revokedStore}, LogoutVerifier: verifier, Grants: grants, Clients: registry, SessionRevoker: sessionStore}, hotGraph{
		secretLoader: deps.secretLoader,
		grantStore:   deps.grantStore,
		postgres:     true, redis: true, externalKMS: true,
		clientRegistry: true, authCodes: true, grants: true, sessions: true,
		revocations: true, outboxWorker: true, jwtVerifier: true,
		logoutVerifier: true, sessionRevoker: true,
		implementations: map[string]string{
			"clients":       fmt.Sprintf("%T", registry),
			"codes":         fmt.Sprintf("%T", codes),
			"grants":        fmt.Sprintf("%T", grants),
			"consents":      fmt.Sprintf("%T", consents),
			"sessions":      fmt.Sprintf("%T", sessionStore),
			"revocations":   fmt.Sprintf("%T", revokedStore),
			"outbox":        fmt.Sprintf("%T", outbox),
			"secret_loader": fmt.Sprintf("%T", deps.secretLoader),
		},
	}, nil
}

func buildExternalKeyProvider(ctx context.Context, kmsConfig crypto.KMSConfig) (crypto.KeyProvider, error) {
	resolver, err := crypto.NewEnvKEKResolver(kmsConfig)
	if err != nil {
		return nil, fmt.Errorf("external KMS configuration required: %w", err)
	}
	switch provider := strings.ToLower(envString("KMS_PROVIDER", "aws")); provider {
	case "openbao":
		client, openBaoErr := crypto.NewOpenBaoKMSClient(crypto.OpenBaoKMSConfig{
			Address:      os.Getenv("OPENBAO_ADDR"),
			Role:         os.Getenv("OPENBAO_KUBERNETES_ROLE"),
			TokenPath:    os.Getenv("OPENBAO_TOKEN_PATH"),
			CACertPath:   os.Getenv("OPENBAO_CACERT"),
			TransitMount: envString("OPENBAO_TRANSIT_MOUNT", "transit"),
		})
		if openBaoErr != nil {
			return nil, fmt.Errorf("external OpenBao KMS client configuration: %w", openBaoErr)
		}
		return crypto.NewKMSKeyProvider(client, resolver), nil
	case "aws":
		awsCfg, awsErr := awsconfig.LoadDefaultConfig(ctx)
		if awsErr != nil {
			return nil, fmt.Errorf("external KMS client configuration: %w", awsErr)
		}
		return crypto.NewKMSKeyProvider(crypto.NewAWSKMSClient(awskms.NewFromConfig(awsCfg)), resolver), nil
	default:
		return nil, fmt.Errorf("external KMS provider %q is unsupported", provider)
	}
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
// blocker 1.1). They are constructed once at startup from required storage.
type bffDeps struct {
	// secretLoader decrypts a user's pairwise secret for PPID derivation.
	secretLoader *clients.DBSecretLoader
	// grantStore reads and writes consent grants (the pairwise_sub an RP sees).
	grantStore                                                *clients.DBGrantStore
	postgres, redis, externalKMS                              bool
	clientRegistry, authCodes, grants, sessions, revocations  bool
	outboxWorker, jwtVerifier, logoutVerifier, sessionRevoker bool
	implementations                                           map[string]string
}

type hotGraph = bffDeps

// buildBFFDepsFromPool constructs the BFF session resolver dependencies from an
// already-opened DB pool. The caller (run) manages the pool lifecycle; this
// function does not open or close it. A nil pool is rejected.
//
// A configured pool REQUIRES HARBOR_KMS_SECRET: the secret loader unwraps DEKs
// that harbor-mgmt's enrollment sealed under that same KMS secret, so the two
// binaries MUST derive the regional KEK identically or every unwrap fails. A
// missing secret against a real DB is therefore fatal — falling back to a
// hardcoded dev key would let anyone with the source re-derive every enrolled
// user's pairwise secret.
func buildBFFDepsFromPool(pool *pgxpool.Pool, logger *slog.Logger) (bffDeps, error) {
	if pool == nil {
		return bffDeps{}, errors.New("build BFF dependencies: PostgreSQL is required")
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
// Redis-backed for multi-replica safety.
func newBFFSessionStore(redisClient *redis.Client, ttl time.Duration, _ *slog.Logger) bff.BFFSessionStore {
	return bff.NewRedisBFFSessionStore(redisClient, ttl)
}

// newSessionResolver returns the SessionResolver the OIDC /authorize flow uses
// to resolve the authenticated user into a per-RP pairwise subject (PPID).
//
// With the required DB-backed dependencies, it returns the real
// oidc.PPIDSessionResolver: it
// reads the signed-in user from the BFF session context (bff.BFFAuthSource —
// never a client-supplied value), loads + decrypts that user's pairwise secret,
// and derives a stable, non-correlating sub while recording consent
// (docs/DESIGN.md §3.2, §11.2). This closes the auth bypass: /authorize can no
// longer issue tokens for a fixed demo user.
func newSessionResolver(deps bffDeps, logger *slog.Logger) (oidc.SessionResolver, error) {
	if deps.secretLoader == nil || deps.grantStore == nil {
		return nil, errors.New("session resolver requires DATABASE_URL and HARBOR_KMS_SECRET")
	}
	logger.Info("session resolver: using PPIDSessionResolver (BFF-authenticated, DB-backed)")
	return oidc.NewPPIDSessionResolver(oidc.PPIDSessionResolverConfig{
		Auth:   bff.NewBFFAuthSource(),
		Loader: deps.secretLoader,
		Grants: deps.grantStore,
	}), nil
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
	// LoginURL is the required absolute URL of harbor-mgmt's BFF /login endpoint.
	LoginURL string
	// DatabaseURL is the required Postgres DSN backing the PPID session resolver.
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
	if c.LoginURL == "" {
		return errors.New("LOGIN_URL is required")
	}
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
	if u.Scheme != "https" {
		hostIP := net.ParseIP(u.Hostname())
		if u.Hostname() != "localhost" && (hostIP == nil || !hostIP.IsLoopback()) {
			return fmt.Errorf("invalid LOGIN_URL %q: production login URL must use HTTPS", c.LoginURL)
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
			FailClosedOnError:      true,
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
	hostIP := net.ParseIP(u.Hostname())
	loopbackHTTP := u.Scheme == "http" && (u.Hostname() == "localhost" || (hostIP != nil && hostIP.IsLoopback()))
	if (u.Scheme != "https" && !loopbackHTTP) || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return fmt.Errorf("invalid %s: requires an absolute credential-free HTTPS URL (HTTP is limited to loopback integration endpoints)", name)
	}
	return nil
}

// newLimiter returns the Redis-backed limiter for one endpoint. The Redis key
// prefix namespaces buckets per endpoint so /token and /authorize never share
// a limit.
func newLimiter(redisClient *redis.Client, spec endpointLimitSpec, limit int, window time.Duration, logger *slog.Logger) clients.RateLimiter {
	cfg := clients.RateLimiterConfig{
		KeyPrefix: "ratelimit:" + string(spec.endpoint) + ":",
		Limit:     limit,
		Window:    window,
	}
	return clients.NewRedisRateLimiter(redisClient, cfg, logger)
}

// minAdminTokenBytes is the minimum acceptable length for ADMIN_API_TOKEN.
// A token shorter than 32 bytes provides insufficient entropy against
// offline brute-force attacks on the SHA-256 comparison.
const minAdminTokenBytes = 32

// loadAdminToken enforces the fail-closed admin-auth boot guard. ADMIN_API_TOKEN must be set and at
// least minAdminTokenBytes long — otherwise key-rotation and JWT-revocation
// are reachable without any credential (audit finding C2, mirrors KEK_SECRET
// The token value is never logged (docs/DESIGN.md §6.5).
func loadAdminToken() (string, error) {
	token := os.Getenv("ADMIN_API_TOKEN")
	if len(token) < minAdminTokenBytes {
		return "", fmt.Errorf(
			"ADMIN_API_TOKEN must be set and at least %d bytes when DATABASE_URL is configured — "+
				"refusing to expose unauthenticated admin key-rotation/JWT-revocation endpoints",
			minAdminTokenBytes,
		)
	}
	return token, nil
}

// loadMgmtHotProxyToken loads the optional MGMT_HOT_PROXY_TOKEN admin
// credential (label "cloud-proxy") that harbor-mgmt's cloudapi key-rotation
// proxy presents instead of ADMIN_API_TOKEN, so leaking one credential never
// leaks the other. Unlike ADMIN_API_TOKEN this is optional — harbor-hot
// serves fine without Harbor Cloud integration configured — but when set it
// must meet the same minimum-entropy bar; an empty return means "not
// configured", not "fail closed".
func loadMgmtHotProxyToken() (string, error) {
	token := os.Getenv("MGMT_HOT_PROXY_TOKEN")
	if token == "" {
		return "", nil
	}
	if len(token) < minAdminTokenBytes {
		return "", fmt.Errorf("MGMT_HOT_PROXY_TOKEN must be at least %d bytes when set", minAdminTokenBytes)
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
