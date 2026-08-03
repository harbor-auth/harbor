// Command harbor-mgmt is the management / dashboard cold-path binary
// (docs/DESIGN.md §4.1, §8). It serves the dashboard/BFF, enrollment, consent,
// audit and admin surfaces.
//
// It exposes the complete durable management graph: enrollment and WebAuthn,
// dynamic client registration, consent/session management, recovery and MFA,
// compliance/audit, dashboard, and relay surfaces.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/harbor-auth/harbor/internal/bff"
	"github.com/harbor-auth/harbor/internal/clients"
	"github.com/harbor-auth/harbor/internal/cloudapi"
	"github.com/harbor-auth/harbor/internal/crypto"
	"github.com/harbor-auth/harbor/internal/gen/db"
	"github.com/harbor-auth/harbor/internal/httpserver"
	"github.com/harbor-auth/harbor/internal/identity"
	"github.com/harbor-auth/harbor/internal/mfa"
	"github.com/harbor-auth/harbor/internal/mgmtapi"
	"github.com/harbor-auth/harbor/internal/region"
	"github.com/harbor-auth/harbor/internal/relay"
	"github.com/harbor-auth/harbor/internal/telemetry"
	"github.com/harbor-auth/harbor/internal/webauthn"
	"github.com/harbor-auth/harbor/web"
)

// bffSessionTTL is the lifetime of BFF session records (docs/plans/
// bff-session-middleware.md — 5 min, matching the PKCE state lifetime).
const bffSessionTTL = 5 * time.Minute

// Compile-time proof that clients.DBAuditStore satisfies mgmtapi.AuditStore.
// Placed at package scope (where both packages are imported) to avoid the
// import cycle that would arise inside internal/clients itself.
var _ mgmtapi.AuditStore = (*clients.DBAuditStore)(nil)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	err := run(ctx, logger)
	if err != nil && ctx.Err() == nil {
		logger.Error("harbor-mgmt exited", "error", err)
		os.Exit(1)
	}
}

// run is the fail-closed composition root. Every stateful dependency served
// from this graph is shared by all replicas.
func run(ctx context.Context, logger *slog.Logger) error {
	userDEKKEK := os.Getenv("HARBOR_KMS_SECRET")
	if userDEKKEK == "" {
		return errors.New("harbor-mgmt requires HARBOR_KMS_SECRET for the shared user-DEK KEK")
	}
	if envBool("RATE_LIMIT_DISABLED") {
		return errors.New("RATE_LIMIT_DISABLED is not allowed in production")
	}
	// The Harbor Cloud management API (internal/cloudapi) is wired only when
	// explicitly enabled (mgmt.cloudIntegration.enabled in deploy config) —
	// harbor-hot's public listener never imports this package, and by
	// default no /admin/v1/* route is registered at all (a 404, not an
	// auth failure). When enabled, its three dependencies are required
	// up front so a misconfigured deployment fails at boot rather than
	// serving cloudapi routes that silently 401 every request.
	cloudIntegrationEnabled := envBool("CLOUD_INTEGRATION_ENABLED")
	var cloudServiceAuthPublicKey, cloudHotProxyToken, cloudHotInternalURL string
	if cloudIntegrationEnabled {
		cloudServiceAuthPublicKey = os.Getenv("CLOUD_SERVICE_AUTH_PUBLIC_KEY")
		if cloudServiceAuthPublicKey == "" {
			return errors.New("harbor-mgmt requires CLOUD_SERVICE_AUTH_PUBLIC_KEY when CLOUD_INTEGRATION_ENABLED is set")
		}
		cloudHotProxyToken = os.Getenv("MGMT_HOT_PROXY_TOKEN")
		if cloudHotProxyToken == "" {
			return errors.New("harbor-mgmt requires MGMT_HOT_PROXY_TOKEN when CLOUD_INTEGRATION_ENABLED is set")
		}
		cloudHotInternalURL = os.Getenv("HARBOR_HOT_INTERNAL_URL")
		if err := validateInternalURL("HARBOR_HOT_INTERNAL_URL", cloudHotInternalURL); err != nil {
			return err
		}
	}
	authorizeCompleteURL := os.Getenv("AUTHORIZE_COMPLETE_URL")
	if err := validateProductionURL("AUTHORIZE_COMPLETE_URL", authorizeCompleteURL); err != nil {
		return err
	}
	registrationBaseURL := os.Getenv("REGISTRATION_BASE_URL")
	if err := validateProductionURL("REGISTRATION_BASE_URL", registrationBaseURL); err != nil {
		return err
	}
	rpID := os.Getenv("WEBAUTHN_RP_ID")
	if err := validateProductionHost("WEBAUTHN_RP_ID", rpID); err != nil {
		return err
	}
	rpOrigins := splitAndTrim(os.Getenv("WEBAUTHN_RP_ORIGINS"))
	if err := validateProductionOrigins(rpOrigins, rpID); err != nil {
		return err
	}
	pool, err := clients.ConnectDB(ctx, logger)
	if err != nil {
		return fmt.Errorf("connect database: %w", err)
	}
	if pool == nil {
		return errors.New("production requires DATABASE_URL")
	}
	defer pool.Close()

	redisClient, err := clients.ConnectRedis(ctx, logger)
	if err != nil {
		return fmt.Errorf("connect redis: %w", err)
	}
	if redisClient == nil {
		return errors.New("production requires REDIS_URL")
	}
	defer func() {
		if closeErr := redisClient.Close(); closeErr != nil {
			logger.Warn("redis close error", "error", closeErr)
		}
	}()

	// The local provider is the documented crypto-only exception until the HSM
	// signing-key plan supplies an external backend for user-DEK wrapping.
	kp, err := crypto.NewLocalKeyProvider(userDEKKEK)
	if err != nil {
		return fmt.Errorf("configure user-DEK key provider: %w", err)
	}

	q := db.New(pool)
	bffStore := bff.NewRedisBFFSessionStore(redisClient, bffSessionTTL)
	enrollmentSessions := mgmtapi.NewRedisEnrollmentSessionStore(redisClient)
	credentialStore := webauthn.NewDBStore(q).WithPool(pool)
	ceremonySessions := webauthn.NewRedisSessionStore(redisClient, bffSessionTTL)
	webauthnService, err := webauthn.NewService(webauthn.Config{
		RPID: rpID, RPDisplayName: getenv("WEBAUTHN_RP_DISPLAY_NAME", "Harbor"), RPOrigins: rpOrigins,
	}, credentialStore, ceremonySessions)
	if err != nil {
		return fmt.Errorf("configure webauthn: %w", err)
	}

	persister := clients.NewDBUserPersister(q)
	enroller := identity.NewEnroller(kp, crypto.NewCipher(), persister)
	grantStore := clients.NewDBGrantStore(q)
	sessionStore := clients.NewDBSessionStoreWithPool(q, pool)
	registrationStore := clients.NewDBClientRegistrationStore(q)
	recoveryStore := clients.NewDBRecoveryStore(q, q)
	recoveryManager := identity.NewRecoveryManager()
	recoveryService := identity.NewRecoveryService(recoveryStore)
	recoveryCeremonies := mgmtapi.NewRedisRecoveryCeremonyStore(redisClient)
	mfaService, err := mfa.NewService(mfa.ServiceConfig{
		Store: mfa.NewDBStore(q), Cipher: crypto.NewCipher(), Keys: clients.NewDBMFAKeyResolver(q, kp),
	})
	if err != nil {
		return fmt.Errorf("configure MFA: %w", err)
	}
	userLoader := clients.NewDBComplianceUserLoader(q)
	auditRecorder := identity.NewAuditRecorder(userLoader, q, kp, crypto.NewCipher(), logger)
	auditTrailDeps := &mgmtapi.AuditTrailDeps{
		Store:     clients.NewDBAuditStore(q),
		Users:     userLoader,
		Keys:      kp,
		Decryptor: crypto.NewCipher(),
	}
	complianceDeps := &mgmtapi.ComplianceDeps{
		Bundler: identity.NewExportBundler(q, q, q, q, kp, crypto.NewCipher()),
		Eraser:  identity.NewEraser(q, q, auditRecorder, logger),
		Users:   userLoader,
	}
	relayStore := relay.NewStore(q, crypto.NewCipher())
	mtaDomain := getenv("MTA_DOMAIN", "mta.harbor.id")
	relayDomain := os.Getenv("RELAY_DOMAIN")
	if relayDomain == "" {
		return errors.New("harbor-mgmt requires RELAY_DOMAIN")
	}
	byoDomainStore := mgmtapi.NewDBBYODomainStore(q)
	domainVerifier := relay.NewDomainVerifier(relay.NewNetResolver(), mtaDomain, relayDomain)
	dashboardTemplates, err := web.ParseDashboardTemplates()
	if err != nil {
		return fmt.Errorf("parse dashboard templates: %w", err)
	}
	dashboardHandler, err := bff.NewDashboardHandler(
		grantStore,
		sessionStore,
		clients.NewDBDashboardCredentialStore(q),
		auditTrailDeps,
		&dashboardRelayAdapter{store: relayStore},
		dashboardTemplates,
		logger,
	)
	if err != nil {
		return fmt.Errorf("configure dashboard handler: %w", err)
	}
	signupHandler, err := bff.NewSignupHandler(dashboardTemplates, logger)
	if err != nil {
		return fmt.Errorf("configure signup handler: %w", err)
	}

	initialAccessToken := os.Getenv("INITIAL_ACCESS_TOKEN")
	if initialAccessToken == "" {
		return errors.New("production dynamic registration requires INITIAL_ACCESS_TOKEN")
	}
	mgmtServer, err := mgmtapi.New(enroller, enrollmentSessions, registrationStore, registrationBaseURL, logger)
	if err != nil {
		return fmt.Errorf("configure management API: %w", err)
	}
	// Shared by both PostRecoveryComplete (lost-device recovery) and the
	// post-registration handoff below (first-time signup): the two entry
	// points into the exact same enrollment-only BFF session type.
	enrollmentSessionIssuer := &recoverySessionIssuer{bffSessions: bffStore, enrollmentSessions: enrollmentSessions}
	mgmtServer.
		WithCallerSource(bffCallerAdapter{}).
		WithConsentStore(grantStore).
		WithSessionRevoker(sessionStore).
		WithConsentAuditLog(auditRecorder).
		WithInitialAccessToken(initialAccessToken).
		RequireRegistrationAuthorization().
		WithRecovery(recoveryManager, recoveryStore, recoveryService, recoveryCeremonies).
		WithScopedSessionIssuer(enrollmentSessionIssuer).
		WithRecoveryRequirementClearer(recoveryRequirementClearer{store: credentialStore}).
		WithRecoverySessionRefresher(bffSessionScopeRefresher{bffSessions: bffStore}).
		WithEnrollmentCallerSource(bffEnrollmentCallerAdapter{}).
		WithMFA(mfaService).
		WithMFASessionStamper(bffMFASessionStamper{store: bffStore}).
		WithCompliance(complianceDeps).
		WithAuditTrail(auditTrailDeps).
		WithRelayStore(relayStore).
		WithBYODomainStore(byoDomainStore, domainVerifier, mtaDomain, relayDomain).
		WithRelayDomain(relayDomain)
	mfaAbuseProtection := newMgmtLimiter(redisClient, "mfa", 30, time.Minute, logger)
	recoveryAbuseProtection := newMgmtLimiter(redisClient, "recovery", 20, time.Minute, logger)
	enrollmentAbuseProtection := newMgmtLimiter(redisClient, "enroll", 10, time.Minute, logger)
	registrationAbuseProtection := newMgmtLimiter(redisClient, "register", 10, time.Minute, logger)
	mgmtServer.WithProductionAbuseProtection(mfaAbuseProtection.endpoint, mfaAbuseProtection.limiter)
	mgmtServer.WithProductionAbuseProtection(recoveryAbuseProtection.endpoint, recoveryAbuseProtection.limiter)
	mgmtServer.WithProductionAbuseProtection(enrollmentAbuseProtection.endpoint, enrollmentAbuseProtection.limiter)
	mgmtServer.WithProductionAbuseProtection(registrationAbuseProtection.endpoint, registrationAbuseProtection.limiter)
	// The WebAuthn ceremony endpoints sit directly behind the public signup/
	// signin surface and, unlike /enroll, /register, /mfa/* and /recovery/*,
	// have never had rate-limit coverage. webauthn.Handler is a separate,
	// Server-less package (no abuseGate seam), so each route is wrapped
	// individually below instead of going through WithProductionAbuseProtection.
	webauthnRegisterBeginAbuseProtection := newMgmtLimiter(redisClient, "webauthn_register_begin", 20, time.Minute, logger)
	webauthnRegisterFinishAbuseProtection := newMgmtLimiter(redisClient, "webauthn_register_finish", 20, time.Minute, logger)
	webauthnLoginBeginAbuseProtection := newMgmtLimiter(redisClient, "webauthn_login_begin", 30, time.Minute, logger)
	webauthnLoginFinishAbuseProtection := newMgmtLimiter(redisClient, "webauthn_login_finish", 30, time.Minute, logger)

	mux := httpserver.NewHealthMux()
	webauthnHandler, err := webauthn.NewHandler(webauthnService, enrollmentSessions)
	if err != nil {
		return fmt.Errorf("configure WebAuthn handler: %w", err)
	}
	mux.Handle("POST /webauthn/register/begin", wrapPreSessionRoute(webauthnHandler.BeginRegistration, webauthnRegisterBeginAbuseProtection.limiter, maxWebauthnCeremonyBody))
	// Post-registration handoff wraps the FULL existing CSRF+ratelimit+ceremony
	// chain so a first successful passkey registration immediately lands the
	// new user in the same enrollment-only BFF session type PostRecoveryComplete
	// produces (see wirePostRegistrationHandoff, caller.go).
	mux.Handle("POST /webauthn/register/finish", wirePostRegistrationHandoff(
		wrapPreSessionRoute(webauthnHandler.FinishRegistration, webauthnRegisterFinishAbuseProtection.limiter, maxWebauthnCeremonyBody),
		enrollmentSessions, enrollmentSessionIssuer, logger,
	))
	mux.Handle("POST /webauthn/login/begin", wrapPreSessionRoute(webauthnHandler.BeginLogin, webauthnLoginBeginAbuseProtection.limiter, maxWebauthnCeremonyBody))
	mux.Handle("POST /webauthn/login/finish", wrapPreSessionRoute(webauthnHandler.FinishLogin, webauthnLoginFinishAbuseProtection.limiter, maxWebauthnCeremonyBody))
	mgmtServer.Routes(mux)
	dashboardHandler.Routes(mux)
	if cloudIntegrationEnabled {
		cloudVerifier, err := cloudapi.NewServiceAuthVerifier(cloudapi.ServiceAuthVerifierConfig{
			PublicKeyPEM: cloudServiceAuthPublicKey,
			ReplayGuard:  cloudapi.NewRedisReplayGuard(redisClient),
			Logger:       telemetry.New(logger),
		})
		if err != nil {
			return fmt.Errorf("configure cloud service auth verifier: %w", err)
		}
		cloudStore := cloudapi.NewStore(q)
		cloudKeysHandler := cloudapi.NewKeysHandler(cloudVerifier, cloudHotInternalURL, cloudHotProxyToken, nil)
		registerCloudAPIRoutes(mux, cloudVerifier, cloudStore, cloudKeysHandler, newCloudAPILimiters(redisClient, logger))
	}
	signupHandler.Routes(mux)
	loginHandler := bff.NewLoginHandler(bffStore, newBFFWebAuthnAdapter(webauthnService), bff.DiscoverableUserResolver{}, authorizeCompleteURL)
	mux.HandleFunc("GET /login", loginHandler.BeginLogin)
	mux.HandleFunc("POST /login/complete", loginHandler.FinishLogin)
	signinHandler, err := bff.NewSigninHandler(bffStore, dashboardTemplates, bffSessionTTL, splitAndTrim(os.Getenv("RETURN_TO_ALLOWLIST")), logger)
	if err != nil {
		return fmt.Errorf("configure signin handler: %w", err)
	}
	mux.HandleFunc("GET /signin", signinHandler.ServeSignin)
	handler := bff.Middleware(bffStore)(requireSensitiveManagementStepUp(bff.NewStepUpGate(bffStore, bff.DefaultStepUpTTL), mux))
	regionName := os.Getenv("REGION")
	if regionName == "" {
		return errors.New("harbor-mgmt requires REGION")
	}
	reg, err := region.Parse(regionName)
	if err != nil {
		return fmt.Errorf("invalid REGION: %w", err)
	}
	if err := region.BindIssuerHost(rpOrigins[0], reg); err != nil {
		return fmt.Errorf("bind WebAuthn origin to REGION: %w", err)
	}
	if _, err := region.Resolve(rpOrigins[0]); err != nil {
		return fmt.Errorf("resolve WebAuthn origin region: %w", err)
	}
	handler = mgmtapi.RegionMiddleware(telemetry.New(logger))(handler)
	if observe, _ := ctx.Value(mgmtGraphObserverKey{}).(func(mgmtGraph)); observe != nil {
		observe(mgmtGraph{implementations: map[string]string{
			"bff_sessions":        fmt.Sprintf("%T", bffStore),
			"enrollment_sessions": fmt.Sprintf("%T", enrollmentSessions),
			"credentials":         fmt.Sprintf("%T", credentialStore),
			"ceremony_sessions":   fmt.Sprintf("%T", ceremonySessions),
			"users":               fmt.Sprintf("%T", persister),
			"grants":              fmt.Sprintf("%T", grantStore),
			"sessions":            fmt.Sprintf("%T", sessionStore),
			"registration":        fmt.Sprintf("%T", registrationStore),
			"byo_domains":         fmt.Sprintf("%T", byoDomainStore),
		}})
	}
	return httpserver.Run(ctx, ":"+getenv("PORT", "8081"), handler, logger)
}

type mgmtGraph struct {
	implementations map[string]string
}

type mgmtGraphObserverKey struct{}

// runWithGraphObserver invokes the unchanged production composition root with
// a read-only integration-test observation point. The observer cannot replace
// dependencies or alter the served handler.
func runWithGraphObserver(ctx context.Context, logger *slog.Logger, observe func(mgmtGraph)) error {
	return run(context.WithValue(ctx, mgmtGraphObserverKey{}, observe), logger)
}

// dashboardRelayAdapter bridges *relay.Store (which returns raw encrypted
// addresses with mappings) to bff.DashboardRelayStore (which returns plain
// DashboardRelayAddress summaries). The dashboard only needs relay metadata
// (token, clientID, state, region) -- the encrypted email mapping is never
// exposed to the UI (INVARIANT §2).
type dashboardRelayAdapter struct {
	store *relay.Store
}

func (a *dashboardRelayAdapter) ListByUser(ctx context.Context, userID string) ([]bff.DashboardRelayAddress, error) {
	addresses, _, err := a.store.ListByUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]bff.DashboardRelayAddress, len(addresses))
	for i, addr := range addresses {
		out[i] = bff.DashboardRelayAddress{
			ID:       addr.ID.String(),
			Token:    addr.Token,
			ClientID: addr.ClientID,
			State:    string(addr.State),
			Region:   string(addr.Region),
		}
	}
	return out, nil
}

func (a *dashboardRelayAdapter) Deactivate(ctx context.Context, addressID string) error {
	return a.store.Deactivate(ctx, addressID)
}

// --- env helpers ------------------------------------------------------------

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// splitAndTrim splits a comma-separated list and drops empty/whitespace entries.
func splitAndTrim(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func envBool(key string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

type mgmtAbuseProtection struct {
	endpoint string
	limiter  clients.RateLimiter
}

func newMgmtLimiter(client *redis.Client, endpoint string, limit int, window time.Duration, logger *slog.Logger) mgmtAbuseProtection {
	return mgmtAbuseProtection{
		endpoint: endpoint,
		limiter: clients.NewRedisRateLimiter(client, clients.RateLimiterConfig{
			KeyPrefix: "ratelimit:mgmt:" + endpoint + ":",
			Limit:     limit,
			Window:    window,
		}, logger),
	}
}

// maxWebauthnCeremonyBody bounds the request body of every WebAuthn ceremony
// route the same way maxEnrollBody bounds POST /enroll (docs/DESIGN.md §6.5).
// The begin endpoints read no body at all; the finish endpoints decode an
// attestation/assertion response, which comfortably fits well under this cap.
const maxWebauthnCeremonyBody = 16 * 1024

// wrapPreSessionRoute applies the shared pre-session Origin/CSRF check
// (bff.PreSessionCSRF), a per-route abuse limiter, and a bounded body to a
// WebAuthn ceremony route. These routes run before the enrollment-session
// cookie authenticates anything and, unlike the mgmtapi Server routes, have no
// abuseGate seam of their own, so all three defenses are composed here at the
// routing layer instead.
func wrapPreSessionRoute(next http.HandlerFunc, limiter clients.RateLimiter, maxBody int64) http.Handler {
	bounded := func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxBody)
		allowed, retryAfter, err := limiter.Allow(r.Context(), remoteAddrKey(r))
		if err != nil || !allowed {
			if retryAfter > 0 {
				w.Header().Set("Retry-After", fmt.Sprintf("%d", int(retryAfter.Seconds())))
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":"rate_limited","message":"too many requests"}`))
			return
		}
		next(w, r)
	}
	return bff.PreSessionCSRF(http.HandlerFunc(bounded))
}

// remoteAddrKey derives a rate-limit key from the caller's IP without storing
// the IP itself in Redis (docs/DESIGN.md §6.5 — no PII at rest).
func remoteAddrKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || host == "" {
		host = r.RemoteAddr
	}
	digest := sha256.Sum256([]byte(host))
	return hex.EncodeToString(digest[:])
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

// validateInternalURL checks that raw is an absolute http(s) URL with no
// embedded credentials. Unlike validateProductionURL it permits plain HTTP to
// a non-loopback host — HARBOR_HOT_INTERNAL_URL points at another pod's
// cluster-internal Service DNS name (e.g.
// "http://harbor-hot.harbor.svc.cluster.local:8080"), reached over a network
// where transport encryption is provided by the service mesh (Linkerd mTLS),
// not the URL scheme.
func validateInternalURL(name, raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid %s: %w", name, err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return fmt.Errorf("invalid %s: requires an absolute credential-free HTTP(S) URL", name)
	}
	return nil
}

func validateProductionOrigins(origins []string, rpID string) error {
	if len(origins) == 0 {
		return errors.New("production requires WEBAUTHN_RP_ORIGINS")
	}
	for _, origin := range origins {
		if err := validateProductionURL("WEBAUTHN_RP_ORIGINS", origin); err != nil {
			return err
		}
		u, err := url.Parse(origin)
		if err != nil {
			return fmt.Errorf("invalid WEBAUTHN_RP_ORIGINS: %w", err)
		}
		if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
			return fmt.Errorf("invalid WEBAUTHN_RP_ORIGINS: %q is not an origin", origin)
		}
		if u.Hostname() != rpID && !strings.HasSuffix(u.Hostname(), "."+rpID) {
			return fmt.Errorf("invalid WEBAUTHN_RP_ORIGINS: %q is outside WEBAUTHN_RP_ID %q", origin, rpID)
		}
	}
	return nil
}

func validateProductionHost(name, host string) error {
	if host == "localhost" {
		return nil
	}
	if host == "" || strings.ContainsAny(host, "/:@?#") || net.ParseIP(host) != nil || !strings.Contains(host, ".") {
		return fmt.Errorf("invalid %s: production requires a DNS hostname", name)
	}
	if strings.TrimSpace(host) != host {
		return fmt.Errorf("invalid %s: production requires a DNS hostname", name)
	}
	return nil
}
