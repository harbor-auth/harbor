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
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/harbor-auth/harbor/internal/bff"
	"github.com/harbor-auth/harbor/internal/clients"
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

	initialAccessToken := os.Getenv("INITIAL_ACCESS_TOKEN")
	if initialAccessToken == "" {
		return errors.New("production dynamic registration requires INITIAL_ACCESS_TOKEN")
	}
	mgmtServer, err := mgmtapi.New(enroller, enrollmentSessions, registrationStore, registrationBaseURL, logger)
	if err != nil {
		return fmt.Errorf("configure management API: %w", err)
	}
	mgmtServer.
		WithCallerSource(bffCallerAdapter{}).
		WithConsentStore(grantStore).
		WithSessionRevoker(sessionStore).
		WithConsentAuditLog(auditRecorder).
		WithInitialAccessToken(initialAccessToken).
		RequireRegistrationAuthorization().
		WithRecovery(recoveryManager, recoveryStore, recoveryService, recoveryCeremonies).
		WithScopedSessionIssuer(&recoverySessionIssuer{bffSessions: bffStore, enrollmentSessions: enrollmentSessions}).
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

	mux := httpserver.NewHealthMux()
	webauthnHandler, err := webauthn.NewHandler(webauthnService, enrollmentSessions)
	if err != nil {
		return fmt.Errorf("configure WebAuthn handler: %w", err)
	}
	webauthnHandler.RegisterRoutes(mux)
	mgmtServer.Routes(mux)
	dashboardHandler.Routes(mux)
	loginHandler := bff.NewLoginHandler(bffStore, newBFFWebAuthnAdapter(webauthnService), bff.DiscoverableUserResolver{}, authorizeCompleteURL)
	mux.HandleFunc("GET /login", loginHandler.BeginLogin)
	mux.HandleFunc("POST /login/complete", loginHandler.FinishLogin)
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
	return httpserver.Run(ctx, ":"+getenv("PORT", "8081"), handler, logger)
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
	if host == "" || strings.ContainsAny(host, "/:@?#") || net.ParseIP(host) != nil || !strings.Contains(host, ".") {
		return fmt.Errorf("invalid %s: production requires a DNS hostname", name)
	}
	if strings.TrimSpace(host) != host {
		return fmt.Errorf("invalid %s: production requires a DNS hostname", name)
	}
	return nil
}
