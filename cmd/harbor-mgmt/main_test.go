package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

func productionAssembly(t *testing.T) string {
	t.Helper()
	source, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "main.go", source, 0)
	if err != nil {
		t.Fatalf("parse main.go: %v", err)
	}
	for _, declaration := range file.Decls {
		fn, ok := declaration.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "run" {
			continue
		}
		start := fset.Position(fn.Body.Pos()).Offset
		end := fset.Position(fn.Body.End()).Offset
		return string(source[start:end])
	}
	t.Fatal("startup must be isolated in run so its object graph can be audited")
	return ""
}

// TestProductionLiveGraphRequiresDurableDependencies is a source-level guard
// around the composition root. Unit tests for each store are not sufficient:
// the shipped binary must actually put the durable implementations in its live
// HTTP graph. The assembly is deliberately isolated in run so it can be audited.
func TestProductionLiveGraphRequiresDurableDependencies(t *testing.T) {
	productionAssembly := productionAssembly(t)

	for _, required := range []string{
		"clients.ConnectDB",
		"clients.ConnectRedis",
		"mgmtapi.NewRedisEnrollmentSessionStore",
		"webauthn.NewRedisSessionStore",
		"webauthn.NewDBStore",
		"webauthn.NewHandler(webauthnService, enrollmentSessions)",
		"mgmtapi.New(enroller, enrollmentSessions, registrationStore",
		"clients.NewDBUserPersister",
		"clients.NewDBGrantStore",
		"clients.NewDBSessionStoreWithPool",
		"clients.NewDBClientRegistrationStore",
		"clients.NewDBRecoveryStore",
		"mfa.NewDBStore",
		"clients.NewDBAuditStore",
		"clients.NewDBDashboardCredentialStore",
		"relay.NewStore",
		"WithCompliance",
		"WithAuditTrail",
		"WithRelayStore",
		"dashboardHandler.Routes",
		"WithRecovery",
		"WithScopedSessionIssuer",
		"WithMFA",
		"WithInitialAccessToken",
	} {
		if !strings.Contains(productionAssembly, required) {
			t.Errorf("production harbor-mgmt graph does not wire %q", required)
		}
	}
}

func TestStartupHasOneDurableGraph(t *testing.T) {
	source, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	assembly := string(source)
	for _, forbidden := range []string{"internal/testsupport", "HARBOR_DEV_MODE", "runDevelopment", "RuntimeDevelopment", "noopUserPersister", "bootstrapManagementGraph"} {
		if strings.Contains(assembly, forbidden) {
			t.Errorf("harbor-mgmt still contains development graph marker %q", forbidden)
		}
	}
}

// TestProductionLiveGraphContainsNoScaffolds prevents a future refactor from
// satisfying readiness checks while retaining an insecure fallback in the
// handler that is actually served.
func TestProductionLiveGraphContainsNoScaffolds(t *testing.T) {
	productionAssembly := productionAssembly(t)

	for _, forbidden := range []string{
		"internal/testsupport",
		"HARBOR_DEV_MODE",
		"runDevelopment",
		"bootstrapManagementGraph",
		"noopUserPersister",
		"NewPlaceholderIssuer",
		"NewStubSessionResolver",
		"NewInMemoryBFFSessionStore",
		"NewInMemoryStore",
		"NewInMemorySessionStore",
		"NewInMemoryEnrollmentSessionStore",
		"webauthn.RegisterRoutes",
		`HandleFunc("POST /users/enroll"`,
	} {
		if strings.Contains(productionAssembly, forbidden) {
			t.Errorf("production harbor-mgmt graph still references scaffold or legacy route %q", forbidden)
		}
	}
}

func TestProductionStartupValidatesOriginsHostsAndRegistrationURL(t *testing.T) {
	source, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	assembly := string(source)
	for _, required := range []string{
		"validateProductionURL(\"AUTHORIZE_COMPLETE_URL\"",
		"validateProductionOrigins",
		"validateProductionHost(\"WEBAUTHN_RP_ID\"",
		"validateProductionURL(\"REGISTRATION_BASE_URL\"",
	} {
		if !strings.Contains(assembly, required) {
			t.Errorf("production harbor-mgmt startup does not enforce %q", required)
		}
	}
}

func TestStartupRejectsMissingProductionConfigurationBeforeListen(t *testing.T) {
	startup := productionAssembly(t)
	listen := strings.Index(startup, "httpserver.Run(")
	if listen < 0 {
		t.Fatal("harbor-mgmt startup does not contain the HTTP listen boundary")
	}

	for name, marker := range map[string]string{
		"PostgreSQL":                 `production requires DATABASE_URL`,
		"Redis":                      `production requires REDIS_URL`,
		"authorize completion URL":   `validateProductionURL("AUTHORIZE_COMPLETE_URL"`,
		"registration URL":           `validateProductionURL("REGISTRATION_BASE_URL"`,
		"registration authorization": `production dynamic registration requires INITIAL_ACCESS_TOKEN`,
		"shared user-DEK KEK":        `HARBOR_KMS_SECRET`,
	} {
		check := strings.Index(startup, marker)
		if check < 0 {
			t.Errorf("harbor-mgmt startup does not reject missing %s (want %q)", name, marker)
			continue
		}
		if check > listen {
			t.Errorf("harbor-mgmt checks %s after its HTTP listen boundary", name)
		}
	}
}

func TestValidateProductionURLAllowsOnlyLoopbackHTTP(t *testing.T) {
	for _, raw := range []string{"http://localhost:8081", "http://127.0.0.1:8081", "http://[::1]:8081", "https://mgmt.example.com"} {
		if err := validateProductionURL("URL", raw); err != nil {
			t.Errorf("validateProductionURL(%q) = %v", raw, err)
		}
	}
	for _, raw := range []string{"http://mgmt.example.com", "https://user@mgmt.example.com", "https://mgmt.example.com/#fragment"} {
		if err := validateProductionURL("URL", raw); err == nil {
			t.Errorf("validateProductionURL(%q) accepted an insecure URL", raw)
		}
	}
}

func TestValidateProductionHostAllowsWebAuthnLocalhostOnly(t *testing.T) {
	for _, host := range []string{"localhost", "login.harbor.example.com"} {
		if err := validateProductionHost("WEBAUTHN_RP_ID", host); err != nil {
			t.Errorf("validateProductionHost(%q) = %v", host, err)
		}
	}
	for _, host := range []string{"local", "127.0.0.1", "bad/host"} {
		if err := validateProductionHost("WEBAUTHN_RP_ID", host); err == nil {
			t.Errorf("validateProductionHost(%q) accepted invalid host", host)
		}
	}
}

// TestCloudIntegrationGateRequiresItsConfigBeforeListen mirrors
// TestStartupRejectsMissingProductionConfigurationBeforeListen for the three
// cloudapi env vars: these are conditionally required (only when
// CLOUD_INTEGRATION_ENABLED is set), so they live outside the always-required
// map above, but the same "checked before the HTTP listen boundary" contract
// applies.
func TestCloudIntegrationGateRequiresItsConfigBeforeListen(t *testing.T) {
	startup := productionAssembly(t)
	listen := strings.Index(startup, "httpserver.Run(")
	if listen < 0 {
		t.Fatal("harbor-mgmt startup does not contain the HTTP listen boundary")
	}

	for name, marker := range map[string]string{
		"trust-anchor public key": `requires CLOUD_SERVICE_AUTH_PUBLIC_KEY when CLOUD_INTEGRATION_ENABLED is set`,
		"hot proxy token":         `requires MGMT_HOT_PROXY_TOKEN when CLOUD_INTEGRATION_ENABLED is set`,
		"hot internal URL":        `validateInternalURL("HARBOR_HOT_INTERNAL_URL"`,
	} {
		check := strings.Index(startup, marker)
		if check < 0 {
			t.Errorf("harbor-mgmt startup does not reject missing %s (want %q)", name, marker)
			continue
		}
		if check > listen {
			t.Errorf("harbor-mgmt checks %s after its HTTP listen boundary", name)
		}
	}
}

// TestProductionGraphWiresCloudAPIRoutesBehindGate is the same source-level
// guard as TestProductionLiveGraphRequiresDurableDependencies, scoped to the
// cloudapi wiring: the gate variable must guard route registration, and
// registration must use the durable Redis/DB-backed dependencies already in
// the graph — never a standalone/in-memory substitute.
func TestProductionGraphWiresCloudAPIRoutesBehindGate(t *testing.T) {
	assembly := productionAssembly(t)

	if !strings.Contains(assembly, "if cloudIntegrationEnabled {") {
		t.Error("production harbor-mgmt graph does not gate cloudapi route registration on cloudIntegrationEnabled")
	}
	for _, required := range []string{
		"cloudapi.NewServiceAuthVerifier(",
		"cloudapi.NewRedisReplayGuard(redisClient)",
		"cloudapi.NewStore(q)",
		"cloudapi.NewKeysHandler(",
		"registerCloudAPIRoutes(mux,",
	} {
		if !strings.Contains(assembly, required) {
			t.Errorf("production harbor-mgmt graph does not wire %q", required)
		}
	}
}

func TestProductionGraphWiresOutageAwareAbuseProtection(t *testing.T) {
	source, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	assembly := string(source)
	for _, endpoint := range []string{"mfa", "recovery", "enrollment", "registration"} {
		marker := "WithProductionAbuseProtection(" + endpoint
		if !strings.Contains(assembly, marker) {
			t.Errorf("production graph lacks outage-aware abuse protection for %s endpoints (want %q)", endpoint, marker)
		}
	}
}

// TestProductionGraphWiresWebauthnCeremonyProtections is a source-level guard
// proving the four WebAuthn ceremony routes — previously uncovered by any
// rate limit — are each routed through wrapPreSessionRoute (Origin/CSRF check
// + abuse limiter + bounded body), not through the bare handler.
func TestProductionGraphWiresWebauthnCeremonyProtections(t *testing.T) {
	productionAssembly := productionAssembly(t)

	for _, required := range []string{
		"wrapPreSessionRoute(webauthnHandler.BeginRegistration",
		"wrapPreSessionRoute(webauthnHandler.FinishRegistration",
		"wrapPreSessionRoute(webauthnHandler.BeginLogin",
		"wrapPreSessionRoute(webauthnHandler.FinishLogin",
	} {
		if !strings.Contains(productionAssembly, required) {
			t.Errorf("production graph does not wire %q", required)
		}
	}
}
