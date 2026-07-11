// Command harbor-hot is the stateless OIDC / token-verification hot-path binary
// (docs/DESIGN.md §4.1, §8). It is the internet-facing surface that serves
// /authorize, /token, /jwks, discovery and verify/introspect.
//
// Its routes are served from the spec-generated OpenAPI handlers
// (api/openapi/harbor.yaml → internal/gen/openapi), implemented in
// internal/oidcapi. Today that is /healthz, the OIDC discovery document, and the
// Authorization Code + PKCE flow (/authorize + /token). The flow's client
// registry, code store, token signer, grant store, and login/consent are
// in-memory / stubbed scaffolds for now (see internal/oidc); more endpoints and
// real backends are added by growing the spec and swapping the interface
// implementations. The DB-backed registry + grant store live in internal/clients
// and are wired here when DATABASE_URL is configured (DESIGN §10).
package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/harbor/harbor/internal/crypto"
	"github.com/harbor/harbor/internal/gen/openapi"
	"github.com/harbor/harbor/internal/httpserver"
	"github.com/harbor/harbor/internal/oidc"
	"github.com/harbor/harbor/internal/oidcapi"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Issuer anchors the discovery document (docs/DESIGN.md §3.4). Configurable
	// so each region runs its own issuer; defaults to a local dev URL.
	issuer := os.Getenv("ISSUER")
	if issuer == "" {
		issuer = "http://localhost:" + port
	}

	// Authorization Code + PKCE flow backends. SCAFFOLD: all in-memory / stubbed
	// (docs/DESIGN.md §11.2, §7.3) — a demo client + auto-approving login/consent
	// + unsigned placeholder tokens — so the flow is exercisable before the real
	// registry, HSM signer, and auth UI land. Swap these implementations, not the
	// flow logic, to go to production.
	clients := oidc.NewInMemoryClientRegistry()
	clients.Put(oidc.Client{
		ID:            "demo-client",
		SectorID:      "localhost", // groups redirect URIs for PPID derivation (§3.2)
		RedirectURIs:  []string{"http://localhost:3000/callback"},
		ScopesAllowed: []string{"openid", "profile", "email", "offline_access"},
	})

	// DEV-ONLY signing key. SCAFFOLD: the private key is generated in-process and
	// is NOT backed by the regional HSM (docs/DESIGN.md §7.3). Tokens do not
	// survive a restart. Swap crypto.NewLocalSigner for the HSM-backed signer to
	// go to production.
	signer, err := crypto.NewLocalSigner()
	if err != nil {
		logger.Error("failed to create local signer", "error", err)
		os.Exit(1)
	}

	// Demo user for PPIDSessionResolver. SCAFFOLD: the demo user ID is fixed and
	// the pairwise secret is deterministic — NOT for production. Swap the
	// FixedAuthSource for a real BFF-session-backed AuthSource and the
	// InMemorySecretLoader for clients.NewDBSecretLoader once DATABASE_URL lands.
	demoUserID := "00000000-0000-0000-0000-000000000001"
	demoSecret := make([]byte, 32)
	for i := range demoSecret {
		demoSecret[i] = byte(i + 1)
	}
	secretLoader := oidc.NewInMemorySecretLoader()
	secretLoader.Put(demoUserID, oidc.UserSecret{Region: "us", Secret: demoSecret})

	grantStore := oidc.NewInMemoryGrantStore()

	svc := oidc.NewService(oidc.ServiceConfig{
		Issuer:  issuer,
		Clients: clients,
		Codes:   oidc.NewInMemoryAuthCodeStore(),
		Tokens:  oidc.NewJWTIssuer(oidc.JWTIssuerConfig{Signer: signer}),
		Sessions: oidc.NewPPIDSessionResolver(oidc.PPIDSessionResolverConfig{
			Auth:   oidc.NewFixedAuthSource(demoUserID),
			Loader: secretLoader,
			Grants: grantStore,
		}),
		// SCAFFOLD: in-memory grant store — swap for clients.NewDBGrantStore(db.New(pool))
		// once DATABASE_URL wiring lands (docs/DESIGN.md §10, §11.3).
		Grants: grantStore,
		// SCAFFOLD: in-memory session store — swap for clients.NewDBSessionStore(db.New(pool))
		// once DATABASE_URL wiring lands (docs/DESIGN.md §3.5, §10).
		SessionStore: oidc.NewInMemorySessionStore(),
	})

	srv := oidcapi.New(oidcapi.Config{
		Issuer:  issuer,
		Service: svc,
		Signers: []crypto.Signer{signer},
	})
	handler := openapi.HandlerFromMux(srv, http.NewServeMux())

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	logger.Info("starting harbor-hot", "port", port, "issuer", issuer)
	if err := httpserver.Run(ctx, ":"+port, handler, logger); err != nil {
		logger.Error("harbor-hot exited with error", "error", err)
		os.Exit(1)
	}
}
