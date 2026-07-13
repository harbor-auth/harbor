// Command harbor-hot is the stateless OIDC / token-verification hot-path binary
// (docs/DESIGN.md §4.1, §8). It is the internet-facing surface that serves
// /authorize, /token, /jwks, discovery and verify/introspect.
//
// Its routes are served from the spec-generated OpenAPI handlers
// (api/openapi/harbor.yaml → internal/gen/openapi), implemented in
// internal/oidcapi. Today that is /healthz, the OIDC discovery document, and the
// Authorization Code + PKCE flow (/authorize + /token).
//
// "Stateless" here means the hot path owns no mutable PII state — it does not run
// enrollment ceremonies and never imports internal/webauthn (see the arch
// fitness test TestHotPathDoesNotImportMgmtPackages). It MAY read from the
// regional DB via internal/clients: when DATABASE_URL is configured, the client
// registry, grant store, session store, and secret loader are DB-backed
// (DESIGN §10). Without DATABASE_URL it falls back to in-memory dev scaffolds so
// the flow stays exercisable before real backends are provisioned.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/harbor/harbor/internal/clients"
	"github.com/harbor/harbor/internal/crypto"
	"github.com/harbor/harbor/internal/gen/db"
	"github.com/harbor/harbor/internal/gen/openapi"
	"github.com/harbor/harbor/internal/httpserver"
	"github.com/harbor/harbor/internal/oidc"
	"github.com/harbor/harbor/internal/oidcapi"
)

// connectDB creates a pgxpool from DATABASE_URL. Returns (nil, nil) when
// DATABASE_URL is unset — the caller falls back to in-memory dev scaffolds.
func connectDB(ctx context.Context, logger *slog.Logger) (*pgxpool.Pool, error) {
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		return nil, nil
	}
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("pgxpool.New: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		if ctx.Err() != nil {
			return nil, fmt.Errorf("db ping: interrupted by shutdown signal during startup: %w", err)
		}
		return nil, fmt.Errorf("db ping: %w", err)
	}
	logger.Info("connected to database")
	return pool, nil
}

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

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// DEV-ONLY signing key. SCAFFOLD: the private key is generated in-process and
	// is NOT backed by the regional HSM (docs/DESIGN.md §7.3). Tokens do not
	// survive a restart. Swap crypto.NewLocalSigner for the HSM-backed signer to
	// go to production.
	signer, err := crypto.NewLocalSigner()
	if err != nil {
		logger.Error("failed to create local signer", "error", err)
		stop()
		os.Exit(1)
	}

	pool, err := connectDB(ctx, logger)
	if err != nil {
		logger.Error("database connection failed", "error", err)
		stop()
		os.Exit(1)
	}
	if pool != nil {
		defer pool.Close()
	}

	// SCAFFOLD: FixedAuthSource is a placeholder for real BFF-session-backed auth
	// (docs/DESIGN.md §11.1). It hardcodes a single demo user — NOT for
	// production — and is used in both the DB and in-memory paths until real
	// session validation lands.
	const demoUserID = "00000000-0000-0000-0000-000000000001"

	var (
		clientRegistry oidc.ClientRegistry
		grantStore     oidc.GrantStore
		sessionStore   oidc.SessionStore
		secretLoader   oidc.UserSecretLoader
	)

	if pool != nil {
		q := db.New(pool)
		// SCAFFOLD: dev-only LocalKeyProvider. Swap for the HSM-backed KeyProvider
		// in production (docs/DESIGN.md §7.3). KEK_SECRET MUST be set when
		// DATABASE_URL is configured so the pairwise-secret DEKs unwrap correctly —
		// falling back to a hardcoded dev key against a real DB would let anyone
		// with the source re-derive every user's pairwise secret, so it is fatal.
		kekSecret := os.Getenv("KEK_SECRET")
		if kekSecret == "" {
			logger.Error("KEK_SECRET must be set when DATABASE_URL is configured")
			// os.Exit skips deferred functions, so release resources explicitly.
			stop()
			pool.Close()
			os.Exit(1)
		}
		keyProvider, err := crypto.NewLocalKeyProvider(kekSecret)
		if err != nil {
			logger.Error("failed to create key provider", "error", err)
			// os.Exit skips deferred functions, so release resources explicitly.
			stop()
			pool.Close()
			os.Exit(1)
		}
		clientRegistry = clients.NewDBClientRegistry(q).WithLogger(logger)
		grantStore = clients.NewDBGrantStore(q)
		sessionStore = clients.NewDBSessionStore(q).WithPool(pool)
		secretLoader = clients.NewDBSecretLoader(q, keyProvider, crypto.NewCipher())
		logger.Info("using DB-backed stores")
		// SCAFFOLD: authorization codes are still stored in-memory (see the
		// oidc.NewInMemoryAuthCodeStore wiring below), so a code issued by one
		// replica cannot be redeemed by another. Warn so this isn't silently
		// deployed multi-replica (docs/DESIGN.md §4.4).
		logger.Warn("authorization codes stored in-memory — not suitable for multi-replica deployment")
		// SCAFFOLD: even in the DB path the subject is still resolved by
		// FixedAuthSource below, so every /authorize authenticates as the SAME
		// hardcoded demo user regardless of who is calling. This must be replaced
		// by real BFF-session-backed auth before any deployment (docs/DESIGN.md §11.1).
		logger.Warn("SCAFFOLD: FixedAuthSource wired in DB path — /authorize always authenticates as the hardcoded demo user; NOT suitable for deployment (docs/DESIGN.md §11.1)")
	} else {
		// SCAFFOLD: in-memory stores for dev/test (DATABASE_URL not set). A demo
		// client + deterministic demo-user secret keep the Authorization Code +
		// PKCE flow exercisable before a regional DB is provisioned.
		logger.Warn("DATABASE_URL not set — using in-memory stores (dev-only SCAFFOLD)")
		inmemClients := oidc.NewInMemoryClientRegistry()
		inmemClients.Put(oidc.Client{
			ID:            "demo-client",
			SectorID:      "localhost", // groups redirect URIs for PPID derivation (§3.2)
			RedirectURIs:  []string{"http://localhost:3000/callback"},
			ScopesAllowed: []string{"openid", "profile", "email", "offline_access"},
		})
		clientRegistry = inmemClients

		demoSecret := make([]byte, 32)
		for i := range demoSecret {
			demoSecret[i] = byte(i + 1)
		}
		inmemLoader := oidc.NewInMemorySecretLoader()
		inmemLoader.Put(demoUserID, oidc.UserSecret{Region: "us", Secret: demoSecret})
		secretLoader = inmemLoader

		grantStore = oidc.NewInMemoryGrantStore()
		sessionStore = oidc.NewInMemorySessionStore()
	}

	svc := oidc.NewService(oidc.ServiceConfig{
		Issuer:  issuer,
		Logger:  logger,
		Clients: clientRegistry,
		Codes:   oidc.NewInMemoryAuthCodeStore(),
		Tokens:  oidc.NewJWTIssuer(oidc.JWTIssuerConfig{Signer: signer}),
		Sessions: oidc.NewPPIDSessionResolver(oidc.PPIDSessionResolverConfig{
			Auth:   oidc.NewFixedAuthSource(demoUserID),
			Loader: secretLoader,
			Grants: grantStore,
		}),
		Grants:       grantStore,
		SessionStore: sessionStore,
	})

	srv := oidcapi.New(oidcapi.Config{
		Issuer:  issuer,
		Service: svc,
		Signers: []crypto.Signer{signer},
	})
	handler := openapi.HandlerFromMux(srv, http.NewServeMux())

	logger.Info("starting harbor-hot", "port", port, "issuer", issuer)
	if err := httpserver.Run(ctx, ":"+port, handler, logger); err != nil {
		logger.Error("harbor-hot exited with error", "error", err)
		// os.Exit skips deferred functions, so release resources explicitly.
		stop()
		if pool != nil {
			pool.Close()
		}
		os.Exit(1)
	}
}
