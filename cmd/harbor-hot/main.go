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
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/harbor/harbor/internal/clients"
	"github.com/harbor/harbor/internal/crypto"
	"github.com/harbor/harbor/internal/gen/db"
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
		os.Exit(1) // pool is not yet created at this point — no pool.Close() needed
	}

	pool, err := clients.ConnectDB(ctx, logger)
	if err != nil {
		if ctx.Err() != nil {
			// SIGINT/SIGTERM arrived during startup (before the server bound).
			// This is a clean shutdown, not a crash — exit 0 so process managers
			// (systemd, k8s) don't restart the process.
			logger.Info("startup cancelled by signal — exiting cleanly", "error", err)
			stop()
			os.Exit(0)
		}
		logger.Error("database connection failed", "error", err)
		stop()
		os.Exit(1)
	}
	if pool != nil {
		// defer pool.Close() handles the clean-exit path: main() returns normally
		// after httpserver.Run returns nil and deferred functions run as usual.
		// Every os.Exit() path below calls pool.Close() explicitly because
		// os.Exit skips deferred functions.
		defer pool.Close()
	}

	// Connect to Redis for auth code storage (docs/DESIGN.md §4.4).
	// Returns (nil, nil) when REDIS_URL is unset — falls back to in-memory.
	redisClient, err := clients.ConnectRedis(ctx, logger)
	if err != nil {
		if ctx.Err() != nil {
			logger.Info("startup cancelled by signal — exiting cleanly", "error", err)
			stop()
			if pool != nil {
				pool.Close()
			}
			os.Exit(0)
		}
		logger.Error("redis connection failed", "error", err)
		stop()
		if pool != nil {
			pool.Close()
		}
		os.Exit(1)
	}
	if redisClient != nil {
		defer func() { _ = redisClient.Close() }() //nolint:errcheck // shutdown cleanup
	}

	// Auth code store: Redis-backed if available, otherwise in-memory fallback.
	var authCodeStore oidc.AuthCodeStore
	if redisClient != nil {
		authCodeStore = clients.NewRedisAuthCodeStore(redisClient, 60*time.Second)
		logger.Info("using Redis-backed auth code store")
	} else {
		authCodeStore = oidc.NewInMemoryAuthCodeStore()
		logger.Warn("REDIS_URL not set — using in-memory auth code store (not suitable for multi-replica deployment)")
	}

	// SCAFFOLD: FixedAuthSource is a placeholder for real BFF-session-backed auth
	// (docs/DESIGN.md §11.1). It hardcodes a single demo user — NOT for
	// production — and is used in both the DB and in-memory paths until real
	// session validation lands.
	const demoUserID = "00000000-0000-0000-0000-000000000001"

	var (
		clientRegistry   oidc.ClientRegistry
		grantStore       oidc.GrantStore
		sessionStore     oidc.SessionStore
		secretLoader     oidc.UserSecretLoader
		revocationOutbox oidc.RevocationOutbox
		revocationWorker *oidc.RevocationWorker
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
			// stop() cancels the signal context so any goroutines blocked on
			// ctx.Done() receive the shutdown signal before pool.Close() drains the
			// connection pool. This is the inverse of LIFO defer order (pool.Close
			// first, then stop) but is safe: pgxpool handles a pre-cancelled context
			// gracefully.
			stop()
			if redisClient != nil {
				_ = redisClient.Close() //nolint:errcheck // shutdown cleanup
			}
			pool.Close()
			os.Exit(1)
		}
		keyProvider, err := crypto.NewLocalKeyProvider(kekSecret)
		if err != nil {
			logger.Error("failed to create key provider", "error", err)
			// os.Exit skips deferred functions, so release resources explicitly.
			stop()
			if redisClient != nil {
				_ = redisClient.Close() //nolint:errcheck // shutdown cleanup
			}
			pool.Close()
			os.Exit(1)
		}
		clientRegistry = clients.NewDBClientRegistry(q).WithLogger(logger)
		grantStore = clients.NewDBGrantStore(q)
		sessionStore = clients.NewDBSessionStoreWithPool(q, pool)
		secretLoader = clients.NewDBSecretLoader(q, keyProvider, crypto.NewCipher())

		// Revocation outbox for durable theft-signal delivery
		// (docs/plans/revocation-outbox.md, DESIGN §3.5). Only wired in the DB path;
		// the in-memory dev scaffold uses the noop outbox (inline-only revocation).
		dbOutbox := clients.NewDBRevocationOutbox(q, logger)
		revocationOutbox = dbOutbox

		// RevocationWorker polls the outbox and delivers pending revocation signals.
		// It is started in a background goroutine below and shuts down gracefully
		// when ctx is cancelled (SIGINT/SIGTERM).
		revocationWorker = oidc.NewRevocationWorker(oidc.RevocationWorkerConfig{
			Outbox:       dbOutbox,
			SessionStore: sessionStore,
			Logger:       logger,
		})

		logger.Info("using DB-backed stores")
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
		logger.Warn("SCAFFOLD: FixedAuthSource wired — /authorize always authenticates as the hardcoded demo user; NOT for deployment (docs/DESIGN.md §11.1)")
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
		// revocationOutbox stays nil → NewService defaults to noopRevocationOutbox
		// (inline-only revocation; no durable delivery in dev mode).
	}

	svc := oidc.NewService(oidc.ServiceConfig{
		Issuer:  issuer,
		Logger:  logger,
		Clients: clientRegistry,
		Codes:   authCodeStore,
		Tokens:  oidc.NewJWTIssuer(oidc.JWTIssuerConfig{Signer: signer}),
		Sessions: oidc.NewPPIDSessionResolver(oidc.PPIDSessionResolverConfig{
			Auth:   oidc.NewFixedAuthSource(demoUserID),
			Loader: secretLoader,
			Grants: grantStore,
		}),
		Grants:       grantStore,
		SessionStore: sessionStore,
		Outbox:       revocationOutbox, // durable theft-signal delivery (nil → noop in dev mode)
	})

	// Start the revocation worker if the DB-backed outbox is available. The
	// worker runs in a background goroutine and shuts down gracefully when ctx is
	// cancelled (SIGINT/SIGTERM) — Run() blocks on ctx.Done() and returns. No
	// explicit join is needed: the worker's only side effects are DB writes, and
	// ctx cancellation propagates to any in-flight DeliverPending before
	// pool.Close() drains the pool.
	if revocationWorker != nil {
		go revocationWorker.Run(ctx)
	}

	srv := oidcapi.New(oidcapi.Config{
		Issuer:  issuer,
		Service: svc,
		Signers: []crypto.Signer{signer},
	})
	handler := openapi.HandlerFromMux(srv, http.NewServeMux())

	logger.Info("starting harbor-hot", "port", port, "issuer", issuer)
	if err := httpserver.Run(ctx, ":"+port, handler, logger); err != nil {
		if ctx.Err() != nil {
			// Signal arrived while the server was running — httpserver.Run returned
			// a non-nil error coincident with context cancellation. Treat as a clean
			// shutdown so process managers don't restart the process.
			logger.Info("server stopped by signal — exiting cleanly", "error", err)
			stop()
			if redisClient != nil {
				_ = redisClient.Close() //nolint:errcheck // shutdown cleanup
			}
			if pool != nil {
				pool.Close()
			}
			os.Exit(0)
		}
		logger.Error("harbor-hot exited with error", "error", err)
		// os.Exit skips deferred functions, so release resources explicitly.
		stop()
		if redisClient != nil {
			_ = redisClient.Close() //nolint:errcheck // shutdown cleanup
		}
		if pool != nil {
			pool.Close()
		}
		os.Exit(1)
	}
}
