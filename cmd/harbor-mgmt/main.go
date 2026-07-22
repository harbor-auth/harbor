// Command harbor-mgmt is the management / dashboard cold-path binary
// (docs/DESIGN.md §4.1, §8). It serves the dashboard/BFF, enrollment, consent,
// audit and admin surfaces.
//
// Today it exposes the liveness probe, the passkey (WebAuthn) registration and
// assertion ceremonies, and the user-enrollment endpoint (docs/DESIGN.md §11.1).
// The ceremony store and session store are in-memory scaffolds; the sqlc-backed
// stores plug in behind the same interfaces once DATABASE_URL is wired.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/harbor/harbor/internal/bff"
	"github.com/harbor/harbor/internal/clients"
	"github.com/harbor/harbor/internal/crypto"
	"github.com/harbor/harbor/internal/gen/db"
	"github.com/harbor/harbor/internal/httpserver"
	"github.com/harbor/harbor/internal/identity"
	"github.com/harbor/harbor/internal/mgmtapi"
	"github.com/harbor/harbor/internal/region"
	"github.com/harbor/harbor/internal/telemetry"
	"github.com/harbor/harbor/internal/webauthn"
)

// bffSessionTTL is the lifetime of BFF session records (docs/plans/
// bff-session-middleware.md — 5 min, matching the PKCE state lifetime).
const bffSessionTTL = 5 * time.Minute

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// DB-backed stores plug in when DATABASE_URL is configured; otherwise we run
	// on in-memory dev scaffolds (docs/DESIGN.md §10).
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
		defer pool.Close()
	}

	// BFF session store: Redis for multi-replica safety when REDIS_URL is set,
	// otherwise an in-memory dev scaffold (docs/plans/bff-session-middleware.md).
	// A configured-but-unreachable Redis is fatal — mirrors the ConnectDB guard
	// so a prod misconfiguration surfaces at startup rather than silently
	// falling back to a store that isn't shared across replicas.
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
		os.Exit(1) //nolint:gocritic // pool already closed above
	}
	if redisClient != nil {
		defer func() {
			if err := redisClient.Close(); err != nil {
				logger.Warn("redis close error", "error", err)
			}
		}()
	}

	var bffStore bff.BFFSessionStore
	if redisClient != nil {
		bffStore = bff.NewRedisBFFSessionStore(redisClient, bffSessionTTL)
	} else {
		logger.Warn("REDIS_URL not set — using in-memory BFF session store (dev only; not shared across replicas)")
		bffStore = bff.NewInMemoryBFFSessionStore()
	}

	port := getenv("PORT", "8081")

	// Relying Party config (docs/DESIGN.md §3.1). RP ID is the effective domain
	// (no scheme/port); origins are the fully-qualified sites permitted to run
	// ceremonies. Defaults target local dev.
	rpID := getenv("WEBAUTHN_RP_ID", "localhost")
	rpDisplayName := getenv("WEBAUTHN_RP_DISPLAY_NAME", "Harbor")
	rpOrigins := splitAndTrim(getenv("WEBAUTHN_RP_ORIGINS", "http://localhost:"+port))

	// Dev ceremony stores (in-memory). Replace with sqlc-backed implementations
	// once DATABASE_URL is wired (see docs/plans/user-enrollment.md).
	store := webauthn.NewInMemoryStore()
	// WebAuthn session store: Redis for multi-replica safety when REDIS_URL is set,
	// otherwise an in-memory dev scaffold (docs/plans/webauthn-session-store.md).
	var sessions webauthn.SessionStore
	if redisClient != nil {
		sessions = webauthn.NewRedisSessionStore(redisClient, bffSessionTTL)
	} else {
		logger.Warn("REDIS_URL not set — using in-memory WebAuthn session store (dev only; not shared across replicas)")
		sessions = webauthn.NewInMemorySessionStore()
	}

	svc, err := webauthn.NewService(webauthn.Config{
		RPID:          rpID,
		RPDisplayName: rpDisplayName,
		RPOrigins:     rpOrigins,
	}, store, sessions)
	if err != nil {
		logger.Error("failed to configure webauthn service", "error", err)
		// os.Exit skips deferred functions, so release resources explicitly.
		// We call stop() first (cancels the context), then pool.Close() —
		// the opposite of what LIFO defer order would produce (pool first, then
		// stop). pgxpool handles a pre-cancelled context gracefully. pool may be
		// nil when DATABASE_URL is not set.
		stop()
		if pool != nil {
			pool.Close()
		}
		if redisClient != nil {
			if err := redisClient.Close(); err != nil {
				logger.Warn("redis close error on exit", "error", err)
			}
		}
		os.Exit(1)
	}

	// Key provider for enrollment. Production wiring replaces localKeyProvider
	// with an HSM-backed KeyProvider (docs/DESIGN.md §7.3).
	kmsSecret := getenv("HARBOR_KMS_SECRET", "")
	if kmsSecret == "" {
		// When a real DB is wired, enrollment writes user DEKs sealed under this
		// KMS secret. Falling back to a hardcoded dev key against a real DB would
		// let anyone with the source re-derive every enrolled user's pairwise
		// secret, so it is fatal (mirrors the harbor-hot KEK_SECRET guard).
		if pool != nil {
			logger.Error("HARBOR_KMS_SECRET must be set when DATABASE_URL is configured — refusing to enroll with a dev key against a real DB")
			stop()
			pool.Close()
			if redisClient != nil {
				if err := redisClient.Close(); err != nil {
					logger.Warn("redis close error on exit", "error", err)
				}
			}
			os.Exit(1)
		}
		logger.Warn("HARBOR_KMS_SECRET not set — using insecure dev default; NEVER use in production")
		kmsSecret = "harbor-dev-kms-secret-DO-NOT-USE-IN-PROD"
	}
	kp, err := crypto.NewLocalKeyProvider(kmsSecret)
	if err != nil {
		logger.Error("failed to create key provider", "error", err)
		// os.Exit skips deferred functions, so release resources explicitly.
		stop()
		if pool != nil {
			pool.Close()
		}
		if redisClient != nil {
			if err := redisClient.Close(); err != nil {
				logger.Warn("redis close error on exit", "error", err)
			}
		}
		os.Exit(1)
	}

	// PersistUser target: a real sqlc-backed UserPersister when DATABASE_URL is
	// configured, otherwise the no-op scaffold that drops enrollments (dev only;
	// docs/DESIGN.md §10).
	var persister identity.UserPersister
	if pool != nil {
		persister = clients.NewDBUserPersister(db.New(pool))
	} else {
		logger.Warn("DATABASE_URL not set — enrollments will not be persisted (dev mode)")
		persister = &noopUserPersister{logger: logger}
	}
	enroller := identity.NewEnroller(kp, crypto.NewCipher(), persister)
	// Consent store for mgmtapi consent grant endpoints.
	var consentStore mgmtapi.ConsentStore
	var sessionRevoker mgmtapi.SessionRevoker
	if pool != nil {
		q := db.New(pool)
		consentStore = clients.NewDBConsentStore(q)
		sessionRevoker = clients.NewDBSessionStore(q)
	}
	mgmtServer := mgmtapi.New(enroller, logger).WithConsentStore(consentStore).WithSessionRevoker(sessionRevoker)

	mux := httpserver.NewHealthMux()
	// Passkey ceremony endpoints. userIDFromRequest returns 501 until the BFF
	// session middleware lands (docs/DESIGN.md §9) — production-safe default.
	webauthn.RegisterRoutes(mux, svc)
	mgmtServer.Routes(mux)
	mux.HandleFunc("POST /users/enroll", enrollHandler(enroller, logger))

	// BFF login endpoints (docs/plans/bff-session-middleware.md §11.2 step 2).
	// /login initiates the passkey assertion bound to a BFF session; /login/complete
	// finishes it, writes the authenticated user_id to the session, and redirects
	// back to harbor-hot/authorize/complete.
	loginHandler := bff.NewLoginHandler(bffStore, newBFFWebAuthnAdapter(svc), devUserResolver{})
	mux.HandleFunc("GET /login", loginHandler.BeginLogin)
	mux.HandleFunc("POST /login/complete", loginHandler.FinishLogin)

	// Wrap the mux with the BFF middleware so downstream handlers can read the
	// authenticated user from the BFF session context (via bff.UserIDFromContext).
	// The middleware is non-rejecting: it only populates context when a valid
	// authenticated session cookie is present.
	handler := bff.Middleware(bffStore)(mux)

	// Bind this instance's public RP origin host to its REGION (same rationale as
	// harbor-hot): the region middleware fail-closed rejects any Host it cannot
	// resolve, so a single-region/dev deployment MUST declare REGION for its own
	// origin host to resolve. Binding is add-only and conflict-rejecting, and the
	// boot invariant refuses to serve a surface that rejects its own origin.
	if raw := os.Getenv("REGION"); raw != "" {
		// A set REGION with no origin to anchor it to would be silently dropped —
		// exactly the silent-misconfig footgun the rest of this fail-closed design
		// fights. Refuse to boot loudly instead.
		if len(rpOrigins) == 0 {
			logger.Error("REGION set but no WEBAUTHN_RP_ORIGINS to anchor it to — refusing to boot", "region", raw)
			os.Exit(1)
		}
		reg, err := region.Parse(raw)
		if err != nil {
			logger.Error("invalid REGION — refusing to boot", "region", raw, "error", err)
			os.Exit(1)
		}
		if err := region.BindIssuerHost(rpOrigins[0], reg); err != nil {
			logger.Error("failed to bind RP origin host to REGION — refusing to boot", "origin", rpOrigins[0], "region", reg, "error", err)
			os.Exit(1)
		}
	}
	if len(rpOrigins) > 0 {
		if _, err := region.Resolve(rpOrigins[0]); err != nil {
			logger.Error("RP origin host does not resolve to a region — refusing to boot; set REGION for single-region/dev deployments", "origin", rpOrigins[0], "error", err)
			os.Exit(1)
		}
	}

	// Region-pinning middleware is the OUTERMOST layer so EVERY request has a
	// resolved, pinned region on its context before any user-data handler runs
	// (docs/DESIGN.md §5; OpenSpec regional-data-residency-routing REQ-001,
	// REQ-002). Resolution is total and fail-closed: a request whose Host does
	// not map to a known region is rejected here with a defined 400 (and metered
	// PII-free) before it can reach a handler — never defaulted to a region.
	handler = mgmtapi.RegionMiddleware(telemetry.New(logger))(handler)

	logger.Info("starting harbor-mgmt", "port", port, "rp_id", rpID)
	if err := httpserver.Run(ctx, ":"+port, handler, logger); err != nil {
		if ctx.Err() != nil {
			// Signal arrived while the server was running — httpserver.Run returned
			// a non-nil error coincident with context cancellation. Treat as a clean
			// shutdown so process managers don't restart the process.
			logger.Info("server stopped by signal — exiting cleanly", "error", err)
			stop()
			if pool != nil {
				pool.Close()
			}
			if redisClient != nil {
				if err := redisClient.Close(); err != nil {
					logger.Warn("redis close error on exit", "error", err)
				}
			}
			os.Exit(0)
		}
		logger.Error("harbor-mgmt exited with error", "error", err)
		// os.Exit skips deferred functions, so release resources explicitly.
		stop()
		if pool != nil {
			pool.Close()
		}
		if redisClient != nil {
			if err := redisClient.Close(); err != nil {
				logger.Warn("redis close error on exit", "error", err)
			}
		}
		os.Exit(1)
	}
}

// enrollHandler returns a handler for POST /users/enroll. It reads a JSON body
// with a `region` field, calls the Enroller, and returns the new user ID.
func enrollHandler(e *identity.Enroller, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Region string `json:"region"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Region == "" {
			writeErrorJSON(w, http.StatusBadRequest, "invalid_request", "region is required")
			return
		}
		res, err := e.Enroll(r.Context(), req.Region)
		if err != nil {
			if errors.Is(err, region.ErrUnknownRegion) {
				writeErrorJSON(w, http.StatusBadRequest, "invalid_region", "unknown region")
				return
			}
			logger.Error("enrollment failed", "error", err)
			writeErrorJSON(w, http.StatusInternalServerError, "enrollment_failed", "enrollment failed")
			return
		}
		writeJSON(w, http.StatusCreated, res)
	}
}

// noopUserPersister drops enrollments. Replace with a sqlc-backed
// implementation once DATABASE_URL is wired (docs/plans/user-enrollment.md).
type noopUserPersister struct {
	logger *slog.Logger
}

func (p *noopUserPersister) PersistUser(_ context.Context, r identity.UserRecord) error {
	p.logger.Warn("enrollment scaffold: PersistUser is a no-op (DATABASE_URL not wired)",
		"region", r.Region)
	return nil
}

// --- JSON helpers -----------------------------------------------------------

type jsonError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErrorJSON(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, jsonError{Code: code, Message: message})
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
