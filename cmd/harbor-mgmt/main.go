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

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/harbor/harbor/internal/clients"
	"github.com/harbor/harbor/internal/crypto"
	"github.com/harbor/harbor/internal/gen/db"
	"github.com/harbor/harbor/internal/httpserver"
	"github.com/harbor/harbor/internal/identity"
	"github.com/harbor/harbor/internal/region"
	"github.com/harbor/harbor/internal/webauthn"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	// DB-backed stores plug in when DATABASE_URL is configured; otherwise we run
	// on in-memory dev scaffolds (docs/DESIGN.md §10).
	pool := connectDB(context.Background(), logger)
	if pool != nil {
		defer pool.Close()
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
	sessions := webauthn.NewInMemorySessionStore()

	svc, err := webauthn.NewService(webauthn.Config{
		RPID:          rpID,
		RPDisplayName: rpDisplayName,
		RPOrigins:     rpOrigins,
	}, store, sessions)
	if err != nil {
		logger.Error("failed to configure webauthn service", "error", err)
		os.Exit(1)
	}

	// Key provider for enrollment. Production wiring replaces localKeyProvider
	// with an HSM-backed KeyProvider (docs/DESIGN.md §7.3).
	kmsSecret := getenv("HARBOR_KMS_SECRET", "")
	if kmsSecret == "" {
		logger.Warn("HARBOR_KMS_SECRET not set — using insecure dev default; NEVER use in production")
		kmsSecret = "harbor-dev-kms-secret-DO-NOT-USE-IN-PROD"
	}
	kp, err := crypto.NewLocalKeyProvider(kmsSecret)
	if err != nil {
		logger.Error("failed to create key provider", "error", err)
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

	mux := httpserver.NewHealthMux()
	// Passkey ceremony endpoints. userIDFromRequest returns 501 until the BFF
	// session middleware lands (docs/DESIGN.md §9) — production-safe default.
	webauthn.RegisterRoutes(mux, svc, false)
	mux.HandleFunc("POST /users/enroll", enrollHandler(enroller, logger))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	logger.Info("starting harbor-mgmt", "port", port, "rp_id", rpID)
	if err := httpserver.Run(ctx, ":"+port, mux, logger); err != nil {
		logger.Error("harbor-mgmt exited with error", "error", err)
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

// connectDB opens a pgx connection pool from DATABASE_URL. It returns nil when
// DATABASE_URL is unset (dev mode: in-memory scaffolds). A configured-but-
// unreachable database is fatal — fail fast rather than silently dropping data.
func connectDB(ctx context.Context, logger *slog.Logger) *pgxpool.Pool {
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		return nil
	}
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		logger.Error("failed to connect to database", "error", err)
		os.Exit(1)
	}
	if err := pool.Ping(ctx); err != nil {
		logger.Error("database ping failed", "error", err)
		os.Exit(1)
	}
	logger.Info("connected to database")
	return pool
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
