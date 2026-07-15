// Command harbor-mgmt is Harbor's management / dashboard cold-path binary
// (docs/DESIGN.md §4.2, §8): dashboard/BFF, enrollment, consent, audit, admin.
// It shares the tiny HTTP wiring in internal/httpserver with harbor-hot and,
// unlike the stateless hot path, owns the write-side database connection used
// for real user enrollment (§11.1).
//
// This is the binary skeleton: it loads config from the environment, wires the
// enrollment stack (pgx pool → db.Queries → KEK key provider + cipher →
// identity.Enroller), and exposes GET /healthz. The enrollment HTTP routes are
// layered on in later tasks; a missing dependency must never take down liveness,
// so the binary still answers health checks in the reduced dev-scaffold mode.
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
	"github.com/harbor/harbor/internal/httpserver"
	"github.com/harbor/harbor/internal/identity"
	"github.com/harbor/harbor/internal/mgmtapi"
	"github.com/harbor/harbor/internal/webauthn"
)

// defaultPort is the cold-path listen port (docs/DESIGN.md §4.2); harbor-hot
// owns 8080. Override with PORT.
const defaultPort = "8081"

// config holds the environment-derived settings for harbor-mgmt. DATABASE_URL
// is read inside clients.ConnectDB, so it is intentionally not duplicated here.
type config struct {
	// port is the listen port (PORT, default 8081).
	port string
	// kekSecret is the dev-only KEK secret (HARBOR_KEK_SECRET) used by the
	// software key provider. Enrollment is disabled when it is empty.
	kekSecret string
	// webauthnRPID is the Relying Party ID for passkey ceremonies (WEBAUTHN_RP_ID).
	webauthnRPID string
	// webauthnRPName is the human-facing RP name (WEBAUTHN_RP_NAME).
	webauthnRPName string
	// webauthnOrigin is the allowed origin for ceremonies (WEBAUTHN_ORIGIN).
	webauthnOrigin string
}

// loadConfig reads harbor-mgmt's settings from the environment, applying the
// default port when PORT is unset.
func loadConfig() config {
	port := os.Getenv("PORT")
	if port == "" {
		port = defaultPort
	}
	return config{
		port:           port,
		kekSecret:      os.Getenv("HARBOR_KEK_SECRET"),
		webauthnRPID:   os.Getenv("WEBAUTHN_RP_ID"),
		webauthnRPName: os.Getenv("WEBAUTHN_RP_NAME"),
		webauthnOrigin: os.Getenv("WEBAUTHN_ORIGIN"),
	}
}

func main() {
	// Structured, PII-free logging consistent with docs/DESIGN.md §6.5.
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	// SIGINT/SIGTERM cancels ctx, which httpserver.Run turns into a graceful
	// shutdown.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, loadConfig(), logger); err != nil {
		logger.Error("harbor-mgmt exited with error", "error", err)
		os.Exit(1)
	}
}

// run wires the dependencies and serves until ctx is cancelled. It is separate
// from main so it can return errors (and be exercised by tests) instead of
// calling os.Exit directly.
func run(ctx context.Context, cfg config, logger *slog.Logger) error {
	// Cold-path DB connection (write side): user enrollment persists here.
	// ConnectDB returns (nil, nil) when DATABASE_URL is unset — the dev-scaffold
	// path — so the binary still serves /healthz without a database.
	pool, err := clients.ConnectDB(ctx, logger)
	if err != nil {
		return fmt.Errorf("connect database: %w", err)
	}
	if pool != nil {
		defer pool.Close()
	}

	// Wire the enrollment stack when we have both a database and a KEK secret.
	// Absent either, we run in a reduced dev-scaffold mode that still answers
	// health checks — a missing dependency must never crash liveness.
	enrollerImpl, err := buildEnroller(pool, cfg)
	if err != nil {
		return fmt.Errorf("wire enrollment: %w", err)
	}
	if enrollerImpl != nil {
		logger.Info("enrollment wired (database + KEK present)")
	} else {
		logger.Warn("enrollment unavailable: set DATABASE_URL and HARBOR_KEK_SECRET to enable")
	}

	// Enrollment session store: bridges POST /enroll and the passkey registration
	// ceremony so the user handle comes from a server-side session, not a client-
	// supplied IDOR-prone query param (docs/DESIGN.md §9, §11.1).
	enrollmentSessions := mgmtapi.NewInMemoryEnrollmentSessionStore()

	// Health/liveness mux shared with harbor-hot, plus the cold-path routes
	// (POST /enroll). A nil Enroller (dev-scaffold mode) leaves /enroll wired but
	// returning 503, so a missing DB/KEK never affects liveness. Assigning
	// through the interface var keeps it a true nil (not a typed-nil pointer
	// boxed in a non-nil interface).
	mux := httpserver.NewHealthMux()
	var enroller mgmtapi.Enroller
	if enrollerImpl != nil {
		enroller = enrollerImpl
	}
	mgmtapi.New(enroller, logger).
		WithEnrollmentSessions(enrollmentSessions).
		Routes(mux)

	// WebAuthn passkey registration: wired when RP config is present. The
	// enrollment session store bridges POST /enroll → register/begin/finish so
	// the user handle is read from a secure cookie, not a query param.
	if err := wireWebAuthn(mux, cfg, enrollmentSessions, logger); err != nil {
		logger.Warn("webauthn unavailable", "error", err)
	} else if cfg.webauthnRPID != "" {
		logger.Info("webauthn wired", "rp_id", cfg.webauthnRPID)
	}

	addr := ":" + cfg.port
	return httpserver.Run(ctx, addr, mux, logger)
}

// buildEnroller constructs the identity.Enroller from the DB pool and KEK
// secret, or returns (nil, nil) when either is absent (dev-scaffold mode).
// Isolating the wiring keeps run() readable and the dependency graph explicit:
// pool → db.Queries → DBUserPersister, plus the dev KEK provider and cipher.
func buildEnroller(pool *pgxpool.Pool, cfg config) (*identity.Enroller, error) {
	if pool == nil || cfg.kekSecret == "" {
		return nil, nil
	}

	// NewLocalKeyProvider is DEV-ONLY (software-derived KEK, not HSM-backed) and
	// logs a loud warning on construction — see docs/DESIGN.md §7.3.
	keys, err := crypto.NewLocalKeyProvider(cfg.kekSecret)
	if err != nil {
		return nil, fmt.Errorf("key provider: %w", err)
	}

	queries := db.New(pool)
	persister := clients.NewDBUserPersister(queries)
	return identity.NewEnroller(keys, crypto.NewCipher(), persister), nil
}

// wireWebAuthn registers the passkey ceremony routes on mux when the RP config
// is present. It uses an in-memory credential store (dev-scaffold) and bridges
// the enrollment session store so registration ceremonies read the user handle
// from the enrollment cookie instead of the insecure query param.
func wireWebAuthn(mux *http.ServeMux, cfg config, enrollmentSessions mgmtapi.EnrollmentSessionStore, logger *slog.Logger) error {
	if cfg.webauthnRPID == "" {
		return fmt.Errorf("WEBAUTHN_RP_ID not set")
	}
	waCfg := webauthn.Config{
		RPID:          cfg.webauthnRPID,
		RPDisplayName: cfg.webauthnRPName,
		RPOrigins:     []string{cfg.webauthnOrigin},
	}
	// In-memory stores for dev-scaffold; production will wire DB-backed stores.
	credStore := webauthn.NewInMemoryStore()
	sessionStore := webauthn.NewInMemorySessionStore()
	svc, err := webauthn.NewService(waCfg, credStore, sessionStore)
	if err != nil {
		return fmt.Errorf("webauthn service: %w", err)
	}
	// allowInsecureUserID=false: the production default refuses the IDOR path.
	// The enrollment session store provides the secure alternative.
	handler := webauthn.NewHandler(svc, false).
		WithEnrollmentSessions(enrollmentSessions)
	mux.HandleFunc("POST /webauthn/register/begin", handler.BeginRegistration)
	mux.HandleFunc("POST /webauthn/register/finish", handler.FinishRegistration)
	mux.HandleFunc("POST /webauthn/login/begin", handler.BeginLogin)
	mux.HandleFunc("POST /webauthn/login/finish", handler.FinishLogin)
	return nil
}
