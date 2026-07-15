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
}

// loadConfig reads harbor-mgmt's settings from the environment, applying the
// default port when PORT is unset.
func loadConfig() config {
	port := os.Getenv("PORT")
	if port == "" {
		port = defaultPort
	}
	return config{
		port:      port,
		kekSecret: os.Getenv("HARBOR_KEK_SECRET"),
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
	mgmtapi.New(enroller, logger).Routes(mux)

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
