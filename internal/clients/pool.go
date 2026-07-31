package clients

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Pool-sizing defaults.
//
// Arithmetic: replicas × maxConns must stay below Postgres max_connections
// (default 100) with headroom for superuser connections and monitoring tools.
// At the HPA ceiling of 20 replicas, 10 × 20 = 200 — use a Postgres
// max_connections of at least 220 in production (allow ~20 for admin/monitoring).
// Adjust DB_MAX_CONNS down if you run more replicas or share the DB with other
// services, or increase max_connections accordingly.
const (
	defaultMaxConns        int32         = 10
	defaultMinConns        int32         = 2
	defaultMaxConnLifetime time.Duration = 30 * time.Minute
)

// ConnectDB creates a pgxpool from DATABASE_URL. Returns (nil, nil) when
// DATABASE_URL is unset — the caller falls back to in-memory dev scaffolds.
// Both cmd/harbor-hot and cmd/harbor-mgmt share this single connection contract:
// signal-context-aware, Ping-validated, and nil-safe for the no-DB dev path.
//
// Pool sizing is controlled by three env vars:
//
//	DB_MAX_CONNS         — maximum open connections per replica (default 10)
//	DB_MIN_CONNS         — minimum idle connections per replica (default 2)
//	DB_MAX_CONN_LIFETIME — maximum connection lifetime (default 30m, e.g. "1h")
func ConnectDB(ctx context.Context, logger *slog.Logger) (*pgxpool.Pool, error) {
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		return nil, nil
	}

	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, fmt.Errorf("pgxpool.ParseConfig: %w", err)
	}

	cfg.MaxConns = envInt32("DB_MAX_CONNS", defaultMaxConns)
	cfg.MinConns = envInt32("DB_MIN_CONNS", defaultMinConns)
	cfg.MaxConnLifetime = envDuration("DB_MAX_CONN_LIFETIME", defaultMaxConnLifetime)

	logger.Info("connecting to database",
		"max_conns", cfg.MaxConns,
		"min_conns", cfg.MinConns,
		"max_conn_lifetime", cfg.MaxConnLifetime,
	)

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("pgxpool.NewWithConfig: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("db ping: %w", err)
	}
	logger.Info("connected to database")
	return pool, nil
}

// envInt32 reads an environment variable as an int32, returning def on parse
// error or when the variable is unset.
func envInt32(key string, def int32) int32 {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.ParseInt(v, 10, 32)
	if err != nil {
		return def
	}
	return int32(n)
}

// envDuration reads an environment variable as a time.Duration, returning def
// on parse error or when the variable is unset.
func envDuration(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def
	}
	return d
}
