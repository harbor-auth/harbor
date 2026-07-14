package clients

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ConnectDB creates a pgxpool from DATABASE_URL. Returns (nil, nil) when
// DATABASE_URL is unset — the caller falls back to in-memory dev scaffolds.
// Both cmd/harbor-hot and cmd/harbor-mgmt share this single connection contract:
// signal-context-aware, Ping-validated, and nil-safe for the no-DB dev path.
func ConnectDB(ctx context.Context, logger *slog.Logger) (*pgxpool.Pool, error) {
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
		return nil, fmt.Errorf("db ping: %w", err)
	}
	logger.Info("connected to database")
	return pool, nil
}
