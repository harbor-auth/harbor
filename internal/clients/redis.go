package clients

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/redis/go-redis/v9"
)

// ConnectRedis creates a Redis client from REDIS_URL. Returns (nil, nil) when
// REDIS_URL is unset — the caller falls back to in-memory dev scaffolds.
// This follows the same contract as ConnectDB: signal-context-aware,
// Ping-validated, and nil-safe for the no-Redis dev path.
func ConnectRedis(ctx context.Context, logger *slog.Logger) (*redis.Client, error) {
	url := os.Getenv("REDIS_URL")
	if url == "" {
		return nil, nil
	}
	opts, err := redis.ParseURL(url)
	if err != nil {
		return nil, fmt.Errorf("redis.ParseURL: %w", err)
	}
	client := redis.NewClient(opts)
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("redis ping: %w", err)
	}
	logger.Info("connected to redis")
	return client, nil
}
