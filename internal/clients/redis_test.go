package clients

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/alicebob/miniredis/v2"
)

func TestConnectRedis_NoURL(t *testing.T) {
	// Ensure REDIS_URL is unset (t.Setenv restores original after test)
	t.Setenv("REDIS_URL", "")

	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	client, err := ConnectRedis(ctx, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client != nil {
		t.Fatal("expected nil client when REDIS_URL is unset")
	}
}

func TestConnectRedis_InvalidURL(t *testing.T) {
	t.Setenv("REDIS_URL", "not-a-valid-url")

	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	client, err := ConnectRedis(ctx, logger)
	if err == nil {
		t.Fatal("expected error for invalid URL")
	}
	if client != nil {
		t.Fatal("expected nil client on error")
	}
}

func TestConnectRedis_Success(t *testing.T) {
	mr := miniredis.RunT(t)
	t.Setenv("REDIS_URL", "redis://"+mr.Addr())

	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	client, err := ConnectRedis(ctx, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil client")
	}
	defer func() { _ = client.Close() }() //nolint:errcheck // test cleanup

	// Verify the connection works
	if err := client.Ping(ctx).Err(); err != nil {
		t.Fatalf("ping failed: %v", err)
	}
}

func TestConnectRedis_PingFailure(t *testing.T) {
	// Start miniredis, get the address, then close it to simulate connection failure
	mr := miniredis.RunT(t)
	addr := mr.Addr()
	mr.Close()

	t.Setenv("REDIS_URL", "redis://"+addr)

	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	client, err := ConnectRedis(ctx, logger)
	if err == nil {
		t.Fatal("expected error when Redis is unreachable")
	}
	if client != nil {
		t.Fatal("expected nil client on ping failure")
	}
}
