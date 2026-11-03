// Package realredis starts isolated Redis servers for tests of production stores.
package realredis

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// NewClient starts a real Redis process with no TCP listener or persistence.
// Missing Redis is a test failure; the helper never substitutes an emulator.
func NewClient(t testing.TB) *redis.Client {
	t.Helper()
	binary, err := exec.LookPath("redis-server")
	if err != nil {
		t.Fatalf("real Redis required: install redis-server: %v", err)
	}
	// Keep Unix socket paths below macOS's 104-byte limit.
	dir, err := os.MkdirTemp("", "hredis-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Errorf("remove Redis directory: %v", err)
		}
	})
	socket := filepath.Join(dir, "redis.sock")
	log, err := os.Create(filepath.Join(dir, "redis.log"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := log.Close(); err != nil {
			t.Errorf("close Redis log: %v", err)
		}
	})
	cmd := exec.Command(binary, "--port", "0", "--unixsocket", socket,
		"--unixsocketperm", "700", "--save", "", "--appendonly", "no", "--dir", dir)
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Start(); err != nil {
		t.Fatalf("start Redis: %v", err)
	}
	t.Cleanup(func() {
		if err := cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			t.Errorf("stop Redis: %v", err)
		}
		if err := cmd.Wait(); err != nil {
			var exit *exec.ExitError
			// A signal exit is expected after killing our test-owned process.
			if !errors.As(err, &exit) {
				t.Errorf("wait for Redis: %v", err)
			}
		}
	})
	client := redis.NewClient(&redis.Options{Network: "unix", Addr: socket, MaxRetries: -1, DialTimeout: 100 * time.Millisecond})
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("close Redis client: %v", err)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for {
		if client.Ping(ctx).Err() == nil {
			return client
		}
		if ctx.Err() != nil {
			output, readErr := os.ReadFile(log.Name())
			t.Fatalf("Redis did not start: %v (log read: %v)\n%s", ctx.Err(), readErr, output)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
