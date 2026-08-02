//go:build integration

package main

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"
)

// TestRunBuildsDurableLiveGraph exercises the same startup path as main against
// the containerised dependencies supplied by the integration environment. It
// observes, but cannot replace, the graph immediately before HTTP serving.
func TestRunBuildsDurableLiveGraph(t *testing.T) {
	for _, name := range []string{"DATABASE_URL", "REDIS_URL", "KMS_KEY_MAP", "AWS_ENDPOINT_URL"} {
		if strings.TrimSpace(os.Getenv(name)) == "" {
			t.Skipf("%s is not set; start the containerised integration dependencies", name)
		}
	}
	t.Setenv("HARBOR_KMS_SECRET", "integration-user-dek-kek")
	t.Setenv("ISSUER", "http://127.0.0.1:18080")
	t.Setenv("LOGIN_URL", "http://127.0.0.1:18081/login")
	t.Setenv("ADMIN_API_TOKEN", "integration-admin-token-at-least-32-bytes")
	t.Setenv("ADDR", "127.0.0.1:0")
	t.Setenv("REGION", "EU")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	observed := make(chan hotGraph, 1)
	errCh := make(chan error, 1)
	go func() {
		errCh <- runWithGraphObserver(ctx, logger, func(graph hotGraph) {
			observed <- graph
			cancel()
		})
	}()

	var graph hotGraph
	select {
	case graph = <-observed:
	case err := <-errCh:
		t.Fatalf("run returned before assembling the live graph: %v", err)
	case <-ctx.Done():
		t.Fatalf("run did not assemble the live graph: %v", ctx.Err())
	}

	want := map[string]string{
		"clients":       "*clients.DBClientRegistry",
		"codes":         "*clients.RedisAuthCodeStore",
		"grants":        "*clients.DBGrantStore",
		"consents":      "*clients.DBConsentStore",
		"sessions":      "*clients.DBSessionStore",
		"revocations":   "*clients.DBRevokedJTIStore",
		"outbox":        "*clients.DBRevocationOutbox",
		"secret_loader": "*clients.DBSecretLoader",
		"bff_sessions":  "*bff.RedisBFFSessionStore",
	}
	for seam, concrete := range want {
		if got := graph.implementations[seam]; got != concrete {
			t.Errorf("%s implementation = %q, want %q", seam, got, concrete)
		}
	}

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("run shutdown: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run did not stop after cancellation")
	}
}
