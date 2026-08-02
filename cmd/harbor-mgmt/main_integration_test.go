//go:build integration

package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"
)

func setValidManagementEnvironment(t *testing.T) {
	t.Helper()
	t.Setenv("HARBOR_KMS_SECRET", "integration-user-dek-kek")
	t.Setenv("AUTHORIZE_COMPLETE_URL", "https://login.integration.harbor.test/complete")
	t.Setenv("REGISTRATION_BASE_URL", "https://mgmt.integration.harbor.test")
	t.Setenv("WEBAUTHN_RP_ID", "mgmt.integration.harbor.test")
	t.Setenv("WEBAUTHN_RP_ORIGINS", "https://mgmt.integration.harbor.test")
	t.Setenv("INITIAL_ACCESS_TOKEN", "integration-initial-access-token")
	t.Setenv("RELAY_DOMAIN", "relay.integration.harbor.test")
	t.Setenv("REGION", "EU")
	t.Setenv("PORT", "0")
}

// TestRunRejectsMissingDatabaseBeforeGraphObservation proves a missing required
// dependency terminates startup before the fully assembled/pre-listen boundary.
func TestRunRejectsMissingDatabaseBeforeGraphObservation(t *testing.T) {
	setValidManagementEnvironment(t)
	t.Setenv("DATABASE_URL", "")
	observed := false
	err := runWithGraphObserver(context.Background(), slog.Default(), func(mgmtGraph) {
		observed = true
	})
	if err == nil || !strings.Contains(err.Error(), "production requires DATABASE_URL") {
		t.Fatalf("run error = %v, want missing DATABASE_URL failure", err)
	}
	if observed {
		t.Fatal("management graph was observed despite a missing required database")
	}
	if errors.Is(err, context.Canceled) {
		t.Fatalf("run reached serving instead of failing startup: %v", err)
	}
}

// TestRunBuildsDurableManagementGraph exercises the same startup path as main
// against the containerised dependencies supplied by the integration environment.
func TestRunBuildsDurableManagementGraph(t *testing.T) {
	for _, name := range []string{"DATABASE_URL", "REDIS_URL"} {
		if strings.TrimSpace(os.Getenv(name)) == "" {
			t.Skipf("%s is not set; start the containerised integration dependencies", name)
		}
	}
	setValidManagementEnvironment(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	observed := make(chan mgmtGraph, 1)
	errCh := make(chan error, 1)
	go func() {
		errCh <- runWithGraphObserver(ctx, logger, func(graph mgmtGraph) {
			observed <- graph
			cancel()
		})
	}()

	var graph mgmtGraph
	select {
	case graph = <-observed:
	case err := <-errCh:
		t.Fatalf("run returned before assembling the live graph: %v", err)
	case <-ctx.Done():
		t.Fatalf("run did not assemble the live graph: %v", ctx.Err())
	}

	want := map[string]string{
		"bff_sessions":        "*bff.RedisBFFSessionStore",
		"enrollment_sessions": "*mgmtapi.RedisEnrollmentSessionStore",
		"credentials":         "*webauthn.DBStore",
		"ceremony_sessions":   "*webauthn.RedisSessionStore",
		"users":               "*clients.DBUserPersister",
		"grants":              "*clients.DBGrantStore",
		"sessions":            "*clients.DBSessionStore",
		"registration":        "*clients.DBClientRegistrationStore",
		"byo_domains":         "*mgmtapi.DBBYODomainStore",
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
