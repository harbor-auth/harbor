// Command harbor-mgmt is the management / dashboard cold-path binary
// (docs/DESIGN.md §4.1, §8). It serves the dashboard/BFF, enrollment, consent,
// audit and admin surfaces.
//
// Today it exposes the liveness probe plus the passkey (WebAuthn) registration
// and assertion ceremonies (docs/DESIGN.md §3.1), served from internal/webauthn.
// The credential and ceremony-session stores are in-memory for now; the
// sqlc-backed stores (db/queries) plug in behind the same interfaces later.
package main

import (
	"context"
	"encoding/base64"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/harbor/harbor/internal/httpserver"
	"github.com/harbor/harbor/internal/webauthn"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	port := getenv("PORT", "8081")

	// Relying Party config (docs/DESIGN.md §3.1). RP ID is the effective domain
	// (no scheme/port); origins are the fully-qualified sites permitted to run
	// ceremonies. Defaults target local dev.
	rpID := getenv("WEBAUTHN_RP_ID", "localhost")
	rpDisplayName := getenv("WEBAUTHN_RP_DISPLAY_NAME", "Harbor")
	rpOrigins := splitAndTrim(getenv("WEBAUTHN_RP_ORIGINS", "http://localhost:"+port))

	// WEBAUTHN_ALLOW_INSECURE_USER_ID enables the DEV-ONLY path where the user
	// handle is read from a client-supplied `user_id` query param. It MUST stay
	// false in production — otherwise any caller can drive ceremonies as any user
	// (docs/DESIGN.md §9). Defaults to false; a parse error is treated as false.
	allowInsecureUserID, _ := strconv.ParseBool(getenv("WEBAUTHN_ALLOW_INSECURE_USER_ID", "false"))
	if allowInsecureUserID {
		logger.Warn("WEBAUTHN_ALLOW_INSECURE_USER_ID is ENABLED — ceremonies trust a client-supplied user_id; DEV ONLY, never enable in production")
	}

	// Dev stores (in-memory). Replace with sqlc-backed implementations for prod.
	store := webauthn.NewInMemoryStore()
	sessions := webauthn.NewInMemorySessionStore()

	// Seed a demo user so the ceremony endpoints are exercisable in dev. Only
	// when the insecure path is enabled — prod wiring stays clean. Real accounts
	// are provisioned by the enrollment flow (docs/DESIGN.md §11.1).
	demoUserID := []byte("demo-user")
	if allowInsecureUserID {
		store.PutUser(webauthn.NewUser(demoUserID, "demo@harbor.local", "Demo User", nil))
	}

	svc, err := webauthn.NewService(webauthn.Config{
		RPID:          rpID,
		RPDisplayName: rpDisplayName,
		RPOrigins:     rpOrigins,
	}, store, sessions)
	if err != nil {
		logger.Error("failed to configure webauthn service", "error", err)
		os.Exit(1)
	}

	mux := httpserver.NewHealthMux()
	webauthn.RegisterRoutes(mux, svc, allowInsecureUserID)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	logger.Info("starting harbor-mgmt",
		"port", port,
		"rp_id", rpID,
		"demo_user_id", base64.RawURLEncoding.EncodeToString(demoUserID),
	)
	if err := httpserver.Run(ctx, ":"+port, mux, logger); err != nil {
		logger.Error("harbor-mgmt exited with error", "error", err)
		os.Exit(1)
	}
}

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
