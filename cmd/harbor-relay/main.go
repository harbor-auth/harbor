// Command harbor-relay is the inbound email relay MTA (docs/DESIGN.md §7.5).
//
// It listens for SMTP, looks up masked per-RP relay addresses, authenticates
// inbound mail (SPF/DKIM/DMARC), ARC-seals it, and forwards it to the user's
// real inbox via a smarthost. The real email address is stored envelope-
// encrypted (region-pinned) and is only decrypted transiently in memory during
// forwarding — it is never logged or persisted in the clear (§7.5.6).
//
// Configuration (environment):
//
//	PORT                     — SMTP listen port (default 2525; the Service maps
//	                           the public port 25 → this non-privileged port so
//	                           the pod runs as non-root).
//	REGION                   — home region this MTA serves (e.g. "EU").
//	RELAY_DOMAIN             — relay domain suffix (e.g. "relay.eu.harbor.id").
//	RELAY_SMARTHOST          — host:port of the outbound smarthost used to
//	                           deliver forwarded mail. When empty, mail is
//	                           accepted but not forwarded (test mode).
//	RELAY_RETURN_PATH        — envelope sender for forwarded mail (bounces).
//	RELAY_DKIM_SELECTOR      — DKIM selector for ARC sealing (optional).
//	RELAY_DKIM_PRIVATE_KEY   — PEM-encoded RSA private key for ARC sealing
//	                           (optional; ARC sealing is skipped when unset).
//	RELAY_ENFORCE_AUTH       — "true" to reject mail that fails SPF/DKIM/DMARC;
//	                           otherwise results are evaluated but only logged.
//	DATABASE_URL             — regional Postgres DSN (REQUIRED: the mapping
//	                           lookup lives here).
//	HARBOR_KMS_SECRET        — regional KEK sealing per-user DEKs (REQUIRED).
package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/harbor-auth/harbor/internal/clients"
	"github.com/harbor-auth/harbor/internal/crypto"
	"github.com/harbor-auth/harbor/internal/gen/db"
	"github.com/harbor-auth/harbor/internal/region"
	"github.com/harbor-auth/harbor/internal/relay"
)

const (
	// defaultPort is the non-privileged port the container listens on. The
	// Kubernetes Service maps the public SMTP port 25 → this port so the pod
	// never needs to bind a privileged port (and thus runs as non-root).
	defaultPort = "2525"
	// maxMessageBytes caps a single inbound message at 25 MiB.
	maxMessageBytes = 25 * 1024 * 1024
	// shutdownTimeout bounds graceful drain of in-flight SMTP sessions.
	shutdownTimeout = 30 * time.Second
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(logger); err != nil {
		logger.Error("harbor-relay exited with error", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// --- Required configuration ---
	reg := region.Region(os.Getenv("REGION"))
	if reg == "" {
		return errors.New("REGION is required")
	}
	relayDomain := os.Getenv("RELAY_DOMAIN")
	if relayDomain == "" {
		return errors.New("RELAY_DOMAIN is required")
	}
	kekSecret := os.Getenv("HARBOR_KMS_SECRET")
	if kekSecret == "" {
		return errors.New("HARBOR_KMS_SECRET is required")
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = defaultPort
	}

	// --- Database (required — the encrypted mapping lives here) ---
	pool, err := clients.ConnectDB(ctx, logger)
	if err != nil {
		if ctx.Err() != nil {
			// SIGINT/SIGTERM during startup is a clean shutdown, not a crash.
			logger.Info("startup cancelled by signal — exiting cleanly", "error", err)
			return nil
		}
		return fmt.Errorf("database connection failed: %w", err)
	}
	if pool == nil {
		return errors.New("DATABASE_URL is required for harbor-relay")
	}
	defer pool.Close()

	queries := db.New(pool)

	// --- Crypto: local KEK provider + cipher for the envelope-encrypted
	// relay mapping. (KMS provider plugs in behind the same interface later.) ---
	keyProvider, err := crypto.NewLocalKeyProvider(kekSecret)
	if err != nil {
		return fmt.Errorf("key provider: %w", err)
	}
	store := relay.NewStore(queries, crypto.NewCipher())

	resolver := &dbMappingResolver{queries: queries, keyProvider: keyProvider, store: store}

	// --- ARC sealing (optional) ---
	var sealer *relay.ARCSealer
	if selector := os.Getenv("RELAY_DKIM_SELECTOR"); selector != "" {
		keyPEM := os.Getenv("RELAY_DKIM_PRIVATE_KEY")
		if keyPEM == "" {
			return errors.New("RELAY_DKIM_SELECTOR set but RELAY_DKIM_PRIVATE_KEY is empty")
		}
		key, keyErr := parseDKIMKey(keyPEM)
		if keyErr != nil {
			return keyErr
		}
		sealer = relay.NewARCSealer(relayDomain, selector, key)
	}

	// --- Forwarding (optional): only wire the forwarder + resolver when a
	// smarthost is configured. MappingResolver is required only when a
	// Forwarder is set. ---
	var (
		forwarder       relay.Forwarder
		mappingResolver relay.MappingResolver
	)
	if smarthost := os.Getenv("RELAY_SMARTHOST"); smarthost != "" {
		forwarder = relay.NewSMTPForwarder(smarthost)
		mappingResolver = resolver
	}

	enforceAuth, err := parseEnforceAuth(os.Getenv("RELAY_ENFORCE_AUTH"))
	if err != nil {
		return err
	}

	cfg := relay.MTAConfig{
		Lookup:          store,
		Logger:          logger,
		Domain:          relayDomain,
		MaxRecipients:   1,
		MaxMessageBytes: maxMessageBytes,
		Authenticator:   relay.NewAuthenticator(),
		EnforceAuth:     enforceAuth,
		ARCSealer:       sealer,
		Forwarder:       forwarder,
		MappingResolver: mappingResolver,
		ReturnPath:      os.Getenv("RELAY_RETURN_PATH"),
		Region:          reg,
	}

	srv := relay.NewServer(cfg)
	srv.Addr = ":" + port

	errCh := make(chan error, 1)
	go func() {
		logger.Info("harbor-relay listening",
			"addr", srv.Addr,
			"domain", relayDomain,
			"region", string(reg),
			"forwarding", forwarder != nil,
			"arc_sealing", sealer != nil,
			"enforce_auth", enforceAuth,
		)
		errCh <- srv.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		logger.Info("shutdown signal received — draining")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	case err := <-errCh:
		return err
	}
}

// Compile-time assertion: dbMappingResolver must satisfy relay.MappingResolver.
var _ relay.MappingResolver = (*dbMappingResolver)(nil)

// dbMappingResolver resolves a relay address to the user's real email by
// unwrapping the user's DEK (via the KEK provider) and decrypting the region-
// pinned envelope-encrypted mapping. The plaintext email exists only for the
// duration of a single forward and is never logged or persisted.
type dbMappingResolver struct {
	queries     *db.Queries
	keyProvider crypto.KeyProvider
	store       *relay.Store
}

// ResolveRealEmail decrypts and returns the real email for the given relay address.
func (r *dbMappingResolver) ResolveRealEmail(ctx context.Context, addr *relay.Address, encMapping []byte) (string, error) {
	uid := pgtype.UUID{Bytes: addr.UserID, Valid: true}
	user, err := r.queries.GetUser(ctx, uid)
	if err != nil {
		return "", fmt.Errorf("relay: load user: %w", err)
	}
	dek, err := r.keyProvider.UnwrapDEK(ctx, string(addr.Region), user.DekWrapped)
	if err != nil {
		return "", fmt.Errorf("relay: unwrap DEK: %w", err)
	}
	return r.store.DecryptMapping(encMapping, addr.Region, dek)
}

// parseDKIMKey parses a PEM-encoded RSA private key (PKCS#1 or PKCS#8) used for
// ARC sealing.
func parseDKIMKey(pemStr string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("RELAY_DKIM_PRIVATE_KEY is not valid PEM")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	keyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse DKIM key: %w", err)
	}
	rsaKey, ok := keyAny.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("DKIM key is not an RSA key")
	}
	return rsaKey, nil
}

// parseEnforceAuth interprets RELAY_ENFORCE_AUTH, the switch that decides
// whether inbound mail failing SPF/DKIM/DMARC is rejected or merely logged.
//
// An UNSET value means "evaluate but only log" — the documented default (see
// the Configuration block at the top of this file). A value that cannot be
// parsed is FATAL rather than falsely disabling enforcement: silently reading a
// typo'd RELAY_ENFORCE_AUTH=yes as "off" would leave an operator believing
// inbound mail is authenticated when it is not. Failing closed on a
// misconfigured security control beats booting with it quietly disabled
// (docs/design/principles/error-handling.md §1.11 — an error is handled,
// returned, or explicitly justified; never swallowed).
//
// The accepted spellings deliberately match the rest of Harbor's env handling
// (cmd/harbor-hot envBool) and are a superset of strconv.ParseBool, so an
// operator who writes "yes" or "on" gets what they meant instead of the
// opposite.
func parseEnforceAuth(raw string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "":
		return false, nil
	case "1", "t", "true", "yes", "on":
		return true, nil
	case "0", "f", "false", "no", "off":
		return false, nil
	default:
		return false, fmt.Errorf("invalid RELAY_ENFORCE_AUTH %q: use true/false (also accepted: yes/no, on/off, 1/0)", raw)
	}
}
