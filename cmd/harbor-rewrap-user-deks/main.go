// Command harbor-rewrap-user-deks migrates user DEK envelopes after every
// application writer has enabled OpenBao. It never changes user ciphertext.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/harbor-auth/harbor/internal/clients"
	"github.com/harbor-auth/harbor/internal/crypto"
	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	if os.Getenv("USER_DEK_PROVIDER") != "openbao" {
		return fmt.Errorf("rewrap requires USER_DEK_PROVIDER=openbao")
	}
	provider, err := crypto.NewUserKeyProviderFromEnv()
	if err != nil {
		return err
	}
	keys, ok := provider.(*crypto.UserKeyProvider)
	if !ok {
		return fmt.Errorf("rewrap requires external user-DEK provider")
	}
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		return fmt.Errorf("DATABASE_URL is required")
	}
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		return fmt.Errorf("database configuration failed")
	}
	defer pool.Close()
	count, err := clients.RewrapUserDEKs(ctx, pool, keys)
	if err != nil {
		return fmt.Errorf("rewrap stopped after %d committed rows: %w", count, err)
	}
	fmt.Printf("Rewrapped %d user DEKs; no nonempty legacy envelopes remain.\n", count)
	return nil
}
