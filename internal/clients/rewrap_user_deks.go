package clients

import (
	"context"
	"fmt"

	"github.com/harbor-auth/harbor/internal/crypto"
	db "github.com/harbor-auth/harbor/internal/gen/db"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// RewrapUserDEKs replaces only the envelope around each existing DEK. User
// ciphertext and pairwise identities remain unchanged. Each batch commits
// atomically and can be retried after interruption. Run only once every writer
// has switched to the external provider; erased (empty) keys are never restored.
func RewrapUserDEKs(ctx context.Context, pool *pgxpool.Pool, keys *crypto.UserKeyProvider) (int, error) {
	total := 0
	for {
		changed, err := rewrapUserDEKBatch(ctx, pool, keys)
		if err != nil {
			return total, err
		}
		total += changed
		if changed == 0 {
			return total, nil
		}
	}
}

func rewrapUserDEKBatch(ctx context.Context, pool *pgxpool.Pool, keys *crypto.UserKeyProvider) (int, error) {
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return 0, err
	}
	defer rollbackTransaction(tx)
	q := db.New(tx)
	prefix := crypto.UserDEKEnvelopePrefix()
	rows, err := q.ListUserDEKsToRewrap(ctx, db.ListUserDEKsToRewrapParams{PrefixLength: int32(len(prefix)), EnvelopePrefix: prefix})
	if err != nil {
		return 0, fmt.Errorf("list user DEKs: %w", err)
	}
	for _, row := range rows {
		wrapped, err := rewrapUserDEK(ctx, keys, row.Region, row.DekWrapped)
		if err != nil {
			return 0, fmt.Errorf("rewrap user DEK: %w", err)
		}
		if err := q.ReplaceUserDEK(ctx, db.ReplaceUserDEKParams{ID: row.ID, DekWrapped: wrapped}); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return len(rows), nil
}

func rewrapUserDEK(ctx context.Context, keys *crypto.UserKeyProvider, region string, wrapped []byte) ([]byte, error) {
	dek, err := keys.UnwrapDEK(ctx, region, wrapped)
	if err != nil {
		return nil, err
	}
	defer clear(dek[:])
	next, err := keys.WrapDEK(ctx, region, dek)
	if err != nil {
		return nil, err
	}
	if !crypto.IsExternalUserDEK(next) {
		return nil, fmt.Errorf("enable external user-DEK writes before migration")
	}
	verified, err := keys.UnwrapDEK(ctx, region, next)
	if err != nil {
		return nil, err
	}
	defer clear(verified[:])
	if verified != dek {
		return nil, fmt.Errorf("external user-DEK verification mismatch")
	}
	return next, nil
}
