package clients

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
	"log/slog"
	"sync"
	"time"

	"github.com/harbor-auth/harbor/internal/crypto"
	db "github.com/harbor-auth/harbor/internal/gen/db"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// LiveSigningKeys coordinates durable rotation across replicas. Every read
// checks current DB metadata; only key unwrapping is cached. Thus an unavailable
// database fails closed rather than letting a disconnected replica keep signing
// with a retired key. KMS calls occur only for new keys, not for each token.
type LiveSigningKeys struct {
	pool   *pgxpool.Pool
	kp     crypto.KeyProvider
	region string
	timing crypto.RotationConfig
	now    func() time.Time
	mu     sync.Mutex
	cache  map[string]cachedSigningKey
}
type cachedSigningKey struct {
	wrappedHash [32]byte
	signer      crypto.Signer
}

func NewLiveSigningKeys(pool *pgxpool.Pool, kp crypto.KeyProvider, region string, timing crypto.RotationConfig) *LiveSigningKeys {
	return &LiveSigningKeys{pool: pool, kp: kp, region: region, timing: timing, now: time.Now, cache: make(map[string]cachedSigningKey)}
}

// Initialize serializes first-key seeding too: concurrent cold replicas must
// never create competing active keys or leave orphan pending keys.
func (s *LiveSigningKeys) Initialize(ctx context.Context) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollbackTransaction(tx)
	q := db.New(tx)
	if err = q.LockSigningKeyRotation(ctx); err != nil {
		return err
	}
	loader := NewSigningKeyLoader(NewDBSigningKeyStore(q), s.kp, s.region)
	if _, err = loader.SeedAndLoad(ctx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *LiveSigningKeys) Snapshot(ctx context.Context) (crypto.SigningKeyProvider, error) {
	rows, err := db.New(s.pool).ListLiveSigningKeys(ctx)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	loader := NewSigningKeyLoader(nil, s.kp, s.region)
	next := make(map[string]cachedSigningKey, len(rows))
	var active crypto.Signer
	others := make([]crypto.Signer, 0, len(rows))
	for _, row := range rows {
		key := rowToSigningKey(row)
		hash := sha256.Sum256(key.PrivateKeyWrapped)
		cached, ok := s.cache[key.Kid]
		if !ok || cached.wrappedHash != hash {
			signer, err := loader.reconstructSigner(ctx, key)
			if err != nil {
				return nil, err
			}
			if signer.KeyID() != key.Kid {
				return nil, fmt.Errorf("signing key identity mismatch")
			}
			cached = cachedSigningKey{wrappedHash: hash, signer: signer}
		}
		next[key.Kid] = cached
		if key.State == string(crypto.KeyStateActive) {
			active = cached.signer
		} else {
			others = append(others, cached.signer)
		}
	}
	provider, err := crypto.NewMultiKeyProvider(active, others...)
	if err != nil {
		return nil, err
	}
	s.cache = next
	return provider, nil
}

func (s *LiveSigningKeys) Rotate(ctx context.Context, opts crypto.RotateOptions) (crypto.RotateResult, error) {
	if opts.Region != "" && opts.Region != s.region {
		return crypto.RotateResult{}, fmt.Errorf("rotation region does not match issuer")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return crypto.RotateResult{}, err
	}
	defer rollbackTransaction(tx)
	q := db.New(tx)
	if err = q.LockSigningKeyRotation(ctx); err != nil {
		return crypto.RotateResult{}, err
	}
	live, err := q.ListLiveSigningKeys(ctx)
	if err != nil {
		return crypto.RotateResult{}, err
	}
	var old string
	for _, key := range live {
		if key.State == "active" {
			old = key.Kid
		}
		if key.State == "pending" && !opts.Emergency {
			return crypto.RotateResult{}, fmt.Errorf("a signing key rotation is already pending")
		}
	}
	if old == "" {
		return crypto.RotateResult{}, crypto.ErrNoActiveKey
	}
	signer, err := crypto.NewLocalSigner()
	if err != nil {
		return crypto.RotateResult{}, err
	}
	loader := NewSigningKeyLoader(nil, s.kp, s.region)
	wrapped, err := loader.wrapSigner(ctx, signer)
	if err != nil {
		return crypto.RotateResult{}, err
	}
	store := NewDBRotationStore(NewDBSigningKeyStore(q), s.region)
	now := s.now()
	if err = store.Create(ctx, crypto.NewKeyMaterial{Kid: signer.KeyID(), PublicJWK: signer.PublicJWK(), Region: s.region, WrappedPrivateKey: wrapped}); err != nil {
		return crypto.RotateResult{}, err
	}
	result := crypto.RotateResult{NewKid: signer.KeyID(), OldKid: old, Emergency: opts.Emergency, PromoteAt: now.Add(s.timing.GracePeriod), RetireOldAt: now.Add(s.timing.GracePeriod + s.timing.OverlapWindow)}
	if opts.Emergency {
		// Clear every previously trusted key, including pending/draining keys.
		// The new row is made active in the same transaction, never exposing a gap.
		if err = q.RetireAllLiveSigningKeys(ctx, stamp(now)); err != nil {
			return crypto.RotateResult{}, err
		}
		if err = store.Promote(ctx, signer.KeyID(), now); err != nil {
			return crypto.RotateResult{}, err
		}
		result.PromoteAt = now
		result.RetireOldAt = now
	} else {
		if err = q.ScheduleSigningKey(ctx, db.ScheduleSigningKeyParams{Kid: signer.KeyID(), PromoteAfter: stamp(result.PromoteAt)}); err != nil {
			return crypto.RotateResult{}, err
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return crypto.RotateResult{}, err
	}
	return result, nil
}

// Reconcile applies persisted deadlines. Repeating it, restarting the process,
// or running it concurrently on several replicas cannot promote twice.
func (s *LiveSigningKeys) Reconcile(ctx context.Context) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollbackTransaction(tx)
	q := db.New(tx)
	if err = q.LockSigningKeyRotation(ctx); err != nil {
		return err
	}
	now := s.now()
	if err = q.RetireDueSigningKeys(ctx, stamp(now)); err != nil {
		return err
	}
	rows, err := q.ListLiveSigningKeys(ctx)
	if err != nil {
		return err
	}
	store := NewDBRotationStore(NewDBSigningKeyStore(q), s.region)
	for _, key := range rows {
		if key.State != "pending" || !key.PromoteAfter.Valid || key.PromoteAfter.Time.After(now) {
			continue
		}
		if err = q.DrainActiveSigningKey(ctx, stamp(now.Add(s.timing.OverlapWindow))); err != nil {
			return err
		}
		if err = store.Promote(ctx, key.Kid, now); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (s *LiveSigningKeys) Run(ctx context.Context, logger *slog.Logger) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		if err := s.Reconcile(ctx); err != nil && ctx.Err() == nil {
			logger.Error("signing key reconciliation failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func stamp(t time.Time) pgtype.Timestamptz { return pgtype.Timestamptz{Time: t, Valid: true} }

func rollbackTransaction(tx pgx.Tx) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := tx.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		slog.Error("database transaction rollback failed", "error", err)
	}
}
