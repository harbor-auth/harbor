package oidc

import (
	"context"
	"log/slog"
	"time"
)

// RevocationWorkerConfig configures a RevocationWorker.
type RevocationWorkerConfig struct {
	// Outbox is the durable outbox that stores pending revocation signals.
	// Must implement DeliverPending(ctx, sink) — typically *clients.DBRevocationOutbox.
	Outbox OutboxDeliverer

	// SessionStore is the sink for revocation delivery (RevokeSessionsByUserClient).
	SessionStore SessionStore

	// Logger for worker lifecycle and delivery errors. Defaults to slog.Default().
	Logger *slog.Logger

	// TickInterval is the polling interval. Defaults to 5 seconds.
	TickInterval time.Duration
}

// OutboxDeliverer is the subset of DBRevocationOutbox that RevocationWorker needs.
// Defined here to avoid importing internal/clients (which imports oidc).
type OutboxDeliverer interface {
	// DeliverPending fetches pending revocations and attempts delivery.
	DeliverPending(ctx context.Context, sink SessionStore) error
}

// defaultTickInterval is the default polling interval for the revocation worker.
const defaultTickInterval = 5 * time.Second

// RevocationWorker polls the revocation outbox and delivers pending signals.
// It runs as a background goroutine, started via Run(), and shuts down gracefully
// when the provided context is cancelled.
type RevocationWorker struct {
	outbox       OutboxDeliverer
	sessionStore SessionStore
	logger       *slog.Logger
	tickInterval time.Duration
}

// NewRevocationWorker creates a RevocationWorker from the given config.
// Panics if Outbox or SessionStore is nil.
func NewRevocationWorker(cfg RevocationWorkerConfig) *RevocationWorker {
	if cfg.Outbox == nil {
		panic("oidc: RevocationWorkerConfig.Outbox must not be nil")
	}
	if cfg.SessionStore == nil {
		panic("oidc: RevocationWorkerConfig.SessionStore must not be nil")
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	tickInterval := cfg.TickInterval
	if tickInterval <= 0 {
		tickInterval = defaultTickInterval
	}
	return &RevocationWorker{
		outbox:       cfg.Outbox,
		sessionStore: cfg.SessionStore,
		logger:       logger,
		tickInterval: tickInterval,
	}
}

// Run starts the worker loop. It blocks until ctx is cancelled, then returns.
// Call this in a goroutine: go worker.Run(ctx)
//
// The worker polls the outbox every TickInterval (default 5s) and calls
// DeliverPending to process any pending revocation signals. Delivery errors
// are logged but do not stop the worker — it continues polling on the next tick.
func (w *RevocationWorker) Run(ctx context.Context) {
	w.logger.InfoContext(ctx, "revocation worker starting",
		slog.Duration("tick_interval", w.tickInterval))

	ticker := time.NewTicker(w.tickInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			w.logger.InfoContext(ctx, "revocation worker stopping (context cancelled)")
			return
		case <-ticker.C:
			w.tick(ctx)
		}
	}
}

// tick performs one delivery cycle. Errors are logged, not returned —
// the worker continues on the next tick regardless.
func (w *RevocationWorker) tick(ctx context.Context) {
	// Use a child context with a timeout to bound each delivery cycle.
	// This prevents a hung DB from blocking the worker indefinitely.
	tickCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	if err := w.outbox.DeliverPending(tickCtx, w.sessionStore); err != nil {
		w.logger.ErrorContext(ctx, "revocation worker: DeliverPending failed",
			slog.Any("error", err))
	}
}
