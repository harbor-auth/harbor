// Package httpserver provides the small, shared HTTP wiring used by Harbor's
// binaries (harbor-hot, harbor-mgmt). Keeping it here means the cmd/ mains stay
// thin and the wiring is tested once.
package httpserver

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"
)

// NewHealthMux returns a mux with a single liveness endpoint:
//
//	GET /healthz -> 200 "ok"
//
// It is deliberately tiny and dependency-free so both binaries can embed it and
// grow their own routes on top.
func NewHealthMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	return mux
}

// Run starts an http.Server bound to addr serving h, and shuts it down
// gracefully when ctx is cancelled. It returns nil on a clean shutdown.
//
// Logging is structured (slog) and carries no PII, consistent with the
// observability rules in docs/DESIGN.md §6.5.
func Run(ctx context.Context, addr string, h http.Handler, logger *slog.Logger) error {
	// Timeouts blunt slow-client (Slowloris) attacks and stop leaked connections
	// from tying up the hot path (docs/DESIGN.md §6.5).
	srv := &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// Shut down gracefully when the context is cancelled. The goroutine also
	// exits if the server stops on its own (serveErr), so it never leaks.
	serveErr := make(chan error, 1)
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		select {
		case <-ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := srv.Shutdown(shutdownCtx); err != nil {
				logger.Error("graceful shutdown failed", "error", err)
			}
		case <-serveErr:
			// Server already stopped; nothing to shut down.
		}
	}()

	logger.Info("http server listening", "addr", addr)
	err := srv.ListenAndServe()
	serveErr <- err
	<-shutdownDone
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
