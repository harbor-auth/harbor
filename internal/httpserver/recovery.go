package httpserver

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/harbor-auth/harbor/internal/telemetry"
)

// httpPanicsTotal counts handler panics recovered by WithRecovery. It carries
// no per-request dimensions — a panic is always an error and aggregate count is
// sufficient for alerting.
var httpPanicsTotal = telemetry.NewCounter(
	"harbor_http_panics_total",
	"Total number of handler panics recovered by the HTTP server.",
)

// WithRecovery wraps next in a middleware that catches any handler panic,
// emits a structured error log (no PII, no panic value in body or log),
// increments the harbor_http_panics_total counter, and writes a generic
// HTTP 500 response.
//
// The panic value is deliberately excluded from both the log and the response:
// it may contain internal details or PII, and leaking it would violate §6.5.7.
func WithRecovery(next http.Handler, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				// http.ErrAbortHandler is a sentinel used by net/http itself to
				// silently abort a handler (e.g. when the client disconnects).
				// Re-panic so the server handles it as intended rather than
				// converting it into a spurious logged 500.
				// recover() yields `any`, so assert to error before errors.Is —
				// a wrapped ErrAbortHandler would slip past a bare == compare.
				if err, ok := rec.(error); ok && errors.Is(err, http.ErrAbortHandler) {
					panic(rec)
				}
				// Log at ERROR. The panic value (rec) is intentionally not
				// included — it may contain PII or internal implementation
				// details (docs/DESIGN.md §6.5.7).
				logger.Error("handler panic recovered",
					slog.String("component", "httpserver"),
				)
				httpPanicsTotal.Inc()
				http.Error(w, "internal server error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}
