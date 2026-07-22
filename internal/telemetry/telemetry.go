// Package telemetry is Harbor's SOLE allow-listed telemetry wrapper
// (Foundation F10). It exists to make the observability privacy invariants of
// §6.5.7 STRUCTURAL rather than aspirational:
//
//   - No PII in logs, metric labels, or trace spans — ever.
//   - Deny-by-default attribute allow-listing: a structured field is emitted
//     ONLY if its key is explicitly known non-PII; everything else is redacted.
//
// The core promise (§2.2: privacy that is *verifiable*, not merely promised)
// dies quietly the first time someone writes a "helpful"
// `log.Info("user", email)`. This wrapper makes that impossible on the paths
// that use it: an unknown key never reaches the sink with its value intact. The
// companion analyzer tools/lint/piifields catches direct slog/log calls that
// bypass this wrapper.
package telemetry

import (
	"context"
	"log/slog"
)

// AllowedFields is the deny-by-default allow-list of structured keys that are
// KNOWN NON-PII and therefore safe to emit in logs/metrics/traces. Any key not
// in this set is redacted (see Logger). Extend it deliberately and only with
// keys that carry no user-identifying information (§6.5.7).
var AllowedFields = map[string]struct{}{
	"region":        {},
	"issuer":        {},
	"client_id":     {}, // an RP identifier, not a user identifier (§5.3)
	"grant_type":    {},
	"status":        {},
	"http_status":   {},
	"method":        {},
	"path_template": {}, // a route TEMPLATE, never a concrete path with ids
	"latency_ms":    {},
	"result":        {},
	"error_code":    {},
	"count":         {},
	"component":     {},
	"event":         {},
}

// DeniedFields enumerates KNOWN-PII keys that must NEVER be emitted. It is used
// by the F10 analyzer (tools/lint/piifields) and serves as living documentation.
// These are always redacted by the Logger regardless of the allow-list, and are
// asserted disjoint from AllowedFields by the tests.
var DeniedFields = []string{
	"email",
	"user_id",
	"sub",
	"ppid",
	"ip",
	"ip_address",
	"token",
	"access_token",
	"id_token",
	"code",
	"code_verifier",
	"name",
	"phone",
	"relay",
	"relay_address",
}

// redactionValue is the marker substituted for any non-allow-listed attribute
// value. It never contains the original value.
const redactionValue = "REDACTED"

// IsAllowed reports whether key is on the non-PII allow-list.
func IsAllowed(key string) bool {
	_, ok := AllowedFields[key]
	return ok
}

// Logger is a thin, privacy-preserving wrapper over *slog.Logger. Its Info/Warn/
// Error methods pass through ONLY allow-listed attributes; every other attribute
// is replaced with `<key>=REDACTED`, so a caller can never leak PII through it —
// even by accident.
type Logger struct {
	base *slog.Logger
}

// New wraps a base *slog.Logger. If base is nil, slog.Default() is used.
func New(base *slog.Logger) *Logger {
	if base == nil {
		base = slog.Default()
	}
	return &Logger{base: base}
}

// filter returns a copy of attrs with every non-allow-listed key redacted.
func filter(attrs []slog.Attr) []slog.Attr {
	out := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		if IsAllowed(a.Key) {
			out[i] = a
			continue
		}
		out[i] = slog.String(a.Key, redactionValue)
	}
	return out
}

// Info logs at info level with the attributes filtered through the allow-list.
func (l *Logger) Info(msg string, attrs ...slog.Attr) { l.log(slog.LevelInfo, msg, attrs) }

// Warn logs at warn level with the attributes filtered through the allow-list.
func (l *Logger) Warn(msg string, attrs ...slog.Attr) { l.log(slog.LevelWarn, msg, attrs) }

// Error logs at error level with the attributes filtered through the allow-list.
func (l *Logger) Error(msg string, attrs ...slog.Attr) { l.log(slog.LevelError, msg, attrs) }

func (l *Logger) log(level slog.Level, msg string, attrs []slog.Attr) {
	l.base.LogAttrs(context.Background(), level, msg, filter(attrs)...)
}
