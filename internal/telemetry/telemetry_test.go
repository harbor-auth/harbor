package telemetry_test

// Foundation F10 tests: the telemetry wrapper must pass allow-listed attributes
// through unchanged and REDACT everything else, so PII can never reach the sink.

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/harbor-auth/harbor/internal/telemetry"
)

func newCapture() (*telemetry.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	base := slog.New(slog.NewJSONHandler(&buf, nil))
	return telemetry.New(base), &buf
}

func TestAllowedAttrPassesThrough(t *testing.T) {
	log, buf := newCapture()
	log.Info("token issued", slog.String("region", "EU"), slog.String("grant_type", "authorization_code"))

	out := buf.String()
	if !strings.Contains(out, `"region":"EU"`) {
		t.Errorf("allow-listed attr region was not emitted: %s", out)
	}
	if !strings.Contains(out, `"grant_type":"authorization_code"`) {
		t.Errorf("allow-listed attr grant_type was not emitted: %s", out)
	}
}

func TestDeniedAttrIsRedacted(t *testing.T) {
	log, buf := newCapture()
	const secretEmail = "alice@example.com"
	log.Info("login", slog.String("email", secretEmail), slog.String("user_id", "u-123"))

	out := buf.String()
	if strings.Contains(out, secretEmail) {
		t.Fatalf("PII email leaked to the sink: %s", out)
	}
	if strings.Contains(out, "u-123") {
		t.Fatalf("PII user_id leaked to the sink: %s", out)
	}
	if !strings.Contains(out, "REDACTED") {
		t.Errorf("expected a REDACTED marker for the denied attrs: %s", out)
	}
}

func TestUnknownAttrIsRedacted(t *testing.T) {
	log, buf := newCapture()
	log.Warn("weird", slog.String("totally_unlisted_key", "sensitive-value-xyz"))

	out := buf.String()
	if strings.Contains(out, "sensitive-value-xyz") {
		t.Fatalf("unknown (non-allow-listed) attr value leaked: %s", out)
	}
}

func TestIsAllowed(t *testing.T) {
	if !telemetry.IsAllowed("region") {
		t.Error("region should be allowed")
	}
	if telemetry.IsAllowed("email") {
		t.Error("email must never be allowed")
	}
}

// TestAllowAndDenyAreDisjoint guards against a footgun: no known-PII key may
// ever sneak onto the allow-list.
func TestAllowAndDenyAreDisjoint(t *testing.T) {
	for _, denied := range telemetry.DeniedFields {
		if telemetry.IsAllowed(denied) {
			t.Errorf("denied PII key %q is also on the allow-list — they must be disjoint", denied)
		}
	}
}
