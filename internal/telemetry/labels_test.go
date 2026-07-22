package telemetry_test

// Tests for the compile-time label allow-list (observability-metrics REQ-001).
//
// The core privacy property — that a PII / free-form label is NOT EXPRESSIBLE —
// is a COMPILE-TIME guarantee, so it cannot be asserted at runtime. It is
// instead documented (and exercised) here and structurally guaranteed by the
// facade: telemetry.Label has only unexported fields and the ONLY constructors
// are the allow-listed builders below. Code such as
//
//	telemetry.Label{key: "user_id", value: uid}   // unexported fields: won't compile
//	telemetry.NewLabel("user_id", uid)             // no such function: won't compile
//
// does not compile, so a user_id/email/PPID/IP/subject label can never be built.
// The internal/arch test provides the companion CI enforcement (REQ-004).

import (
	"testing"

	"github.com/harbor-auth/harbor/internal/region"
	"github.com/harbor-auth/harbor/internal/telemetry"
)

func TestLabelBuildersPinAllowListedKeys(t *testing.T) {
	cases := []struct {
		name      string
		label     telemetry.Label
		wantKey   telemetry.LabelKey
		wantValue string
	}{
		{"region", telemetry.Region(region.EU), telemetry.KeyRegion, "EU"},
		{"endpoint", telemetry.Endpoint(telemetry.EndpointToken), telemetry.KeyEndpoint, "token"},
		{"outcome", telemetry.Outcome(telemetry.OutcomeSuccess), telemetry.KeyOutcome, "success"},
		{"grant_type", telemetry.GrantType(telemetry.GrantAuthorizationCode), telemetry.KeyGrantType, "authorization_code"},
		{"error_code", telemetry.ErrorCode(telemetry.ErrInvalidGrant), telemetry.KeyErrorCode, "invalid_grant"},
		{"client_id", telemetry.ClientID("rp-123"), telemetry.KeyClientID, "rp-123"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.label.Key(); got != tc.wantKey {
				t.Errorf("Key() = %q, want %q", got, tc.wantKey)
			}
			if got := tc.label.Value(); got != tc.wantValue {
				t.Errorf("Value() = %q, want %q", got, tc.wantValue)
			}
		})
	}
}

// TestZeroLabelIsInert guards the phantom type: a zero Label (the only value an
// external package could name without a builder) carries no allow-listed key,
// so it can never smuggle a dimension into a metric.
func TestZeroLabelIsInert(t *testing.T) {
	var zero telemetry.Label
	if zero.Key() != "" {
		t.Errorf("zero Label has key %q, want empty", zero.Key())
	}
	if zero.Value() != "" {
		t.Errorf("zero Label has value %q, want empty", zero.Value())
	}
}
