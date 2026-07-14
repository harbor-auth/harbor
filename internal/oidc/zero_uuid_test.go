package oidc

import "testing"

// TestZeroUUIDConstantMatchesSentinel verifies that the zeroUUID sentinel
// constant in this package matches the well-known zero UUID string. This
// creates a test-time cross-reference to TestUUIDToStringInvalid in
// internal/clients/grants_test.go, which proves that clients.uuidToString
// returns exactly this sentinel string for a NULL pgtype.UUID — the value
// that signalRefreshReuse guards against.
//
// If clients.uuidToString ever changes its NULL return value, BOTH this
// constant AND that test must be updated together, and the guard in
// signalRefreshReuse must be updated to match.
func TestZeroUUIDConstantMatchesSentinel(t *testing.T) {
	const wantSentinel = "00000000-0000-0000-0000-000000000000"
	if zeroUUID != wantSentinel {
		t.Fatalf("zeroUUID = %q, want %q; also update signalRefreshReuse guard and clients.uuidToString coupling note in TestUUIDToStringInvalid", zeroUUID, wantSentinel)
	}
}
