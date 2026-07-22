package region

import (
	"errors"
	"testing"
)

// These tests exercise BindIssuerHost through the exported API. They bind
// test-only hosts (never a default *.harbor.id host) and delete them from the
// package-global host map on cleanup so the default-map invariants asserted by
// the other region tests stay hermetic regardless of run order.

// TestBindIssuerHostAddsUnknownHost binds a previously-unknown host and proves
// Resolve then routes it — the single seam a single-region/dev deployment uses
// to teach the resolver its own issuer host.
func TestBindIssuerHostAddsUnknownHost(t *testing.T) {
	const host = "bind-add.harbor.test"
	t.Cleanup(func() { delete(hostMap, host) })

	if _, err := Resolve(host); !errors.Is(err, ErrUnknownHost) {
		t.Fatalf("precondition: Resolve(%q) = %v, want ErrUnknownHost", host, err)
	}
	// A full issuer URL must normalise to the bare host before binding.
	if err := BindIssuerHost("https://"+host+":443", EU); err != nil {
		t.Fatalf("BindIssuerHost(%q, EU) = %v, want nil", host, err)
	}
	got, err := Resolve(host)
	if err != nil {
		t.Fatalf("Resolve(%q) after bind = %v, want nil", host, err)
	}
	if got != EU {
		t.Fatalf("Resolve(%q) = %q, want EU", host, got)
	}
}

// TestBindIssuerHostIdempotentSameRegion rebinding a host to the SAME region is
// a no-op success, so BindIssuerHost is safe to call on every boot.
func TestBindIssuerHostIdempotentSameRegion(t *testing.T) {
	const host = "bind-idem.harbor.test"
	t.Cleanup(func() { delete(hostMap, host) })

	if err := BindIssuerHost(host, US); err != nil {
		t.Fatalf("first BindIssuerHost(%q, US) = %v, want nil", host, err)
	}
	if err := BindIssuerHost(host, US); err != nil {
		t.Fatalf("second BindIssuerHost(%q, US) = %v, want nil (idempotent)", host, err)
	}
}

// TestBindIssuerHostRejectsConflict binding a host already mapped to a DIFFERENT
// region is refused — the fail-closed guard against an env typo re-pinning where
// a jurisdiction's PII resolves. The original binding MUST survive.
func TestBindIssuerHostRejectsConflict(t *testing.T) {
	const host = "bind-conflict.harbor.test"
	t.Cleanup(func() { delete(hostMap, host) })

	if err := BindIssuerHost(host, EU); err != nil {
		t.Fatalf("BindIssuerHost(%q, EU) = %v, want nil", host, err)
	}
	if err := BindIssuerHost(host, US); !errors.Is(err, ErrInvalidHostMap) {
		t.Fatalf("BindIssuerHost(%q, US) after EU = %v, want ErrInvalidHostMap", host, err)
	}
	if got, err := Resolve(host); err != nil || got != EU {
		t.Fatalf("Resolve(%q) after rejected rebind = (%q, %v), want (EU, nil)", host, got, err)
	}
}

// TestBindIssuerHostRejectsUnknownRegion an unknown region value cannot be bound
// (defense against a malformed REGION env reaching the host map).
func TestBindIssuerHostRejectsUnknownRegion(t *testing.T) {
	if err := BindIssuerHost("bind-badregion.harbor.test", Region("MARS")); !errors.Is(err, ErrUnknownRegion) {
		t.Fatalf("BindIssuerHost(_, MARS) = %v, want ErrUnknownRegion", err)
	}
	// The rejected host must NOT have been added.
	if _, err := Resolve("bind-badregion.harbor.test"); !errors.Is(err, ErrUnknownHost) {
		t.Fatalf("host was bound despite unknown region: Resolve err = %v, want ErrUnknownHost", err)
	}
}

// TestBindIssuerHostRejectsEmptyHost a blank issuer normalises to no host and is
// rejected as unknown.
func TestBindIssuerHostRejectsEmptyHost(t *testing.T) {
	if err := BindIssuerHost("   ", EU); !errors.Is(err, ErrUnknownHost) {
		t.Fatalf("BindIssuerHost(blank, EU) = %v, want ErrUnknownHost", err)
	}
}
