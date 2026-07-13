package arch

// Foundation F9 — architecture import-boundary fitness tests.
//
// Each test asserts a DESIGN import boundary by computing a package's full
// transitive import set and checking that forbidden packages are absent. We use
// `go list -deps` (module-aware) to compute imports; go/build does not resolve
// module dependencies, so it is unsuitable here.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const modulePath = "github.com/harbor/harbor"

// repoRoot walks up from the test's working directory until it finds go.mod.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find repo root (go.mod) walking up from test dir")
		}
		dir = parent
	}
}

// transitiveImports returns the full transitive import set of pkgPath (the
// package itself plus every dependency, module-internal and external) as a set
// of import paths, via `go list -deps`.
func transitiveImports(t *testing.T, pkgPath string) map[string]bool {
	t.Helper()
	root := repoRoot(t)

	cmd := exec.Command("go", "list", "-deps", pkgPath)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps %s failed: %v\n%s", pkgPath, err, out)
	}

	set := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		if p := strings.TrimSpace(line); p != "" {
			set[p] = true
		}
	}
	if len(set) == 0 {
		t.Fatalf("go list -deps %s returned no packages", pkgPath)
	}
	return set
}

// containsMatching reports the first import in set whose path contains any of the
// given substrings, or "" if none.
func containsMatching(set map[string]bool, substrs ...string) string {
	for imp := range set {
		for _, s := range substrs {
			if strings.Contains(imp, s) {
				return imp
			}
		}
	}
	return ""
}

// TestHotPathDoesNotImportMgmtPackages enforces §4.1/§6.1: the hot path
// (cmd/harbor-hot) is stateless in the sense of owning no mutable PII state —
// it MAY read from the DB via internal/clients (client registry, grant store,
// session store, secret loader) but must never pull in the management-only
// WebAuthn enrollment package (internal/webauthn). That package — the
// registration/authentication ceremonies and their persistence — belongs to
// cmd/harbor-mgmt exclusively.
//
// Note: internal/identity is intentionally NOT forbidden here. It holds the
// shared PPID derivation and PairwiseSecretAAD helpers that the hot path
// legitimately depends on (via clients.DBSecretLoader → identity.PairwiseSecretAAD
// on the /token PPID-resolution path). Forbidding it would contradict the
// clients-based DB read model that §4.1/§6.1 permit.
func TestHotPathDoesNotImportMgmtPackages(t *testing.T) {
	deps := transitiveImports(t, modulePath+"/cmd/harbor-hot")

	if bad := containsMatching(deps,
		modulePath+"/internal/webauthn",
	); bad != "" {
		t.Errorf("cmd/harbor-hot transitively imports %q — the hot path must not "+
			"pull in the mgmt-only WebAuthn enrollment package (§4.1, §6.1): "+
			"internal/webauthn belongs to cmd/harbor-mgmt", bad)
	}
}

// TestOIDCCoreDoesNotImportClients enforces the dependency inversion that keeps
// internal/oidc a pure, independently-testable core (§1.7): the OIDC flow defines
// its store INTERFACES (store.go) and must never depend on their DB-backed
// implementations in internal/clients. If oidc imported clients, the core would
// transitively pull in pgx + internal/gen/db and could no longer be exercised
// without a database — collapsing the seam that lets every branch be unit-tested.
func TestOIDCCoreDoesNotImportClients(t *testing.T) {
	deps := transitiveImports(t, modulePath+"/internal/oidc")

	if bad := containsMatching(deps,
		modulePath+"/internal/clients",
	); bad != "" {
		t.Errorf("internal/oidc transitively imports %q — the pure OIDC core must not "+
			"depend on its store implementations (§1.7): clients depends on oidc, never "+
			"the reverse", bad)
	}
}

// TestClientsDoesNotImportWebAuthn keeps internal/clients usable from BOTH the
// hot path and the mgmt path. clients is the shared DB-adapter layer; if it
// imported internal/webauthn (the mgmt-only enrollment ceremonies) then the hot
// path — which legitimately depends on clients (§4.1, §6.1) — would transitively
// pull in the mgmt-only package and break TestHotPathDoesNotImportMgmtPackages.
func TestClientsDoesNotImportWebAuthn(t *testing.T) {
	deps := transitiveImports(t, modulePath+"/internal/clients")

	if bad := containsMatching(deps,
		modulePath+"/internal/webauthn",
	); bad != "" {
		t.Errorf("internal/clients transitively imports %q — the shared DB-adapter layer "+
			"must stay free of the mgmt-only WebAuthn package so the hot path can import "+
			"clients without pulling in enrollment code (§4.1, §6.1)", bad)
	}
}

// TestRegionIsolationNoCrossRegionImports documents §5.3/§5.4: region resolution
// is pure logic. It must not reach into persistence or the OIDC flow, so that
// the data-plane isolation boundary can't be eroded by an incidental import.
func TestRegionIsolationNoCrossRegionImports(t *testing.T) {
	deps := transitiveImports(t, modulePath+"/internal/region")

	if bad := containsMatching(deps,
		"github.com/jackc/pgx",
		modulePath+"/internal/gen/db",
		modulePath+"/internal/oidc",
	); bad != "" {
		t.Errorf("internal/region transitively imports %q — region resolution must stay "+
			"pure (§5.3, §5.4): no persistence, no OIDC flow", bad)
	}
}

// TestGeneratedPackagesAreImportableLeaves documents §1.3: internal/gen/** is
// generated code — a leaf that hand-written packages import, never the reverse.
// A full static "nothing generates into gen except codegen" check is out of
// scope; here we assert the generated packages parse/list cleanly so the rule is
// anchored by a present, non-flaky test (and the codegen-drift gate in
// `make generate-check` guards the generated *content*).
func TestGeneratedPackagesAreImportableLeaves(t *testing.T) {
	for _, pkg := range []string{
		modulePath + "/internal/gen/db",
		modulePath + "/internal/gen/openapi",
	} {
		if deps := transitiveImports(t, pkg); len(deps) == 0 {
			t.Errorf("generated package %s did not list — codegen output may be broken", pkg)
		}
	}
}
