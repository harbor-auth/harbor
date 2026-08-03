package arch

// Foundation F9 — architecture import-boundary fitness tests.
//
// Each test asserts a DESIGN import boundary by computing a package's full
// transitive import set and checking that forbidden packages are absent. We use
// `go list -deps` (module-aware) to compute imports; go/build does not resolve
// module dependencies, so it is unsuitable here.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/harbor-auth/harbor/internal/telemetry"
)

const modulePath = "github.com/harbor-auth/harbor"

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

var productionGraphAllowedSymbols = map[string]bool{
	// Revocation filters are deliberate hot-path caches backed by durable state.
	"InMemoryRevocationFilter":    true,
	"NewInMemoryRevocationFilter": true,
	"BloomRevocationFilter":       true,
	"NewBloomRevocationFilter":    true,
	// Local crypto remains the production implementation until the HSM work lands.
	"LocalKeyProvider":    true,
	"NewLocalKeyProvider": true,
	"LocalSigner":         true,
	"NewLocalSigner":      true,
}

func forbiddenProductionGraphSymbol(name string) bool {
	if productionGraphAllowedSymbols[name] {
		return false
	}
	lower := strings.ToLower(name)
	for _, fragment := range []string{
		"demo", "inmemory", "noop", "stub", "placeholder", "devmode", "development", "bootstrap",
	} {
		if strings.Contains(lower, fragment) {
			return true
		}
	}
	return false
}

// TestProductionCompositionRootsContainNoScaffolds prevents test helpers or
// permissive fallback implementations from becoming reachable from a shipped
// binary. It inspects only non-test source: composition-root tests may import
// internal/testsupport, but production files may not.
func TestProductionCompositionRootsContainNoScaffolds(t *testing.T) {
	root := repoRoot(t)
	for _, command := range []string{"harbor-hot", "harbor-mgmt"} {
		t.Run(command, func(t *testing.T) {
			dir := filepath.Join(root, "cmd", command)
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatalf("read composition root: %v", err)
			}
			for _, entry := range entries {
				if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
					continue
				}
				if strings.Contains(strings.ToLower(entry.Name()), "bootstrap") {
					t.Errorf("dead bootstrap source %q remains in the production composition root", entry.Name())
				}
				path := filepath.Join(dir, entry.Name())
				fset := token.NewFileSet()
				file, err := parser.ParseFile(fset, path, nil, 0)
				if err != nil {
					t.Fatalf("parse %s: %v", path, err)
				}
				for _, imp := range file.Imports {
					importPath, err := strconv.Unquote(imp.Path.Value)
					if err != nil {
						t.Fatalf("unquote import in %s: %v", path, err)
					}
					if strings.Contains(importPath, modulePath+"/internal/testsupport") {
						t.Errorf("%s imports test-only package %q", entry.Name(), importPath)
					}
				}
				ast.Inspect(file, func(node ast.Node) bool {
					switch n := node.(type) {
					case *ast.Ident:
						if forbiddenProductionGraphSymbol(n.Name) {
							t.Errorf("%s uses forbidden production scaffold symbol %q at %s", entry.Name(), n.Name, fset.Position(n.Pos()))
						}
					case *ast.BasicLit:
						if n.Kind != token.STRING {
							break
						}
						value, err := strconv.Unquote(n.Value)
						if err == nil && (value == "HARBOR_DEV_MODE" || value == "demo-client") {
							t.Errorf("%s contains forbidden production scaffold value %q at %s", entry.Name(), value, fset.Position(n.Pos()))
						}
					}
					return true
				})
			}
		})
	}
}

func TestProductionGraphExceptionsRemainAllowed(t *testing.T) {
	for symbol := range productionGraphAllowedSymbols {
		if forbiddenProductionGraphSymbol(symbol) {
			t.Errorf("documented production exception %q is forbidden", symbol)
		}
	}
	for _, symbol := range []string{"NewInMemoryStore", "noopSessionStore", "NewStubResolver", "NewPlaceholderIssuer", "runDevelopment", "bootstrapGraph", "demoClient"} {
		if !forbiddenProductionGraphSymbol(symbol) {
			t.Errorf("production scaffold %q is allowed", symbol)
		}
	}
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
// Note (N10): the original TestHotPathDoesNotImportDatabase — which forbade
// github.com/jackc/pgx and internal/gen/db from the hot path — was deliberately
// removed when cmd/harbor-hot gained DB-backed stores via internal/clients
// (PR #15). The relaxed boundary is: the hot path MUST NOT import the mgmt-only
// enrollment packages, but it MAY import pgx transitively via internal/clients
// to read the regional data plane (client registry, grants, sessions, secret
// loader). This is a security-relevant architectural decision — see
// docs/DESIGN.md §4.1 ("stateless" = owns no mutable PII state, not "no DB reads")
// and §10.
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

// TestHarborHotDoesNotImportCloudAPI enforces
// openspec/changes/harbor-cloud-management-api-contract-2ee993ea/specs/harbor-cloud-management-api/spec.md's
// "harbor-hot never exposes the contract" requirement at the strongest
// possible level: internal/cloudapi (the Harbor Cloud management API —
// session minting, namespace lifecycle, signing-key rotation) is wired only
// into cmd/harbor-mgmt, behind the private mgmt.cloudIntegration gate
// (internal/cloudapi/store.go's package doc). If cmd/harbor-hot ever
// transitively imported it, the public listener could expose /admin/v1/* by
// accident regardless of any runtime route-table check — see
// internal/oidcapi's TestHarborHotRouteTableHasNoAdminV1Path for the runtime
// half of this same invariant.
func TestHarborHotDoesNotImportCloudAPI(t *testing.T) {
	deps := transitiveImports(t, modulePath+"/cmd/harbor-hot")

	if bad := containsMatching(deps,
		modulePath+"/internal/cloudapi",
	); bad != "" {
		t.Errorf("cmd/harbor-hot transitively imports %q — the Harbor Cloud "+
			"management API contract must be reachable only from cmd/harbor-mgmt "+
			"behind mgmt.cloudIntegration, never from harbor-hot's public listener", bad)
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

// maxMetricLabelDimensions is the ceiling on how many distinct label KEYS the
// metrics facade may partition by. It keeps the label allow-list bounded: an
// unbounded, ever-growing set of dimensions is itself a cardinality risk
// (REQ-004). The current allow-list has six dimensions; the ceiling leaves
// headroom without permitting an explosion.
const maxMetricLabelDimensions = 12

// parseTelemetryFiles parses every non-test Go source file in internal/telemetry
// into ASTs. It parses files individually (rather than the deprecated
// parser.ParseDir) so the fitness test stays lint-clean.
func parseTelemetryFiles(t *testing.T) []*ast.File {
	t.Helper()
	dir := filepath.Join(repoRoot(t), "internal", "telemetry")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read internal/telemetry: %v", err)
	}
	fset := token.NewFileSet()
	var files []*ast.File
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		files = append(files, f)
	}
	if len(files) == 0 {
		t.Fatal("internal/telemetry has no non-test Go source to inspect")
	}
	return files
}

// typedStringConsts returns every string-valued const declared with the given
// named type (e.g. LabelKey), mapped from const name to its literal value.
func typedStringConsts(files []*ast.File, typeName string) map[string]string {
	out := map[string]string{}
	for _, f := range files {
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				ident, ok := vs.Type.(*ast.Ident)
				if !ok || ident.Name != typeName {
					continue
				}
				for i, nm := range vs.Names {
					if i >= len(vs.Values) {
						continue
					}
					bl, ok := vs.Values[i].(*ast.BasicLit)
					if !ok || bl.Kind != token.STRING {
						continue
					}
					val, err := strconv.Unquote(bl.Value)
					if err != nil {
						continue
					}
					out[nm.Name] = val
				}
			}
		}
	}
	return out
}

// hasConstDecl reports whether any const with the given name is declared.
func hasConstDecl(files []*ast.File, name string) bool {
	for _, f := range files {
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for _, nm := range vs.Names {
					if nm.Name == name {
						return true
					}
				}
			}
		}
	}
	return false
}

// hasTypeDecl reports whether any type with the given name is declared.
func hasTypeDecl(files []*ast.File, name string) bool {
	for _, f := range files {
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.TYPE {
				continue
			}
			for _, spec := range gd.Specs {
				if ts, ok := spec.(*ast.TypeSpec); ok && ts.Name.Name == name {
					return true
				}
			}
		}
	}
	return false
}

// piiLabelDenylist is the canonical set of PII / quasi-identifier field names
// that must NEVER appear as a metric label KEY. It reuses telemetry.DeniedFields
// (the single source of truth for known-PII keys, §6.5.7) and adds the field
// names §5 / REQ-004 call out explicitly for metrics.
func piiLabelDenylist() map[string]bool {
	deny := map[string]bool{}
	for _, f := range telemetry.DeniedFields {
		deny[f] = true
	}
	for _, f := range []string{"user_id", "userid", "email", "ppid", "ip", "sub", "subject"} {
		deny[f] = true
	}
	return deny
}

// TestMetricLabelsNoPII enforces REQ-004: the metric label allow-list
// (internal/telemetry LabelKey constants) must never source a label from a PII
// field (user_id, email, PPID, IP, subject, …), and the allow-list must stay
// bounded in cardinality.
//
// This is the CI half of the design's defence-in-depth (Decision 4): the
// phantom-typed Label already makes a PII label unexpressible in the facade;
// this test guards against a future regression where someone adds a PII-named
// dimension to the allow-list, or lets the dimension set grow unbounded.
//
//harbor:invariant INV-METRICS-NO-PII-LABELS
func TestMetricLabelsNoPII(t *testing.T) {
	files := parseTelemetryFiles(t)

	keys := typedStringConsts(files, "LabelKey")
	if len(keys) == 0 {
		t.Fatal("no LabelKey constants found in internal/telemetry — the metric label " +
			"allow-list must exist and be inspectable (REQ-001/REQ-004)")
	}

	deny := piiLabelDenylist()
	for name, value := range keys {
		if deny[value] {
			t.Errorf("metric label key %s = %q is a PII/quasi-identifier field — no metric "+
				"label may be sourced from a PII field (REQ-004)", name, value)
		}
	}

	if len(keys) > maxMetricLabelDimensions {
		t.Errorf("metric label allow-list has %d dimensions, exceeding the cardinality "+
			"ceiling of %d — the label set must stay bounded (REQ-004)",
			len(keys), maxMetricLabelDimensions)
	}
}

// TestMetricSmallNSuppressionEnforced enforces the REQ-004/REQ-005 half of
// Decision 4/5: even an allow-listed label can be a quasi-identifier, so the
// facade MUST carry a small-n suppression mechanism (a small-count floor and the
// suppressor that buckets rare quasi-identifier combinations). This structural
// check fails if that machinery is ever removed, so the aggregate-only
// guarantee cannot silently regress into per-user rows.
//
//harbor:invariant INV-METRICS-AGGREGATE-ONLY
func TestMetricSmallNSuppressionEnforced(t *testing.T) {
	files := parseTelemetryFiles(t)

	if !hasConstDecl(files, "smallCountFloor") {
		t.Error("internal/telemetry must define smallCountFloor — quasi-identifier labels " +
			"require a small-count floor so no series is emitted at a deanonymising count " +
			"of 1 (REQ-004/REQ-005)")
	}
	if !hasTypeDecl(files, "suppressor") {
		t.Error("internal/telemetry must define the suppressor that buckets rare " +
			"quasi-identifier label combinations, bounding their cardinality (REQ-004/REQ-005)")
	}
}
