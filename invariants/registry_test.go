package invariants

// Foundation F1 — the meta-test that makes the invariants registry EXECUTABLE.
//
// It parses registry.yaml (with a tiny, dependency-free parser so this test
// pulls in no third-party YAML library) and asserts, for every invariant:
//
//   1. structural validity — id matches ^INV-[A-Z0-9-]+$, and title,
//      design_refs, and enforced_by are all non-empty;
//   2. every `enforced_by: pkg:TestName` names a REAL `func TestName(` inside a
//      *_test.go under that package; and
//   3. a `//harbor:invariant <id>` comment tag physically exists somewhere in
//      the repo (put on the enforcing test), so the invariant is anchored in
//      code, not just prose.
//
// If any of these fail, the build fails: an invariant with no live, tagged test
// is a bug. This is the keystone the other foundations lean on.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// invariant is one registry entry (only the fields the meta-test needs).
type invariant struct {
	ID          string
	Title       string
	DesignRefs  []string
	Description string
	EnforcedBy  []string
}

var (
	idRE     = regexp.MustCompile(`^INV-[A-Z0-9-]+$`)
	testFnRE = regexp.MustCompile(`func (Test[A-Za-z0-9_]+)\s*\(`)
	tagRE    = regexp.MustCompile(`//harbor:invariant\s+(INV-[A-Z0-9-]+)`)
	dashIDRE = regexp.MustCompile(`^\s*-\s+id:\s*(.+?)\s*$`)
	fieldRE  = regexp.MustCompile(`^\s+([a-z_]+):\s*(.+?)\s*$`)
	skipDirs = map[string]bool{".git": true, "node_modules": true, "vendor": true, "bin": true}
)

func TestRegistryInvariantsAreEnforced(t *testing.T) {
	root := repoRoot(t)

	invs := parseRegistry(t, filepath.Join(root, "invariants", "registry.yaml"))
	if len(invs) == 0 {
		t.Fatal("registry.yaml parsed to zero invariants — parser or file is broken")
	}

	testsByPkg, tags := scanRepo(t, root)

	seenIDs := map[string]bool{}
	for _, inv := range invs {
		// (1) structural validity.
		if !idRE.MatchString(inv.ID) {
			t.Errorf("invariant id %q does not match %s", inv.ID, idRE)
		}
		if seenIDs[inv.ID] {
			t.Errorf("duplicate invariant id %q", inv.ID)
		}
		seenIDs[inv.ID] = true
		if inv.Title == "" {
			t.Errorf("%s: missing title", inv.ID)
		}
		if len(inv.DesignRefs) == 0 {
			t.Errorf("%s: missing design_refs", inv.ID)
		}
		if len(inv.EnforcedBy) == 0 {
			t.Errorf("%s: has no enforced_by tests — an invariant with no test is a bug", inv.ID)
		}

		// (3) a physical `//harbor:invariant <id>` tag must exist.
		if !tags[inv.ID] {
			t.Errorf("%s: no `//harbor:invariant %s` tag found anywhere in the repo — "+
				"tag the enforcing test so the invariant is anchored in code", inv.ID, inv.ID)
		}

		// (2) each enforced_by test must actually exist under its package.
		for _, ref := range inv.EnforcedBy {
			pkg, name, ok := strings.Cut(ref, ":")
			if !ok {
				t.Errorf("%s: enforced_by entry %q is not in pkg:TestName form", inv.ID, ref)
				continue
			}
			pkg = filepath.ToSlash(strings.TrimSpace(pkg))
			name = strings.TrimSpace(name)
			if names, ok := testsByPkg[pkg]; !ok || !names[name] {
				t.Errorf("%s: enforced_by %s:%s not found — no `func %s(` in a *_test.go under %s/",
					inv.ID, pkg, name, name, pkg)
			}
		}
	}
}

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

// parseRegistry reads registry.yaml with a minimal, format-specific parser that
// understands exactly the flat shape this registry uses (see registry.yaml's
// header). It deliberately avoids a YAML dependency.
func parseRegistry(t *testing.T, path string) []invariant {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	var out []invariant
	var cur *invariant
	flush := func() {
		if cur != nil {
			out = append(out, *cur)
			cur = nil
		}
	}

	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") || strings.TrimSpace(line) == "" {
			continue
		}
		if m := dashIDRE.FindStringSubmatch(line); m != nil {
			flush()
			cur = &invariant{ID: unquote(m[1])}
			continue
		}
		if cur == nil {
			continue // skip the top-level `invariants:` key etc.
		}
		if m := fieldRE.FindStringSubmatch(line); m != nil {
			key, val := m[1], m[2]
			switch key {
			case "title":
				cur.Title = unquote(val)
			case "description":
				cur.Description = unquote(val)
			case "design_refs":
				cur.DesignRefs = splitInline(val)
			case "enforced_by":
				cur.EnforcedBy = splitInline(val)
			}
		}
	}
	flush()
	return out
}

// splitInline parses an inline YAML list like `[a, b, c]` into trimmed entries.
func splitInline(v string) []string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "[")
	v = strings.TrimSuffix(v, "]")
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = unquote(strings.TrimSpace(p)); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && (s[0] == '"' || s[0] == '\'') && s[len(s)-1] == s[0] {
		return s[1 : len(s)-1]
	}
	return s
}

// scanRepo walks the tree once, collecting (a) every test function keyed by its
// package path (slash-separated, relative to root) and (b) the set of invariant
// ids referenced by `//harbor:invariant` tags anywhere in the repo.
func scanRepo(t *testing.T, root string) (testsByPkg map[string]map[string]bool, tags map[string]bool) {
	t.Helper()
	testsByPkg = map[string]map[string]bool{}
	tags = map[string]bool{}

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		src := string(data)

		for _, m := range tagRE.FindAllStringSubmatch(src, -1) {
			tags[m[1]] = true
		}

		if strings.HasSuffix(path, "_test.go") {
			rel, err := filepath.Rel(root, filepath.Dir(path))
			if err != nil {
				return err
			}
			pkg := filepath.ToSlash(rel)
			for _, m := range testFnRE.FindAllStringSubmatch(src, -1) {
				if testsByPkg[pkg] == nil {
					testsByPkg[pkg] = map[string]bool{}
				}
				testsByPkg[pkg][m[1]] = true
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk repo: %v", err)
	}
	return testsByPkg, tags
}
