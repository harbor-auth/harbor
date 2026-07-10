// Command testweakening is Harbor's anti-Goodhart tamper detector (Foundation F5).
//
// Weakening a check to make a build go green is the Goodhart failure mode: the
// metric (green CI) is satisfied while the target (actually-correct, actually-
// protected code) is abandoned. This tool inspects the diff against a base and
// flags the tell-tale moves:
//
//   - a deleted test / benchmark / fuzz function (fewer tests = weaker net);
//   - a dropped `//harbor:invariant INV-XXX` tag (an invariant losing its anchor);
//   - a newly-added `t.Skip(` / `t.SkipNow(` (a test being silenced);
//   - a naked `//nolint` with no linter + reason (a lint being muzzled);
//   - a modification to a frozen golden vector (*_vectors.json) without the
//     `VECTOR-CHANGE:` review marker.
//
// It is stdlib-only and shells out to `git diff` (no network). CI (Foundation
// F7) runs it with the real PR base, and CODEOWNERS on the protected paths gives
// it teeth: a reviewer must sign off on any legitimate weakening.
//
// Usage:
//
//	go run ./tools/lint/testweakening [--base origin/main]
//
// The base may also be set via the BASE env var. If no baseline is available
// (e.g. a fresh clone with no upstream), it prints a note and exits 0 so it
// never blocks work that has nothing to compare against.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
)

var (
	testFuncRE   = regexp.MustCompile(`^func ((Test|Benchmark|Fuzz)[A-Za-z0-9_]*)\s*\(`)
	invariantRE  = regexp.MustCompile(`//harbor:invariant\s+INV-[A-Z0-9-]+`)
	skipRE       = regexp.MustCompile(`\.Skip(Now)?\s*\(`)
	vectorFileRE = regexp.MustCompile(`testdata/.*vectors.*\.json$`)
	// A justified nolint looks like `//nolint:linter // reason`. Anything else
	// (bare `//nolint`, or `//nolint:linter` with no reason) is "naked".
	justifiedNolintRE = regexp.MustCompile(`//nolint:[a-zA-Z0-9_,-]+\s+//\s*\S`)
	nolintRE          = regexp.MustCompile(`//nolint`)
)

// finding is one detected tamper signal. high findings are always failures.
type finding struct {
	file string
	msg  string
	high bool
}

func main() {
	base := os.Getenv("BASE")
	if base == "" {
		base = "origin/main"
	}
	for i := 1; i < len(os.Args); i++ {
		if os.Args[i] == "--base" && i+1 < len(os.Args) {
			base = os.Args[i+1]
		} else if strings.HasPrefix(os.Args[i], "--base=") {
			base = strings.TrimPrefix(os.Args[i], "--base=")
		}
	}

	diff, ok := gitDiff(base)
	if !ok {
		fmt.Printf("testweakening: no usable git baseline (%q) — nothing to compare; skipping.\n", base)
		os.Exit(0)
	}

	findings := analyze(diff)
	if len(findings) == 0 {
		fmt.Println("testweakening: clean — no test-weakening signals in the diff.")
		os.Exit(0)
	}

	var failed bool
	for _, f := range findings {
		sev := "WARN"
		if f.high {
			sev = "FAIL"
			failed = true
		}
		fmt.Fprintf(os.Stderr, "%s %s: %s\n", sev, f.file, f.msg)
	}
	fmt.Fprintf(os.Stderr, "\ntestweakening: %d finding(s) — weakening a check requires an explicit, reviewed change (F5).\n", len(findings))
	// Warnings (skips / naked nolint) also fail: they must be justified/removed.
	_ = failed
	os.Exit(1)
}

// gitDiff returns the unified=0 diff of the working tree against base. It first
// verifies base resolves to a commit; if not, it tries a bare `git diff` (any
// uncommitted changes) and, failing that, reports no baseline.
func gitDiff(base string) (string, bool) {
	if commitExists(base) {
		if out, err := run("git", "diff", "--unified=0", base); err == nil {
			return out, true
		}
	}
	// Fallback: uncommitted working-tree changes only (still catches local tampering).
	if out, err := run("git", "diff", "--unified=0"); err == nil && strings.TrimSpace(out) != "" {
		fmt.Printf("testweakening: base %q not found — falling back to uncommitted working-tree diff.\n", base)
		return out, true
	}
	return "", false
}

func commitExists(ref string) bool {
	_, err := run("git", "rev-parse", "--verify", "--quiet", ref+"^{commit}")
	return err == nil
}

func run(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	return string(out), err
}

// analyze parses a unified=0 diff and collects tamper findings.
func analyze(diff string) []finding {
	var findings []finding

	// Per-file sets of removed / added test-function names. A pure rename that
	// re-adds the same name nets out; a genuine deletion surfaces by name.
	removedTests := map[string]map[string]bool{}
	addedTests := map[string]map[string]bool{}
	fileOrder := []string{}
	seenFile := map[string]bool{}

	curFile := ""
	for _, line := range strings.Split(diff, "\n") {
		switch {
		case strings.HasPrefix(line, "+++ "):
			curFile = stripDiffPath(strings.TrimPrefix(line, "+++ "))
			// Exclude the linter's own source tree — it legitimately contains the
			// exact patterns it detects (regex literals, doc comments) and should
			// not be flagged as a weakening signal.
			if strings.HasPrefix(curFile, "tools/lint/") || strings.HasPrefix(curFile, "tools/agentcheck/") {
				curFile = ""
			}
			if curFile != "" && !seenFile[curFile] {
				seenFile[curFile] = true
				fileOrder = append(fileOrder, curFile)
			}
			continue
		case strings.HasPrefix(line, "--- "):
			// Old-side header; keep curFile from the +++ line (set on same hunk).
			continue
		case strings.HasPrefix(line, "@@"), strings.HasPrefix(line, "diff --git"), strings.HasPrefix(line, "index "):
			continue
		}
		if curFile == "" {
			continue
		}

		added := strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++")
		removed := strings.HasPrefix(line, "-") && !strings.HasPrefix(line, "---")
		if !added && !removed {
			continue
		}
		content := line[1:]

		// (1) removed / added test-function names (deletion adjudication).
		if m := testFuncRE.FindStringSubmatch(strings.TrimSpace(content)); m != nil {
			name := m[1]
			if removed {
				if removedTests[curFile] == nil {
					removedTests[curFile] = map[string]bool{}
				}
				removedTests[curFile][name] = true
			} else {
				if addedTests[curFile] == nil {
					addedTests[curFile] = map[string]bool{}
				}
				addedTests[curFile][name] = true
			}
		}

		// (2) dropped invariant tag.
		if removed && invariantRE.MatchString(content) {
			findings = append(findings, finding{
				file: curFile,
				msg:  "removed a //harbor:invariant tag — an invariant is losing its enforcing anchor",
				high: true,
			})
		}

		// (3) new skip.
		if added && skipRE.MatchString(content) {
			findings = append(findings, finding{
				file: curFile,
				msg:  "adds a t.Skip/SkipNow — silencing a test; justify or remove",
				high: false,
			})
		}

		// (4) naked nolint.
		if added && nolintRE.MatchString(content) && !justifiedNolintRE.MatchString(content) {
			findings = append(findings, finding{
				file: curFile,
				msg:  "adds a naked //nolint — use //nolint:<linter> // <reason>",
				high: false,
			})
		}

		// (5) frozen-vector change (either side).
		if vectorFileRE.MatchString(curFile) && !strings.Contains(diff, "VECTOR-CHANGE:") {
			findings = append(findings, finding{
				file: curFile,
				msg:  "modifies a frozen golden vector — requires a VECTOR-CHANGE: PR trailer + human review",
				high: true,
			})
		}
	}

	// Removed test functions not re-added in the same file (deterministic order).
	// Listing names lets a human adjudicate a rename vs a real deletion.
	for _, f := range fileOrder {
		removed := removedTests[f]
		if len(removed) == 0 {
			continue
		}
		added := addedTests[f]
		var removedOnly []string
		for name := range removed {
			if !added[name] {
				removedOnly = append(removedOnly, name)
			}
		}
		if len(removedOnly) == 0 {
			continue
		}
		sort.Strings(removedOnly)
		findings = append(findings, finding{
			file: f,
			msg:  fmt.Sprintf("removed test/benchmark/fuzz function(s): %s", strings.Join(removedOnly, ", ")),
			high: true,
		})
	}

	// De-duplicate frozen-vector findings (one per file is enough).
	return dedup(findings)
}

func dedup(in []finding) []finding {
	seen := map[string]bool{}
	var out []finding
	for _, f := range in {
		key := f.file + "|" + f.msg
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, f)
	}
	return out
}

// stripDiffPath turns a diff header path like `b/pkg/foo.go` (optionally with a
// trailing tab and timestamp) into `pkg/foo.go`. `/dev/null` becomes "".
func stripDiffPath(p string) string {
	p = strings.TrimSpace(p)
	if i := strings.IndexByte(p, '\t'); i >= 0 {
		p = p[:i]
	}
	if p == "/dev/null" {
		return ""
	}
	p = strings.TrimPrefix(p, "a/")
	p = strings.TrimPrefix(p, "b/")
	return p
}
