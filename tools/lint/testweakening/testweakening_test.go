package main

import (
	"strings"
	"testing"
)

// analyze operates on a unified=0 diff string. These fixtures are hand-built
// with realistic `--- a/…` / `+++ b/…` headers and `@@` hunk markers so the
// parser resolves curFile exactly as it does on a real `git diff --unified=0`.

// countHigh / countAll summarise a finding slice.
func countAll(fs []finding) int { return len(fs) }
func countHigh(fs []finding) int {
	n := 0
	for _, f := range fs {
		if f.high {
			n++
		}
	}
	return n
}

func hasMsgContaining(fs []finding, sub string) bool {
	for _, f := range fs {
		if strings.Contains(f.msg, sub) {
			return true
		}
	}
	return false
}

func hasFile(fs []finding, file string) bool {
	for _, f := range fs {
		if f.file == file {
			return true
		}
	}
	return false
}

// TestAnalyzeNettingAndSignals is the core table: it exercises the cross-file
// netting fix plus every other tamper signal the tool emits.
func TestAnalyzeNettingAndSignals(t *testing.T) {
	cases := []struct {
		name      string
		diff      string
		wantTotal int
		wantHigh  int
		mustHave  string // substring that must appear in some finding msg ("" = skip)
	}{
		{
			name: "same-file rename nets out",
			diff: "--- a/pkg/foo_test.go\n" +
				"+++ b/pkg/foo_test.go\n" +
				"@@ -1 +1 @@\n" +
				"-func TestFoo(t *testing.T) {\n" +
				"+func TestFoo(t *testing.T) {\n",
			wantTotal: 0,
		},
		{
			// The exact regression this PR fixes: TestResolve moved from
			// region_test.go into a new resolve_test.go — per-file netting flagged
			// it; global netting must not.
			name: "cross-file move nets out",
			diff: "--- a/internal/region/region_test.go\n" +
				"+++ b/internal/region/region_test.go\n" +
				"@@ -5,3 +0,0 @@\n" +
				"-func TestResolve(t *testing.T) {\n" +
				"--- a/internal/region/resolve_test.go\n" +
				"+++ b/internal/region/resolve_test.go\n" +
				"@@ -0,0 +1,3 @@\n" +
				"+func TestResolve(t *testing.T) {\n",
			wantTotal: 0,
		},
		{
			name: "genuine deletion flags",
			diff: "--- a/pkg/foo_test.go\n" +
				"+++ b/pkg/foo_test.go\n" +
				"@@ -1,3 +0,0 @@\n" +
				"-func TestGone(t *testing.T) {\n",
			wantTotal: 1,
			wantHigh:  1,
			mustHave:  "TestGone",
		},
		{
			name: "one moved, one deleted -> only the deletion flags",
			diff: "--- a/pkg/a_test.go\n" +
				"+++ b/pkg/a_test.go\n" +
				"@@ -1,6 +0,0 @@\n" +
				"-func TestMoved(t *testing.T) {\n" +
				"-func TestDeleted(t *testing.T) {\n" +
				"--- a/pkg/b_test.go\n" +
				"+++ b/pkg/b_test.go\n" +
				"@@ -0,0 +1,3 @@\n" +
				"+func TestMoved(t *testing.T) {\n",
			wantTotal: 1,
			wantHigh:  1,
			mustHave:  "TestDeleted",
		},
		{
			name: "new t.Skip is a (low) finding",
			diff: "--- a/pkg/foo_test.go\n" +
				"+++ b/pkg/foo_test.go\n" +
				"@@ -0,0 +1 @@\n" +
				"+\tt.Skip(\"flaky\")\n",
			wantTotal: 1,
			wantHigh:  0,
			mustHave:  "Skip",
		},
		{
			name: "naked nolint is a (low) finding",
			diff: "--- a/pkg/foo.go\n" +
				"+++ b/pkg/foo.go\n" +
				"@@ -0,0 +1 @@\n" +
				"+\tx := f() //nolint\n",
			wantTotal: 1,
			wantHigh:  0,
			mustHave:  "nolint",
		},
		{
			name: "justified nolint nets out",
			diff: "--- a/pkg/foo.go\n" +
				"+++ b/pkg/foo.go\n" +
				"@@ -0,0 +1 @@\n" +
				"+\tx := f() //nolint:errcheck // best-effort cleanup\n",
			wantTotal: 0,
		},
		{
			name: "removed invariant tag flags high",
			diff: "--- a/internal/oidc/token.go\n" +
				"+++ b/internal/oidc/token.go\n" +
				"@@ -1 +0,0 @@\n" +
				"-\t//harbor:invariant INV-TOKEN-01\n",
			wantTotal: 1,
			wantHigh:  1,
			mustHave:  "invariant",
		},
		{
			name: "frozen vector change without marker flags high",
			diff: "--- a/internal/crypto/testdata/envelope_vectors.json\n" +
				"+++ b/internal/crypto/testdata/envelope_vectors.json\n" +
				"@@ -1 +1 @@\n" +
				"-  \"ct\": \"aaa\"\n" +
				"+  \"ct\": \"bbb\"\n",
			wantTotal: 1,
			wantHigh:  1,
			mustHave:  "frozen golden vector",
		},
		{
			name: "frozen vector change WITH marker nets out",
			diff: "--- a/internal/crypto/testdata/envelope_vectors.json\n" +
				"+++ b/internal/crypto/testdata/envelope_vectors.json\n" +
				"@@ -1,2 +1,2 @@\n" +
				"-  \"ct\": \"aaa\"\n" +
				"+  \"ct\": \"bbb\"\n" +
				"+  \"_note\": \"VECTOR-CHANGE: rotated KEK\"\n",
			wantTotal: 0,
		},
		{
			name: "excluded paths (e2e, tools/lint) produce no findings",
			diff: "--- a/e2e/flow_test.go\n" +
				"+++ b/e2e/flow_test.go\n" +
				"@@ -1,2 +1 @@\n" +
				"-func TestExcludedE2E(t *testing.T) {\n" +
				"+\tt.Skip(\"no docker\")\n" +
				"--- a/tools/lint/foo_test.go\n" +
				"+++ b/tools/lint/foo_test.go\n" +
				"@@ -1 +0,0 @@\n" +
				"-func TestExcludedTool(t *testing.T) {\n",
			wantTotal: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := analyze(tc.diff)
			if countAll(got) != tc.wantTotal {
				t.Fatalf("total findings = %d, want %d\nfindings: %+v", countAll(got), tc.wantTotal, got)
			}
			if tc.wantHigh != 0 && countHigh(got) != tc.wantHigh {
				t.Fatalf("high findings = %d, want %d\nfindings: %+v", countHigh(got), tc.wantHigh, got)
			}
			if tc.mustHave != "" && !hasMsgContaining(got, tc.mustHave) {
				t.Fatalf("no finding msg contains %q\nfindings: %+v", tc.mustHave, got)
			}
		})
	}
}

// TestDeletionNamesItsFile pins that a genuine deletion reports the file it left,
// which is what lets a human adjudicate deletion vs move.
func TestDeletionNamesItsFile(t *testing.T) {
	diff := "--- a/internal/region/region_test.go\n" +
		"+++ b/internal/region/region_test.go\n" +
		"@@ -1 +0,0 @@\n" +
		"-func TestReallyGone(t *testing.T) {\n"
	got := analyze(diff)
	if !hasFile(got, "internal/region/region_test.go") {
		t.Fatalf("deletion finding did not name the source file; findings: %+v", got)
	}
	if !hasMsgContaining(got, "TestReallyGone") {
		t.Fatalf("deletion finding did not name the func; findings: %+v", got)
	}
}

// TestCrossFileMoveIsNetZeroNotFinding guards the fix directly: a moved test is
// never a finding (a human still sees the stdout relocation note, which is not
// part of the finding set).
func TestCrossFileMoveIsNetZeroNotFinding(t *testing.T) {
	diff := "--- a/internal/region/region_test.go\n" +
		"+++ b/internal/region/region_test.go\n" +
		"@@ -5,3 +0,0 @@\n" +
		"-func TestParse(t *testing.T) {\n" +
		"--- a/internal/region/parse_test.go\n" +
		"+++ b/internal/region/parse_test.go\n" +
		"@@ -0,0 +1,3 @@\n" +
		"+func TestParse(t *testing.T) {\n"
	if got := analyze(diff); len(got) != 0 {
		t.Fatalf("cross-file move produced findings (want none): %+v", got)
	}
}
