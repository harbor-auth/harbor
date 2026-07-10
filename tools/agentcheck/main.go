// Command agentcheck is Harbor's single, agent-legible verdict (Foundation F6).
//
// Agents (and humans) misread log soup. This tool runs the fixed check suite as
// a sequence of subprocesses, classifies each unambiguously as pass|fail|error
// (a SKIPPED check is NEVER counted as a pass), and writes a structured
// check-results.json plus a one-line-per-check human summary. `make agent-check`
// invokes it inside the pinned toolchain (Foundation F3), so the local and CI
// verdicts are identical by construction.
//
// The suite includes the lint checks (golangci-lint, spectral, buf lint), which
// are provided by the pinned toolchain — so the verdict is authoritative only
// inside `nix develop`. Codegen-drift is intentionally NOT here: it needs git
// history, so it runs as an explicit CI step (like tamper-check/coverage-ratchet)
// to keep agent-check git-history-free.
//
// Usage:
//
//	go run ./tools/agentcheck [--out check-results.json]
//
// Exit code is non-zero unless every check passed.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// schema is the versioned contract of check-results.json so downstream readers
// (CI sticky comment, F7) can evolve safely.
const schema = "harbor.agent-check/v1"

// check is one entry in the suite. If special is set, the check is a
// list-style tool (gofmt -l) where NON-EMPTY output means failure even though
// the process exits 0.
type check struct {
	name    string
	argv    []string
	special bool
}

// suite is the ordered, exhaustive list of checks. Order is cheap→broad. The
// invariants meta-test is listed explicitly even though `go test ./...` also
// covers it — an agent reading the report should see it called out by name. The
// lint checks (golangci-lint, buf lint) come before the docs checks; they need
// the pinned toolchain (flake.nix, F3), and a missing tool is classified as
// `error` by run() — never a silent pass (fail-closed; no SOFT escape here). The
// docs integrity checks (docs-design-refs, docs-links) run last; they are fast
// Python scripts with no git-history dependency.
//
// NOTE: spectral (OpenAPI spec-lint) is intentionally NOT in this suite. nixpkgs
// removed the `spectral-cli` package, so it can no longer be guaranteed present
// inside `nix develop`; leaving it here would make it a permanent `error` (a
// missing tool is never a silent pass). It now runs as a dedicated CI-side step
// via `npx @stoplight/spectral-cli@6.16.1` (see .github/workflows/ci.yml), the
// same version-pinned command `make validate` uses locally.
var suite = []check{
	{name: "gofmt", argv: []string{"gofmt", "-l", "."}, special: true},
	{name: "build", argv: []string{"go", "build", "./..."}},
	{name: "vet", argv: []string{"go", "vet", "./..."}},
	{name: "test", argv: []string{"go", "test", "./..."}},
	{name: "invariants", argv: []string{"go", "test", "./invariants/..."}},
	{name: "piifields", argv: []string{"go", "run", "./tools/lint/piifields", "./..."}},
	{name: "golangci-lint", argv: []string{"golangci-lint", "run"}},
	{name: "buf-lint", argv: []string{"buf", "lint"}},
	// Docs integrity checks (python3, no git-history dependency — same as the
	// checks above). Two separate entries give granular pass|fail per concern.
	{name: "docs-design-refs", argv: []string{"python3", "tools/check-design-refs.py"}},
	{name: "docs-links", argv: []string{"python3", "tools/check-doc-links.py"}},
}

// checkResult is the serialized outcome of one check.
type checkResult struct {
	Name       string `json:"name"`
	Status     string `json:"status"` // pass | fail | error
	ExitCode   int    `json:"exit_code"`
	DurationMS int64  `json:"duration_ms"`
	OutputTail string `json:"output_tail"`
}

// report is the full check-results.json document.
type report struct {
	Schema      string        `json:"schema"`
	GeneratedAt string        `json:"generated_at"`
	Overall     string        `json:"overall"` // pass | fail
	Checks      []checkResult `json:"checks"`
}

const outputTailBytes = 2000

func main() {
	out := flag.String("out", "check-results.json", "path to write the structured check-results JSON")
	flag.Parse()

	rep := report{
		Schema:      schema,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Overall:     "pass",
	}

	for _, c := range suite {
		res := run(c)
		rep.Checks = append(rep.Checks, res)
		if res.Status != "pass" {
			rep.Overall = "fail"
		}
	}

	if err := writeReport(*out, rep); err != nil {
		fmt.Fprintf(os.Stderr, "agentcheck: failed to write %s: %v\n", *out, err)
		os.Exit(2)
	}

	// Human summary — one line per check, then the overall verdict.
	for _, r := range rep.Checks {
		fmt.Printf("  %-5s %-14s (%dms)\n", strings.ToUpper(r.Status), r.name(), r.DurationMS)
	}
	fmt.Printf("==> agent-check: %s (%s)\n", strings.ToUpper(rep.Overall), *out)

	if rep.Overall != "pass" {
		os.Exit(1)
	}
}

// name is a tiny accessor so the summary loop reads cleanly.
func (r checkResult) name() string { return r.Name }

// run executes a single check and classifies the outcome.
func run(c check) checkResult {
	start := time.Now()
	cmd := exec.Command(c.argv[0], c.argv[1:]...)
	combined, err := cmd.CombinedOutput()
	dur := time.Since(start).Milliseconds()

	res := checkResult{
		Name:       c.name,
		DurationMS: dur,
		OutputTail: tail(string(combined), outputTailBytes),
	}

	// The tool could not be launched at all (missing binary, etc.).
	if _, isExit := err.(*exec.ExitError); err != nil && !isExit {
		res.Status = "error"
		res.ExitCode = -1
		return res
	}

	res.ExitCode = cmd.ProcessState.ExitCode()

	// gofmt -l exits 0 but lists unformatted files on stdout: non-empty == fail.
	if c.special {
		if strings.TrimSpace(string(combined)) != "" {
			res.Status = "fail"
		} else {
			res.Status = "pass"
		}
		return res
	}

	if res.ExitCode == 0 {
		res.Status = "pass"
	} else {
		res.Status = "fail"
	}
	return res
}

// tail returns the last n bytes of s (rune-safe on the boundary is unnecessary
// here; this is diagnostic output).
func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "…" + s[len(s)-n:]
}

func writeReport(path string, rep report) error {
	data, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o644)
}
