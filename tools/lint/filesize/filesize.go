// Command filesize is Harbor's small-files principle checker (§1.10).
//
// §1.10 states each file should target one concern and stay small — design
// docs specifically target ~2,000 words. Like §1.11 (error-handling) before
// automation, this was previously enforced by prose + review-time judgment
// only ("the @harbor-reviewer agent flags files that grow large"), which is
// the exact silent-failure shape §1.11 exists to prevent: a principle nothing
// mechanically checks is a principle that quietly erodes.
//
// This tool enforces two thresholds:
//   - Go source files (excluding generated/vendored code) must stay under a
//     line-count budget — a higher budget for _test.go files, since table-driven
//     tests legitimately run longer than the logic they exercise.
//   - docs/design/**/*.md files must stay under a word-count budget, matching
//     the ~2,000-word target stated in §1.10 and the design docs' own headers.
//
// It is stdlib-only (bufio + filepath.WalkDir) so it runs anywhere the pinned
// toolchain does (Foundation F3). It is wired into `make agent-check`
// (Foundation F6) so the check is part of the single trusted verdict.
//
// Usage:
//
//	go run ./tools/lint/filesize          # scan from cwd
package main

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Thresholds. Chosen with headroom over the largest files at the time this
// tool was introduced (largest non-test .go: internal/oidc/service.go @ 296
// lines; largest _test.go: tools/lint/testweakening/testweakening.go @ 275
// lines viewed as source, e2e/flow_test.go @ 266; largest docs/design/*.md:
// docs/design/flows/error-cases.md @ 1,106 words) — flagging real growth, not
// today's status quo.
//
// RATCHET NOTE: like Makefile's COVERAGE_FLOOR (F5), these are a ceiling that
// should only ever get stricter over time as files are kept lean. If a file
// legitimately needs to grow past the threshold, the correct response is to
// split it along a package/file boundary (§1.10), not raise the number.
const (
	maxNonTestGoLines = 400
	maxTestGoLines    = 500
	maxDesignDocWords = 2000
)

type finding struct {
	path  string
	count int
	limit int
	unit  string // "lines" or "words"
}

func main() {
	var findings []finding

	goFindings, err := scanGoFiles(".")
	if err != nil {
		fmt.Fprintf(os.Stderr, "filesize: error scanning Go files: %v\n", err)
		os.Exit(1)
	}
	findings = append(findings, goFindings...)

	docFindings, err := scanDesignDocs("docs/design")
	if err != nil {
		fmt.Fprintf(os.Stderr, "filesize: error scanning docs/design: %v\n", err)
		os.Exit(1)
	}
	findings = append(findings, docFindings...)

	if len(findings) == 0 {
		fmt.Println("filesize: clean — no files exceed the §1.10 small-files thresholds.")
		os.Exit(0)
	}

	fmt.Fprintf(os.Stderr, "filesize: %d file(s) exceed the §1.10 small-files thresholds.\n", len(findings))
	fmt.Fprintf(os.Stderr, "A large file mixes concerns — split along a package/file boundary (see docs/design/principles/skills-and-small-files.md §1.10).\n\n")
	for _, f := range findings {
		fmt.Fprintf(os.Stderr, "  %s: %d %s (limit %d)\n", f.path, f.count, f.unit, f.limit)
	}
	os.Exit(1)
}

// skipDir reports whether a directory should not be walked.
func skipDir(name string) bool {
	switch name {
	case ".git", "vendor", "node_modules", "testdata":
		return true
	}
	return false
}

// scanGoFiles walks root for *.go files (excluding generated/vendored code)
// and flags any whose line count exceeds the relevant threshold.
func scanGoFiles(root string) ([]finding, error) {
	var out []finding
	if err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil //nolint:nilerr // WalkDir idiom: skip unreadable entries, keep walking
		}
		if d.IsDir() {
			if skipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || skipGoFile(path) {
			return nil
		}
		lines, err := countLines(path)
		if err != nil {
			// Read errors are the compiler's job; skip the file.
			return nil //nolint:nilerr // intentional: individual unreadable files don't abort the scan
		}
		limit := maxNonTestGoLines
		if strings.HasSuffix(path, "_test.go") {
			limit = maxTestGoLines
		}
		if lines > limit {
			out = append(out, finding{path: path, count: lines, limit: limit, unit: "lines"})
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("walking %s: %w", root, err)
	}
	return out, nil
}

// skipGoFile reports whether a .go file is exempt: generated code, which is
// machine-written and not subject to the hand-authored small-files principle.
func skipGoFile(path string) bool {
	return strings.Contains(filepath.ToSlash(path), "internal/gen/")
}

// scanDesignDocs walks root for *.md files and flags any whose word count
// exceeds the design-doc budget.
func scanDesignDocs(root string) ([]finding, error) {
	var out []finding
	if err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil //nolint:nilerr // WalkDir idiom: skip unreadable entries, keep walking
		}
		if d.IsDir() {
			if skipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".md") {
			return nil
		}
		words, err := countWords(path)
		if err != nil {
			return nil //nolint:nilerr // intentional: individual unreadable files don't abort the scan
		}
		if words > maxDesignDocWords {
			out = append(out, finding{path: path, count: words, limit: maxDesignDocWords, unit: "words"})
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("walking %s: %w", root, err)
	}
	return out, nil
}

// countLines returns the number of newline-terminated lines in path.
func countLines(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close() //nolint:errcheck // deferred os.File.Close on a read-only file; see error-handling.md §1.11

	n := 0
	scanner := bufio.NewScanner(f)
	// Source files can have long generated-looking lines even outside
	// internal/gen/ (e.g. long string literals); grow the buffer so a single
	// long line doesn't abort the scan.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		n++
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	return n, nil
}

// countWords returns the number of whitespace-separated words in path.
func countWords(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close() //nolint:errcheck // deferred os.File.Close on a read-only file; see error-handling.md §1.11

	n := 0
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	scanner.Split(bufio.ScanWords)
	for scanner.Scan() {
		n++
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	return n, nil
}
