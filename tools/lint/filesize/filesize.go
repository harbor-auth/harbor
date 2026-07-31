// Command filesize is Harbor's small-files principle checker (§1.10).
//
// §1.10 states each file should target one concern and stay small — design
// docs specifically target ~2,000 words. Like §1.11 (error-handling) before
// automation, this was previously enforced by prose + review-time judgment
// only ("the @harbor-reviewer agent flags files that grow large"), which is
// the exact silent-failure shape §1.11 exists to prevent: a principle nothing
// mechanically checks is a principle that quietly erodes.
//
// This tool enforces three thresholds:
//   - Go source files (excluding generated/vendored code) must stay under a
//     line-count budget — a higher budget for _test.go files, since table-driven
//     tests legitimately run longer than the logic they exercise.
//   - docs/design/**/*.md files must stay under a word-count budget, matching
//     the ~2,000-word target stated in §1.10 and the design docs' own headers.
//   - Every file tracked in git must stay under a byte-size budget. A committed
//     binary is a supply-chain smell: nobody reviews it and it is not rebuilt
//     from source on every CI run. `git ls-files` enumerates tracked files;
//     any file that exceeds maxTrackedFileBytes AND looks binary (NUL byte in
//     the first 8 KiB) is flagged. Fail-closed: if git is unavailable the check
//     errors rather than silently passing.
//
// It is stdlib-only (bufio + filepath.WalkDir + os/exec) so it runs anywhere
// the pinned toolchain does (Foundation F3). It is wired into `make agent-check`
// (Foundation F6) so the check is part of the single trusted verdict.
//
// Usage:
//
//	go run ./tools/lint/filesize          # scan from cwd
package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
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

	// maxTrackedFileBytes is the upper bound for any binary file tracked in git.
	// Compiled binaries are typically tens of MiB; legitimate source artefacts
	// (generated protobuf, go.sum) rarely approach this. 1 MiB is a conservative
	// ceiling that catches accidentally committed binaries without false-positives
	// on the current tree. Only files that also look binary (NUL byte in first
	// 8 KiB) are flagged — large text files (go.sum, docs) are not penalised.
	maxTrackedFileBytes = 1 * 1024 * 1024 // 1 MiB

	// binarySniffBytes is how many bytes to read when deciding whether a file
	// looks binary. Matches the heuristic used by git and file(1).
	binarySniffBytes = 8 * 1024
)

// legacyOversizeBaseline freezes the §1.10 violations that predate this check
// being wired into agent-check. It is a RATCHET, not an exemption list:
//
//   - a file listed here fails if it grows BEYOND its recorded count;
//   - a file NOT listed here fails the moment it exceeds the normal limit;
//   - entries may shrink or disappear as files are split — never grow, and
//     nothing new may be added. Adding an entry is how this guard dies quietly,
//     so treat a PR that does so as a design discussion, not a lint fix.
//
// Turning the check on with 34 files already over the line would have meant
// either failing every build or silently weakening the limits. Freezing the debt
// keeps the guard live for all new code while leaving the split work to its own
// change (docs/design/principles/skills-and-small-files.md §1.10).
var legacyOversizeBaseline = map[string]int{
	"cmd/harbor-hot/main.go":                    697,
	"cmd/harbor-mgmt/main.go":                   554,
	"e2e/enrollment_test.go":                    533,
	"e2e/flow_test.go":                          749,
	"internal/bff/dashboard.go":                 536,
	"internal/bff/login_test.go":                798,
	"internal/clients/grants_test.go":           505,
	"internal/clients/ratelimit_test.go":        702,
	"internal/clients/sessions_test.go":         727,
	"internal/crypto/keyprovider_kms.go":        415,
	"internal/crypto/keyprovider_kms_test.go":   923,
	"internal/crypto/rotation_store_db_test.go": 644,
	"internal/crypto/signer_kms_test.go":        671,
	"internal/identity/recovery_test.go":        635,
	"internal/mfa/service.go":                   435,
	"internal/mgmtapi/consent_test.go":          570,
	"internal/mgmtapi/recovery.go":              592,
	"internal/mgmtapi/recovery_test.go":         801,
	"internal/mgmtapi/relay.go":                 587,
	"internal/mgmtapi/relay_test.go":            807,
	"internal/oidc/chaos_test.go":               1052,
	"internal/oidc/jwt_issuer_test.go":          740,
	"internal/oidc/refresh_test.go":             785,
	"internal/oidc/service.go":                  975,
	"internal/oidc/service_test.go":             787,
	"internal/oidcapi/ratelimit_test.go":        525,
	"internal/oidcapi/revoke_test.go":           703,
	"internal/relay/address_test.go":            526,
	"internal/relay/auth_test.go":               540,
	"internal/relay/domain.go":                  501,
	"internal/relay/domain_test.go":             682,
	"internal/relay/forward_test.go":            737,
	"internal/relay/mta.go":                     647,
	"internal/relay/mta_test.go":                701,
}

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

	binaryFindings, err := scanTrackedBinaries()
	if err != nil {
		fmt.Fprintf(os.Stderr, "filesize: error scanning tracked binaries: %v\n", err)
		os.Exit(1)
	}
	findings = append(findings, binaryFindings...)

	if len(findings) == 0 {
		fmt.Println("filesize: clean — no files exceed the §1.10 small-files thresholds.")
		os.Exit(0)
	}

	fmt.Fprintf(os.Stderr, "filesize: %d file(s) exceed the §1.10 small-files thresholds.\n", len(findings))
	fmt.Fprintf(os.Stderr, "A large file mixes concerns — split along a package/file boundary (see docs/design/principles/skills-and-small-files.md §1.10).\n")
	fmt.Fprintf(os.Stderr, "Committed binaries must be removed with `git rm --cached` and added to .gitignore.\n\n")
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
		// A baselined file is judged against its frozen count, not the limit:
		// it may shrink, but any growth is a regression and fails.
		if frozen, ok := legacyOversizeBaseline[path]; ok {
			if lines > frozen {
				out = append(out, finding{path: path, count: lines, limit: frozen, unit: "lines (frozen baseline — may not grow)"})
			}
			return nil
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

// scanTrackedBinaries calls `git ls-files -z` to enumerate every file tracked
// in the current git index and flags any whose on-disk size exceeds
// maxTrackedFileBytes AND whose content looks binary. Using the index (not git
// history) keeps this check git-history-free and safe to run in agent-check.
//
// Fail-closed: if git is unavailable or the repo state is unreadable the
// function returns an error — a missing tool is never a silent pass.
func scanTrackedBinaries() ([]finding, error) {
	cmd := exec.Command("git", "ls-files", "-z")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git ls-files: %w", err)
	}
	var findings []finding
	for _, path := range strings.Split(string(out), "\x00") {
		if path == "" {
			continue
		}
		info, statErr := os.Stat(path)
		if statErr != nil || info.IsDir() {
			continue // deleted or a submodule directory; skip
		}
		size := int(info.Size())
		if size <= maxTrackedFileBytes {
			continue
		}
		binary, sniffErr := looksBinary(path)
		if sniffErr != nil || !binary {
			continue // unreadable or text (e.g. large go.sum); skip
		}
		findings = append(findings, finding{
			path:  path,
			count: size,
			limit: maxTrackedFileBytes,
			unit:  "bytes",
		})
	}
	return findings, nil
}

// looksBinary reports whether the file at path appears to be binary by
// checking for a NUL byte in the first binarySniffBytes, matching the
// heuristic used by git and file(1).
func looksBinary(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close() //nolint:errcheck // deferred os.File.Close on a read-only file; see error-handling.md §1.11

	buf := make([]byte, binarySniffBytes)
	n, err := f.Read(buf)
	if err != nil && n == 0 {
		return false, err
	}
	return bytes.IndexByte(buf[:n], 0) >= 0, nil
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
