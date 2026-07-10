// Command buildtags is Harbor's build-tag/lint coupling checker (§1.11).
//
// A file with a //go:build constraint is completely invisible to
// `golangci-lint run ./...` unless that constraint tag appears in
// .golangci.yml's `run.build-tags` list. The linter silently reports
// "0 issues" for a file it never compiled — the same silent-failure shape
// §1.11 exists to prevent, applied at the tooling layer.
//
// This tool enforces the coupling: it scans every *.go file in the repo,
// extracts any CUSTOM build-constraint tags (i.e. tags that are not a standard
// Go GOOS, GOARCH, toolchain pseudo-tag, or go-version constraint), and fails
// if any such tag is absent from .golangci.yml's `run.build-tags` list.
//
// It is stdlib-only (go/scanner + filepath.WalkDir) so it runs anywhere the
// pinned toolchain does (Foundation F3). It is wired into `make agent-check`
// (Foundation F6) so the check is the single trusted verdict.
//
// Legacy `// +build` lines (pre-Go 1.17 syntax) are intentionally ignored:
// the repo requires go 1.25+, which uses `//go:build` exclusively.
//
// Usage:
//
//	go run ./tools/lint/buildtags          # scan from cwd
package main

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// standardTags is the closed set of Go-defined build-constraint identifiers
// that must NOT be required in run.build-tags (they are always in scope).
//
// Sources:
//   - GOOS values: https://pkg.go.dev/internal/goos
//   - GOARCH values: https://pkg.go.dev/internal/goarch
//   - Toolchain pseudo-tags: gc, gccgo, cgo, race, msan, asan, unix, ignore,
//     boringcrypto, purego
//   - go-version constraints: matched by versionTagRE below (go1.22, go1.25, …)
var standardTags = map[string]bool{
	// GOOS
	"aix": true, "android": true, "darwin": true, "dragonfly": true,
	"freebsd": true, "hurd": true, "illumos": true, "ios": true,
	"js": true, "linux": true, "nacl": true, "netbsd": true,
	"openbsd": true, "plan9": true, "solaris": true, "wasip1": true,
	"windows": true, "zos": true,
	// GOARCH
	"386": true, "amd64": true, "amd64p32": true, "arm": true,
	"arm64": true, "arm64be": true, "armbe": true, "loong64": true,
	"mips": true, "mips64": true, "mips64le": true, "mips64p32": true,
	"mips64p32le": true, "mipsle": true, "ppc": true, "ppc64": true,
	"ppc64le": true, "riscv": true, "riscv64": true, "s390": true,
	"s390x": true, "sparc": true, "sparc64": true, "wasm": true,
	// Toolchain pseudo-tags
	"unix": true, "cgo": true, "race": true, "msan": true, "asan": true,
	"gc": true, "gccgo": true, "ignore": true, "boringcrypto": true,
	"purego": true,
}

// versionTagRE matches Go toolchain version constraints (go1.22, go1.25, …).
var versionTagRE = regexp.MustCompile(`^go\d+(\.\d+)*$`)

// identRE extracts all identifier-shaped tokens from a build expression.
// Operators (!, &&, ||), parentheses, and whitespace are treated as delimiters.
var identRE = regexp.MustCompile(`[A-Za-z][A-Za-z0-9_.]*`)

func main() {
	// Load the set of tags already declared in .golangci.yml.
	declared, err := loadDeclaredTags(".golangci.yml")
	if err != nil {
		fmt.Fprintf(os.Stderr, "buildtags: cannot read .golangci.yml: %v\n", err)
		os.Exit(1)
	}

	// Scan the repo for custom build tags.
	tagFiles := map[string][]string{} // tag → files that require it
	if err := filepath.WalkDir(".", func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil //nolint:nilerr // WalkDir idiom: skip unreadable entries, keep walking
		}
		if d.IsDir() {
			if skipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		tags, err := customTagsInFile(path)
		if err != nil {
			// Read errors are the compiler's job; skip the file.
			return nil //nolint:nilerr // intentional: individual unreadable files don't abort the scan
		}
		for _, tag := range tags {
			tagFiles[tag] = append(tagFiles[tag], path)
		}
		return nil
	}); err != nil {
		fmt.Fprintf(os.Stderr, "buildtags: scan error: %v\n", err)
		os.Exit(1)
	}

	// Report any custom tag not declared in run.build-tags.
	var missing []string
	for tag, files := range tagFiles {
		if !declared[tag] {
			for _, f := range files {
				missing = append(missing, fmt.Sprintf("  %s: tag %q", f, tag))
			}
		}
	}

	if len(missing) == 0 {
		fmt.Println("buildtags: clean — all custom //go:build tags are listed in .golangci.yml run.build-tags.")
		os.Exit(0)
	}

	fmt.Fprintf(os.Stderr, "buildtags: %d file(s) have custom //go:build tags missing from .golangci.yml run.build-tags.\n", len(missing))
	fmt.Fprintf(os.Stderr, "A missing tag means golangci-lint silently skips that file (§1.11 silent-failure gap).\n")
	fmt.Fprintf(os.Stderr, "Add each tag under run.build-tags: in .golangci.yml.\n\n")
	for _, m := range missing {
		fmt.Fprintln(os.Stderr, m)
	}
	os.Exit(1)
}

// skipDir reports whether a directory should be skipped during the walk.
func skipDir(name string) bool {
	switch name {
	case ".git", "vendor", "node_modules", "testdata":
		return true
	}
	return false
}

// customTagsInFile reads the preamble of a Go file (everything before the
// `package` clause) and returns the set of custom build-constraint tags found
// in any `//go:build` line. It returns nil if the file has no such tags.
func customTagsInFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // deferred os.File.Close on a read-only file; see error-handling.md §1.11

	seen := map[string]bool{} // deduplicate tags per file
	var custom []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Stop at the package declaration — build constraints must precede it.
		if strings.HasPrefix(line, "package ") {
			break
		}
		if !strings.HasPrefix(line, "//go:build ") {
			continue
		}
		expr := strings.TrimPrefix(line, "//go:build ")
		for _, ident := range identRE.FindAllString(expr, -1) {
			if !isStandardTag(ident) && !seen[ident] {
				seen[ident] = true
				custom = append(custom, ident)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return custom, nil
}

// isStandardTag reports whether ident is a Go-defined build tag that is always
// in scope and does NOT need to be listed in run.build-tags.
func isStandardTag(ident string) bool {
	return standardTags[ident] || versionTagRE.MatchString(ident)
}

// loadDeclaredTags parses the run.build-tags list from .golangci.yml using
// simple line-by-line scanning (no YAML library required — the file is small
// and its structure is controlled). It handles both the block form:
//
//	run:
//	  build-tags:
//	    - e2e
//
// and the inline form:
//
//	run:
//	  build-tags: [e2e, integration]
func loadDeclaredTags(path string) (map[string]bool, error) {
	f, err := os.Open(path)
	if err != nil {
		// A missing .golangci.yml is not an error for this check — no tags
		// are declared, so any custom tag in the codebase will be flagged.
		if os.IsNotExist(err) {
			return map[string]bool{}, nil
		}
		return nil, err
	}
	defer f.Close() //nolint:errcheck // deferred os.File.Close on a read-only file; see error-handling.md §1.11

	declared := map[string]bool{}
	inBuildTags := false

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		// Strip inline comments.
		if i := strings.Index(trimmed, " #"); i >= 0 {
			trimmed = strings.TrimSpace(trimmed[:i])
		}

		// Detect `build-tags:` key (possibly with inline list).
		if strings.HasPrefix(trimmed, "build-tags:") {
			inBuildTags = true
			// Inline list: `build-tags: [e2e, integration]`
			if idx := strings.Index(trimmed, "["); idx >= 0 {
				inner := trimmed[idx+1:]
				if end := strings.Index(inner, "]"); end >= 0 {
					inner = inner[:end]
				}
				for _, tag := range strings.Split(inner, ",") {
					if t := strings.TrimSpace(tag); t != "" {
						declared[t] = true
					}
				}
				inBuildTags = false // fully consumed on this line
			}
			continue
		}

		if inBuildTags {
			// A dedented (non-list) line means we've left the build-tags block.
			if len(line) > 0 && line[0] != ' ' && line[0] != '\t' {
				inBuildTags = false
				continue
			}
			// Comment-only lines (trimmed starts with #) are part of the block
			// and must be skipped — NOT treated as block terminators. Without
			// this, a commented-out entry like `# - integration` causes the
			// scanner to exit the block early, silently missing subsequent tags.
			if strings.HasPrefix(trimmed, "#") {
				continue
			}
			// Block list item: `    - e2e`
			if strings.HasPrefix(trimmed, "- ") {
				tag := strings.TrimSpace(strings.TrimPrefix(trimmed, "- "))
				if tag != "" {
					declared[tag] = true
				}
			} else if trimmed != "" && !strings.HasSuffix(trimmed, ":") {
				// Any non-list, non-key line ends the block.
				inBuildTags = false
			}
		}
	}
	return declared, scanner.Err()
}
