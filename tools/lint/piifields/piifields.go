// Command piifields is Harbor's PII-in-telemetry analyzer (Foundation F10).
//
// It statically scans Go source for logging calls that pass a KNOWN-PII field
// name as a structured key (e.g. slog.String("email", …), logger.Info(…,
// "user_id", …)), which would violate the observability privacy invariants of
// §6.5.7 (no PII in logs/metrics/traces). Findings are printed one per line and
// the process exits non-zero, so it can gate `make agent-check` (wired in a
// later chunk).
//
// It is intentionally dependency-free (go/parser + go/ast, stdlib only) so it
// runs anywhere the pinned toolchain does. The safe wrapper it steers callers
// toward is internal/telemetry (deny-by-default allow-listing).
//
// Usage:
//
//	go run ./tools/lint/piifields ./...     # scan the repo from cwd
//	go run ./tools/lint/piifields <dir>...  # scan specific roots
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// piiKeys are the structured field names that must never be logged (mirrors
// internal/telemetry.DeniedFields; kept in sync by review — see §6.5.7).
var piiKeys = map[string]bool{
	"email":         true,
	"user_id":       true,
	"sub":           true,
	"ppid":          true,
	"ip":            true,
	"ip_address":    true,
	"token":         true,
	"access_token":  true,
	"id_token":      true,
	"code_verifier": true,
	"phone":         true,
	"name":          true,
	"relay":         true,
	"relay_address": true,
}

// loggingFns are call selectors we treat as logging/attribute sinks. If a PII
// string literal is passed to one of these, it's a finding.
var loggingFns = map[string]bool{
	// slog / log level methods
	"Info": true, "Infof": true, "InfoContext": true,
	"Warn": true, "Warnf": true, "WarnContext": true,
	"Error": true, "Errorf": true, "ErrorContext": true,
	"Debug": true, "Debugf": true, "DebugContext": true,
	"Print": true, "Printf": true, "Println": true,
	"Fatal": true, "Fatalf": true, "Panic": true, "Panicf": true,
	"Log": true, "LogAttrs": true, "With": true,
	// slog attribute constructors
	"String": true, "Int": true, "Int64": true, "Uint64": true,
	"Bool": true, "Float64": true, "Any": true, "Duration": true,
	"Time": true, "Group": true,
}

type finding struct {
	pos token.Position
	key string
}

func main() {
	roots := os.Args[1:]
	// Treat the go-style "./..." (or no args) as "walk from cwd".
	var dirs []string
	for _, r := range roots {
		if r == "./..." || r == "..." {
			continue
		}
		dirs = append(dirs, r)
	}
	if len(dirs) == 0 {
		dirs = []string{"."}
	}

	fset := token.NewFileSet()
	var findings []finding
	for _, root := range dirs {
		f, err := scanRoot(fset, root)
		if err != nil {
			fmt.Fprintf(os.Stderr, "piifields: error scanning %s: %v\n", root, err)
			os.Exit(1)
		}
		findings = append(findings, f...)
	}

	if len(findings) == 0 {
		os.Exit(0)
	}
	for _, f := range findings {
		fmt.Fprintf(os.Stderr, "%s: PII-FIELD: %q passed to a logging call — use internal/telemetry (deny-by-default) or remove\n",
			f.pos, f.key)
	}
	fmt.Fprintf(os.Stderr, "\npiifields: %d finding(s)\n", len(findings))
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

// skipFile reports whether a .go file is exempt from scanning: the telemetry
// wrapper itself, generated code, tests, and this analyzer package.
func skipFile(path string) bool {
	p := filepath.ToSlash(path)
	if strings.HasSuffix(p, "_test.go") {
		return true
	}
	if strings.Contains(p, "internal/gen/") ||
		strings.Contains(p, "internal/telemetry/") ||
		strings.Contains(p, "tools/lint/") {
		return true
	}
	return false
}

func scanRoot(fset *token.FileSet, root string) ([]finding, error) {
	var out []finding
	if err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			// Returning nil (not walkErr) is the filepath.WalkDir callback idiom
			// for "skip this entry, keep walking". Per-file permission errors are
			// intentionally non-fatal: one unreadable file should not abort the
			// whole PII scan. nilerr is correct in general but does not apply to
			// WalkDir callbacks where nil-on-error means "continue".
			return nil //nolint:nilerr
		}
		if d.IsDir() {
			if skipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || skipFile(path) {
			return nil
		}
		out = append(out, scanFile(fset, path)...)
		return nil
	}); err != nil {
		return nil, fmt.Errorf("walking %s: %w", root, err)
	}
	return out, nil
}

func scanFile(fset *token.FileSet, path string) []finding {
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		// A parse error is not our concern (the compiler will surface it); skip.
		return nil
	}

	var out []finding
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || !loggingFns[sel.Sel.Name] {
			return true
		}
		for _, arg := range call.Args {
			lit, ok := arg.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				continue
			}
			val, err := strconv.Unquote(lit.Value)
			if err != nil {
				continue
			}
			if piiKeys[val] {
				out = append(out, finding{pos: fset.Position(lit.Pos()), key: val})
			}
		}
		return true
	})
	return out
}
