package mgmtapi

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoHeaderNameInSourceFiles is a regression guard for audit finding C1
// (universal account takeover via spoofable X-Harbor-User-ID header). It walks
// every non-test Go source file in internal/mgmtapi/ and fails if either the
// header name string or the UserIDHeader symbol reappears.
//
// The forbidden needles are built by concatenation so that this guard file
// never triggers its own check (the guard is a _test.go file and is skipped
// anyway, but concatenation is belt-and-suspenders).
//
// Pattern mirrors the source-scan style in internal/arch/arch_test.go.
func TestNoHeaderNameInSourceFiles(t *testing.T) {
	// Build forbidden strings by concatenation — prevents this file from
	// flagging itself if the scanner were ever widened to include test files.
	headerName := "X-Harbor-" + "User-ID"
	symbolName := "UserID" + "Header"

	// Go tests run with cwd set to the package directory, so "." is
	// internal/mgmtapi/ when this test executes.
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}

	scanned := 0
	for _, e := range entries {
		name := e.Name()
		// Only inspect non-test Go source files.
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}

		content, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		src := string(content)

		if strings.Contains(src, headerName) {
			t.Errorf("%s: contains forbidden header name %q — "+
				"caller identity must come from CallerSource/callerID, "+
				"never a client-supplied header (C1 regression guard)", name, headerName)
		}
		if strings.Contains(src, symbolName) {
			t.Errorf("%s: contains forbidden symbol %q — "+
				"the UserIDHeader constant must not reappear (C1 regression guard)", name, symbolName)
		}
		scanned++
	}

	if scanned == 0 {
		t.Fatal("no non-test Go source files found in internal/mgmtapi/ — " +
			"the regression guard has nothing to check")
	}
}
