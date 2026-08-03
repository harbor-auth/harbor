// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// committedAssetsDir is the vendored output tree this generator must match
// byte-for-byte. Resolved relative to this package (sdk/sign-in-button/gen)
// so the test works regardless of the working directory `go test` is
// invoked from.
const committedAssetsDir = "../assets"

// readDirFiles returns the sorted, relative file names of every regular
// file directly inside dir (Generate does not create subdirectories, so a
// flat listing is sufficient).
func readDirFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading dir %s: %v", dir, err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names
}

// TestGenerate_IsRepeatable is the REQ-005 "generation is repeatable"
// scenario: two independent invocations of Generate, into two fresh
// directories, must produce byte-identical output — no timestamps, random
// IDs, or map-iteration-order artifacts may leak into the generated files.
func TestGenerate_IsRepeatable(t *testing.T) {
	dirA := t.TempDir()
	dirB := t.TempDir()

	if err := Generate(dirA); err != nil {
		t.Fatalf("Generate(%s): %v", dirA, err)
	}
	if err := Generate(dirB); err != nil {
		t.Fatalf("Generate(%s): %v", dirB, err)
	}

	filesA := readDirFiles(t, dirA)
	filesB := readDirFiles(t, dirB)
	if len(filesA) == 0 {
		t.Fatal("Generate produced zero files")
	}
	if !equalStrings(filesA, filesB) {
		t.Fatalf("generated file sets differ:\n  run A: %v\n  run B: %v", filesA, filesB)
	}

	for _, name := range filesA {
		a, err := os.ReadFile(filepath.Join(dirA, name))
		if err != nil {
			t.Fatalf("reading %s from run A: %v", name, err)
		}
		b, err := os.ReadFile(filepath.Join(dirB, name))
		if err != nil {
			t.Fatalf("reading %s from run B: %v", name, err)
		}
		if !bytes.Equal(a, b) {
			t.Errorf("%s differs between two Generate runs:\n--- run A ---\n%s\n--- run B ---\n%s", name, a, b)
		}
	}
}

// TestGenerate_MatchesCommittedAssets is the REQ-005 "regeneration matches
// committed assets" scenario: a fresh generation into a temp dir must be
// byte-identical to the vendored sdk/sign-in-button/assets/ tree committed
// to the repository. A failure here means the committed assets have drifted
// from the generator (the codegen-drift pattern make generate-check
// enforces for the rest of the repo) — regenerate with
// `go run ./sdk/sign-in-button/gen` and commit the result.
func TestGenerate_MatchesCommittedAssets(t *testing.T) {
	if _, err := os.Stat(committedAssetsDir); err != nil {
		t.Fatalf("committed assets dir %s not found: %v", committedAssetsDir, err)
	}

	fresh := t.TempDir()
	if err := Generate(fresh); err != nil {
		t.Fatalf("Generate(%s): %v", fresh, err)
	}

	freshFiles := readDirFiles(t, fresh)
	committedFiles := readDirFiles(t, committedAssetsDir)

	if !equalStrings(freshFiles, committedFiles) {
		t.Fatalf("generated file set does not match committed assets/ tree (drift):\n"+
			"  freshly generated: %v\n"+
			"  committed:         %v\n"+
			"run `go run ./sdk/sign-in-button/gen` and commit the result", freshFiles, committedFiles)
	}

	var drifted []string
	for _, name := range freshFiles {
		got, err := os.ReadFile(filepath.Join(fresh, name))
		if err != nil {
			t.Fatalf("reading %s from fresh generation: %v", name, err)
		}
		want, err := os.ReadFile(filepath.Join(committedAssetsDir, name))
		if err != nil {
			t.Fatalf("reading %s from committed assets: %v", name, err)
		}
		if !bytes.Equal(got, want) {
			drifted = append(drifted, name)
			t.Errorf("committed assets/%s has drifted from the generator:\n--- committed ---\n%s\n--- freshly generated ---\n%s",
				name, want, got)
		}
	}
	if len(drifted) > 0 {
		t.Fatalf("codegen drift in %d file(s): %v — run `go run ./sdk/sign-in-button/gen` and commit the result", len(drifted), drifted)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
