// SPDX-FileCopyrightText: 2026 Harbor Authors
// SPDX-License-Identifier: AGPL-3.0-only

package contract

import (
	"path/filepath"
	"strings"
	"testing"
)

// Independent branches must not assign the same migration version to different
// changes: a database that applied one would silently omit the other at rollout.
func TestMigrationVersionsAreUnique(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("..", "..", "db", "migrations", "*.up.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("no migrations examined")
	}
	seen := map[string]string{}
	for _, path := range paths {
		name := filepath.Base(path)
		version, _, ok := strings.Cut(name, "_")
		if !ok {
			t.Fatalf("migration has no version prefix: %s", name)
		}
		if previous, exists := seen[version]; exists {
			t.Errorf("migration version %s is shared by %s and %s", version, previous, name)
		}
		seen[version] = name
	}
}
