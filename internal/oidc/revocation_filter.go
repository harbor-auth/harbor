// Package oidc revocation_filter.go provides the bloom-filter-based emergency
// JWT revocation mechanism (DESIGN.md §3.5). This file is a placeholder that
// reserves the bloom/v3 dependency; the full implementation follows in
// subsequent tasks.
package oidc

import (
	// Reserve the bloom filter dependency for emergency JWT revocation (§3.5).
	// The full RevocationFilter implementation will be added in a later task.
	_ "github.com/bits-and-blooms/bloom/v3"
)
