# Design: Increase test coverage

## Key Decisions

### Decision 1: Target error paths and edge cases
**Chosen:** Focus on untested error paths (DB failures, crypto failures, invalid
inputs) rather than happy-path variations.
**Rationale:** Error paths are most likely to be untested and most critical for
reliability. Happy paths are already well-covered.
**Alternatives considered:** Full mutation testing (too slow, rejected).

### Decision 2: Use mock/fake implementations for error injection
**Chosen:** Create focused mock types (e.g., `errKeyProvider`, `errCipher`,
`errGrantStore`) that return configurable errors.
**Rationale:** Allows precise control over which error path is exercised without
complex setup. Follows existing patterns in the codebase.
**Alternatives considered:** Monkey-patching (fragile, rejected).

### Decision 3: Exclude generated code from coverage targets
**Chosen:** `internal/gen/*` packages are excluded from the 80% target.
**Rationale:** Generated code is machine-produced from schemas; testing the
generators themselves is out of scope. The generated code is exercised
transitively through tests of consuming packages.

### Decision 4: Document coverage results
**Chosen:** Create `docs/coverage-report.md` with per-package coverage and
justifications for exclusions.
**Rationale:** Provides audit trail and makes coverage goals visible to the team.

### Decision 5: Test fail-closed behavior
**Chosen:** Verify that error conditions return appropriate errors AND do not
produce partial/leaked state (e.g., no DB writes on validation failure).
**Rationale:** Fail-closed is a security invariant; tests should verify both the
error and the absence of side effects.
