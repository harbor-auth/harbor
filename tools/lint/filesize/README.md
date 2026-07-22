# filesize — small-files principle checker (§1.10)

A stdlib-only tool that enforces **DESIGN §1.10** ("each file targets exactly
one feature or concern, and stays small") mechanically instead of leaving it
to review-time judgment alone.

## The problem it solves

§1.10 previously said the principle is "enforced in review: the
`@harbor-reviewer` agent flags files that mix multiple concerns or grow
large" — but nothing *mechanically* checked file size. That's the same
silent-failure shape §1.11 (error-handling) exists to prevent, just applied to
this principle instead: a rule nothing verifies is a rule that quietly erodes
as a codebase grows.

## What it checks

- **Go source files** (excluding `internal/gen/`, which is machine-written):
  flagged if they exceed **400 lines** (non-test) or **500 lines**
  (`_test.go` — table-driven tests legitimately run longer than the logic
  they exercise).
- **`docs/design/**/*.md`** files: flagged if they exceed **2,000 words**,
  matching the target already stated throughout the docs tree (`DESIGN.md`,
  `docs/README.md`, `.agents/docs.md`).

## What it does NOT check

- Files outside `docs/design/` (e.g. `docs/DESIGN.md` itself is an index and
  intentionally short; top-level docs like `docs/README.md` aren't part of
  the §1.10-governed design tree).
- Non-Go source (frontend, if/when one exists) — out of scope for this tool;
  add a sibling checker if that need arises.

## Run it

```bash
go run ./tools/lint/filesize    # from repo root
```

Exits 0 (clean) or 1 (files exceed threshold) with one line per finding.
Wired into `make agent-check` (Foundation F6).

## Thresholds are a ratchet

Like `Makefile`'s `COVERAGE_FLOOR` (Foundation F5), these limits should only
ever get **stricter** over time. If a file legitimately needs to grow past a
threshold, the correct response is to split it along a package/file boundary
(§1.10) — not raise the number. Raising a threshold to make a red build pass
is exactly the Goodhart failure F5 exists to prevent.
