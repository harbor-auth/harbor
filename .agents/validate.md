---
name: validate
description: Fast local validation on changed files — format, vet, lint, spec-lint, and codegen-drift (the inner loop).
---

The **fast inner loop** from `docs/DESIGN.md` §1.8: near-instant feedback **before** CI. Run on **changed files only** so it stays sub-second-ish and actually gets used. Intended to run **pre-commit**.

> **Update this skill:** if the toolchain (linters, spec tools, codegen) changes, fix this file as part of your change. A stale skill is a bug.

## What it runs (changed files only)

```bash
# 1. Format (Go) — check-only: list files needing formatting; non-empty output ⇒ FAIL
gofmt -l $(git diff --name-only --cached -- '*.go')
#   (to auto-fix instead of failing: gofmt -w / goimports -w on the same file set)

# 2. Vet (cheap static checks) — scope to changed packages where possible
go vet ./...

# 3. Lint
golangci-lint run

# 4. Spec-lint the contracts (api/)
spectral lint api/openapi/**/*.yaml     # OpenAPI
buf lint                                # Protobuf

# 5. Codegen-drift check — regenerate from specs; fail if anything changed
#    (server stubs, TS client, sqlc, etc. must match the specs)
<run codegen>   # e.g. buf generate && oapi-codegen ... && sqlc generate
git diff --exit-code   # non-empty diff ⇒ drift ⇒ FAIL
```

## Pass/fail criteria

| Check | Pass |
|---|---|
| `gofmt`/`goimports` | no reformatting needed (no files listed) |
| `go vet` | exit 0 |
| `golangci-lint` | exit 0, no findings |
| `spectral` / `buf lint` | exit 0 |
| **codegen-drift** | `git diff --exit-code` is clean after regenerating |

Any failure blocks the commit. This mirrors CI **Stage 1 (Static)** and **Stage 2 (Contract compat)** in §1.8 — catching it here means it never wastes a CI run.

## Notes

- Prefer wiring these into a **pre-commit hook** on the staged file set.
- The codegen-drift check is the key one: it guarantees the generated code (Go stubs, TS client, `sqlc` queries) always matches the `api/` contracts (§1.2–§1.5). **Regenerate; never hand-edit generated files.**
