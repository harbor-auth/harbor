# buildtags — build-tag/lint coupling checker (§1.11)

A stdlib-only tool that enforces the coupling between `//go:build` constraints
in `.go` files and the `run.build-tags` list in `.golangci.yml`.

## The problem it solves

A file gated behind a `//go:build sometag` constraint is **completely invisible**
to `golangci-lint run ./...` unless `sometag` appears in `.golangci.yml`'s
`run.build-tags` list. The linter silently reports "0 issues" for a file it
never compiled — the same silent-failure shape §1.11 exists to prevent, applied
at the tooling layer.

This was discovered empirically: `e2e/flow_test.go` (tag `e2e`) had four
`io.ReadAll` error-discards that were invisible to lint until `e2e` was added to
`run.build-tags`. A temporarily injected violation confirmed the invisibility.

## What it checks

For every `*.go` file in the repo it reads the preamble (before the `package`
clause) and extracts **custom** build tags — anything that is not a standard Go
GOOS value (`linux`, `darwin`, …), GOARCH value (`amd64`, `arm64`, …), toolchain
pseudo-tag (`cgo`, `race`, `unix`, …), or version constraint (`go1.22`, …). It
then verifies every such custom tag appears in `.golangci.yml`'s `run.build-tags`
list, failing with a clear message if any are missing.

## What it does NOT check

The reverse direction — a tag listed in `run.build-tags` with no corresponding
`//go:build` file — is intentionally ignored. Pre-adding tags for upcoming files
is harmless.

## Run it

```bash
go run ./tools/lint/buildtags    # from repo root
```

Exits 0 (clean) or 1 (missing tags) with one line per finding. Wired into
`make agent-check` (Foundation F6).

## Exclusion sets

Standard (always-in-scope) tags that are never flagged:

| Category | Examples |
|---|---|
| GOOS | `linux`, `darwin`, `windows`, `freebsd`, … |
| GOARCH | `amd64`, `arm64`, `wasm`, `riscv64`, … |
| Toolchain pseudo-tags | `cgo`, `race`, `msan`, `asan`, `gc`, `unix`, `ignore`, … |
| Version constraints | `go1.22`, `go1.25`, … (regex `^go\d+(\.\d+)*$`) |

Any identifier outside this closed set is treated as a custom tag that requires
a corresponding entry in `run.build-tags`.
