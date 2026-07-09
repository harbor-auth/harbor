---
name: go-build
description: Build Harbor's Go binaries (harbor-hot, harbor-mgmt) with caching and fast feedback.
---

Build Harbor's Go backend. The modular monolith (`docs/DESIGN.md` §4.2) compiles into small, separately-deployable binaries under `cmd/` — chiefly **`harbor-hot`** (the stateless OIDC/verify hot path) and **`harbor-mgmt`** (the dashboard/management cold path).

> **Update this skill:** if the module layout, binary names, or build flags below drift from the code, fix this file as part of your change. A stale skill is a bug.

## Quick build (sanity)

```bash
go build ./...      # compile everything; fast, uses the Go build cache
go vet ./...        # cheap static sanity check
```

`go build ./...` failing is a hard stop — fix compile errors before anything else.

## Build the binaries

```bash
go build -o bin/harbor-hot  ./cmd/harbor-hot
go build -o bin/harbor-mgmt ./cmd/harbor-mgmt
```

## Static builds for tiny images

Harbor ships **small static Go binaries → tiny images → fast push/pull/rollout** (§1.8, §6.1). For container builds:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -ldflags='-s -w' -o bin/harbor-hot ./cmd/harbor-hot
```

- `CGO_ENABLED=0` → a fully static binary (no libc), runnable in a `scratch`/`distroless` image.
- `-trimpath` + `-ldflags='-s -w'` → smaller, reproducible binaries.

## Speed & affected-only builds

- The **Go build cache** makes incremental builds fast — don't fight it (avoid unnecessary `-a`).
- Follow the **affected-only** philosophy (§1.8): only rebuild/redeploy the system whose inputs changed. A `harbor-mgmt`-only change should not trigger a `harbor-hot` rebuild/rollout.

## On failure

- **Compile error:** fix it; never comment out or `//nolint` around a real type error.
- **Missing dependency:** add it with `go get <pkg>` (prefer an existing dep already in `go.mod`); run `go mod tidy`.
- **Cache weirdness:** `go clean -cache` only as a last resort (it's slow to warm back up).
