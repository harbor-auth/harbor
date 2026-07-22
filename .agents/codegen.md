---
name: codegen
description: Regenerate all code from the `api/` contracts (Go stubs, TS client, sqlc, docs) — spec-first, zero drift.
---

Regenerate every generated artifact from Harbor's contracts. Per `docs/DESIGN.md` §1.2, contracts live under **`api/`** and are the **single source of truth**; per §1.5, CI **verifies codegen is current** (regenerate → fail if the working tree changes). **Generated code is never hand-edited — if code and spec disagree, the code is the bug.**

> **Update this skill:** if the spec layout, tools, or commands below drift from the code, fix this file as part of your change. Harbor is greenfield — this describes the **intended** workflow per the design and is updated as the code lands. A stale skill is a bug.

## Principle

Edit the **spec** → **regenerate** → commit **both**. Never patch generated files by hand, never reach for `as any` to paper over a stale type. Regenerate instead.

## What generates from what (the spec matrix, §1.3)

| Contract (source of truth) | Generates | Tool |
|---|---|---|
| **OpenAPI 3.1** (`api/openapi/**`) | Go server stubs + types | **`oapi-codegen`** |
| **OpenAPI 3.1** (`api/openapi/**`) | **TypeScript** client + types | **`openapi-typescript`** (or `orval`) |
| **Protobuf/gRPC** (`api/proto/**`) | Go types + gRPC | **`buf generate`** (`protoc-gen-go` / `-go-grpc`) |
| **JSON Schema 2020-12** (shared) | Go + TS types + validation | `$ref`d into OpenAPI |
| **SQL** (`db/`) | typed Go queries | **`sqlc generate`** (ties into `@db-migrate`) |
| OpenAPI 3.1 | API reference docs | Redoc |

**The web app never hand-writes API types** — they come from `openapi-typescript` off the same OpenAPI the Go server uses, so frontend and backend cannot silently drift.

## Representative commands

```bash
# Ideally one command regenerates everything:
make generate            # or: task generate

# ...which wraps the individual generators:
buf generate                                        # proto → Go + gRPC
sqlc generate                                       # SQL → typed Go
oapi-codegen -config api/openapi/oapi-codegen.yaml api/openapi/harbor.yaml   # OpenAPI → Go
pnpm codegen                                         # OpenAPI → TS client (openapi-typescript)
```

## Ordering (lint & compat first)

Before/with generating, lint the specs and check backward compatibility (§1.5):

```bash
spectral lint api/openapi/**/*.yaml     # OpenAPI style/lint
buf lint                                # Protobuf lint
oasdiff breaking <old> <new>            # OpenAPI breaking-change check
buf breaking --against '.git#branch=main'   # proto breaking-change check
```

Breaking changes require an explicit major-version bump and sign-off (§1.2/§1.5).

## Drift check — the crux (§1.5 / §1.8 Stage 1)

Regenerate, then assert the tree is clean:

```bash
make generate
git diff --exit-code    # non-empty diff ⇒ committed generated code is STALE ⇒ FAIL
```

This is exactly what **CI Stage 1** enforces and what **`@validate`** runs on the inner loop. **Always run codegen after any `api/` or SQL change and commit the result.**

## Relationship to other skills

- **`@validate`** — runs the fast **drift check** on changed files (does *not* fix drift).
- **`@codegen`** (this) — the "actually regenerate everything" workflow.
- **`@db-migrate`** — calls into `sqlc generate` here after a schema change.

## Checklist

- [ ] **Spec edited first** (not the generated code)?
- [ ] `spectral` / `buf lint` **clean**?
- [ ] **Breaking-change** checked (`oasdiff` / `buf breaking`) — major bump + sign-off if needed?
- [ ] **All targets regenerated** (Go stubs, TS client, `sqlc`, docs)?
- [ ] **`git diff --exit-code` clean** after regenerating (no drift)?
- [ ] **No hand-edited generated files**?
