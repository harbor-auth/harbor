---
name: frontend-test
description: Validate & test the Harbor Next.js/TypeScript frontend (typecheck, lint, unit tests).
---

Validate and test Harbor's frontend — the **Next.js (React) + TypeScript** dashboard and auth UI (`docs/DESIGN.md` §9). Assumes **pnpm**.

> **Update this skill:** if the package manager, scripts, or test runner drift from the code, fix this file as part of your change. A stale skill is a bug.

## The three checks

```bash
pnpm typecheck     # tsc --noEmit — types must be clean
pnpm lint          # eslint
pnpm test          # unit tests (e.g. vitest / jest)
```

Run all three before opening a PR. Type and lint errors are non-negotiable.

## Generated API types (do not hand-write)

The frontend's API types are **generated from the backend's OpenAPI contract** (§1.3, §9) via `openapi-typescript` / `orval`. The web app **never hand-writes request/response types**.

- If types are **stale** after a backend contract change: **regenerate** (run codegen), don't patch types by hand or reach for `as any`.
- Import types from the generated client, not from ad-hoc local interfaces.

```bash
pnpm codegen       # regenerate the typed API client from api/openapi
pnpm typecheck     # then re-verify
```

## Privacy invariants (auth & dashboard surfaces)

- **No third-party trackers, analytics, or ad SDKs** in the auth or dashboard surfaces (§9, §2.2) — this is a hard rule, consistent with the no-tracking promise. Flag any such dependency in review.
- Tokens/secrets stay **server-side** in `HttpOnly` cookies (BFF pattern) — never in `localStorage`.

## On failure

Fix typecheck/lint/test failures before proceeding. If a failure traces to stale generated types, run codegen rather than editing generated files.
