---
name: code-review
description: Graduated into the dedicated @harbor-reviewer agent — this is now a thin pointer.
---

This skill has **graduated into a dedicated agent**: **`@harbor-reviewer`** (`.agents/harbor-reviewer.ts`).

Use that instead — it bakes in the same privacy/security/sovereignty/spec-first/testing checklist and delegates to `@deep-code-reviewer` for the general quality pass. This pointer is kept so `@code-review` still resolves.

See the **Lifecycle** section of [`.agents/README.md`](./README.md) — `code-review` → `harbor-reviewer` is our first skill-to-agent graduation, the living-toolkit lifecycle in practice.
