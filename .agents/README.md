# Harbor Skills & Agents — A Living Toolkit

A fluid, ever-evolving approach to how we work. **If we do something more than a couple of times, we capture it** — as a *skill* (a repeatable workflow/checklist) or a *dedicated agent* (a specialized doer). Skills and agents are not set in stone; they are living artifacts we refine continuously.

## Principle

Repetition is a signal. The moment a task recurs, the manual effort of doing it "by hand" each time is waste **and** a source of drift and mistakes. We invest a few minutes to write it down as a skill, and everyone (human or agent) benefits from then on.

## Skill vs. agent

| | **Skill** | **Dedicated agent** |
|---|---|---|
| What | A documented, reusable procedure/checklist | A specialized doer that runs many tools autonomously |
| Invoke | `@skill-name` | Spawned as an agent |
| Use when | A workflow is repeatable and easy to get wrong | The task is complex, multi-tool, or benefits from isolation |
| Rule of thumb | **Start here** | **Graduate to this** once the skill is run often and stable |

Start with a skill. Promote it to a dedicated agent only when it's frequently used and its shape has stabilized.

## Modifying skills is first-class

**A stale skill is a bug.** Whenever we find an error in a skill, discover a better way, or the toolchain changes, we **update the skill immediately** — in the same PR as the fix whenever possible. Skills are versioned in-repo and reviewed like code. Do not route around a wrong skill; fix the skill.

## When to create a skill (heuristics)

- The task has been done **≥3 times** (or you can see it coming).
- It's a **multi-step workflow that's easy to get wrong**.
- It's a **checklist tied to our `docs/DESIGN.md` principles** — privacy invariants, spec-first contracts, testing, security.

## Lifecycle

```
Identify repetition  →  Draft skill  →  Use it  →  Refine on every friction  →  (optionally) Promote to a dedicated agent
```

Every skill should carry an **"update this skill" reminder**: if the commands or workflow below are wrong or have drifted from the code, fix this file as part of your change.

**First graduation (in practice):** `code-review` → **`harbor-reviewer`**. The `code-review` skill was run often enough and its shape stabilized, so we promoted it into a dedicated agent (`.agents/harbor-reviewer.ts`) with the privacy/security checklist baked in. The old `@code-review` skill is now a thin pointer to the agent — proof the lifecycle above is real, not aspirational.

**Second graduation:** `hippo` → **`hippo` (agent)**. The `hippo` memory skill graduated into a dedicated agent (`.agents/hippo.ts`) that **auto-recalls** at session start and drives the durable `hippo todo` + friction-capture ritual; `.agents/hippo.md` remains the canonical CLI/ritual reference the agent operationalizes.

## Index

> Harbor's code doesn't all exist yet — these skills describe the **intended** commands/workflow per `docs/DESIGN.md` and are updated as the code lands.

> **Knowledge hierarchy:** `docs/DESIGN.md` (§0–§15) is the top — the WHY and system-level WHAT. Below it, [`docs/README.md`](../docs/README.md) is the **feature & plan TOC**: future work lives in `docs/plans/` and as-built capabilities in `docs/features/`, managed by the `@plan` and `@docs` skills below.

| Skill | Invoke | Description |
|---|---|---|
| `go-build` | `@go-build` | Build Harbor's Go binaries (`harbor-hot`, `harbor-mgmt`) with caching. |
| `go-test` | `@go-test` | Run Go tests — unit, integration, race detector, coverage. |
| `frontend-test` | `@frontend-test` | Typecheck, lint, and unit-test the Next.js/TypeScript frontend. |
| `validate` | `@validate` | Fast local validation on changed files (fmt/vet/lint/spec-lint/codegen-drift). |
| `db-migrate` | `@db-migrate` | Postgres schema migrations via the expand/contract pattern (safe, reversible). |
| `codegen` | `@codegen` | Regenerate all code from the `api/` contracts (Go stubs, TS client, sqlc, docs). |
| `code-review` | `@code-review` → **`@harbor-reviewer`** | Thin pointer — graduated into the dedicated `harbor-reviewer` agent (see below). |
| `oidc-conformance` | `@oidc-conformance` | Run the OIDC OP + WebAuthn conformance suites as a hard release gate (§1.8 Stage 7). |
| `load-test` | `@load-test` | Hot-path throughput & p99 latency load tests as a pre-release gate (§1.8 Stage 8, §6.5.5). |
| `build` | `@build` | Work a plan's implementation checklist (`docs/plans/<slug>.md`) step-by-step — implement, validate, review, commit — then graduate it via `@plan promote`. |
| `docs` | `@docs` | Manage, **query**, and **reconcile** feature docs (`docs/features/`) against the codebase — the agent-consumable memory of the system. |
| `plan` | `@plan` | Author future-work plans (`docs/plans/`) and **graduate** them into feature docs as they ship — the plan→doc lifecycle. |
| `openspec` | `@openspec` | Author & **verify** a formal OpenSpec change (proposal + spec deltas + tasks) alongside every plan — spec-driven development gated by `openspec validate --strict`. |
| `hippo` | `@hippo` → **spawn `hippo` agent** | Thin pointer — graduated into the dedicated `hippo` agent (see below). Canonical CLI/ritual reference for Hippo persistent memory: recall, `hippo todo` tracking, and friction capture. |

### Dedicated agents

Agents that have graduated from a skill (or were born as agents). Spawned as agents rather than invoked inline.

| Agent | Invoke | Description |
|---|---|---|
| `harbor-reviewer` | spawn as an agent (`@harbor-reviewer`) | Reviews changes against Harbor's privacy/security/sovereignty/spec-first/testing checklist; delegates the general pass to `@deep-code-reviewer`. Defined in `.agents/harbor-reviewer.ts`. |
| `hippo` | spawn as an agent (`@hippo`) | Cross-session agent memory: auto-recalls prior context at session start (`hippo health`/`snapshot`/`sessions`/`todo list`), tracks work on the durable `hippo todo` list, and captures friction as todos so nothing is lost when context truncates. Defined in `.agents/hippo.ts`; full CLI ritual in `.agents/hippo.md`. |

**More will be added as the project grows** — e.g. `db-seed`, `release`, `chaos-test`. When you find yourself repeating one of these, add it here.
