---
name: build
description: Work a plan's implementation checklist (docs/plans/<slug>.md) step-by-step — implement, validate, review, commit — then graduate it via @plan promote.
---

Build a feature by working straight through a Harbor **plan's Implementation checklist** — implementing each task, validating, reviewing, and committing at logical boundaries. Because we build **exclusively with agentic systems**, the plan authored by [`@plan`](./plan.md) is the executable brief: `@build` just works it end-to-end. **Do not stop until the specified scope is complete. Do not ask questions — take your best recommended option when there is ambiguity. After each chunk, immediately proceed to the next — do not pause for confirmation.**

> **Update this skill:** if the plan layout, validation stack, review agent, or promotion hand-off below drift from how we actually work, fix this file as part of your change. A stale skill is a bug.

## Principle

A plan (`docs/plans/<slug>.md`) is future WHAT; its **Implementation checklist** is the ordered to-do list. `@build` turns that checklist into as-built code, ticking `- [x]` boxes as tasks land. It **does not** hand-write feature docs — when the checklist is done and the plan's *Definition of done* is met, it hands off to **`@plan promote <slug>`**, which creates the feature doc via `@docs new`, records bidirectional provenance, and moves the row from Plans to Features in [`docs/README.md`](../docs/README.md). Build → promote is the plan→doc lifecycle in motion.

## Invocation

```
@build docs/plans/<slug>.md            # work the whole implementation checklist
@build <slug>                          # resolve to docs/plans/<slug>.md
@build docs/plans/<slug>.md <section>   # only a named part of the checklist
```

If no path is given, resolve the plan from the current branch name against `docs/plans/`.

## Lifecycle integration

`@build` operates on a plan whose `status` is **`approved`** (the agreed plan of record). On starting, flip it to **`in-progress`** (`@plan status <slug> in-progress` — update the frontmatter **and** the Plans row together). As checklist items land, **tick the `- [ ]` boxes** in the plan — that is the progress record (there is no separate TODO document).

The plan stays **`in-progress` until its code is verifiably on `main`**. "An agent finished the checklist on a branch" is **not** the same as "shipped": the terminal path is the two-step `merged → promoted` gate defined in [`@plan`](./plan.md). Only after the PR **lands on `main`** (CI green, migrations non-colliding, `targets:` paths present on `origin/main`) does the plan advance to **`merged`** (`@plan merged <slug> <pr#>`); only then does **`@plan promote <slug>`** graduate it into a feature doc. `@build` itself never writes `docs/features/*.md` and **never sets a plan done off a working-branch merge**.

## Execution loop

### 0. Recall (session start)

Before working the checklist, **recall first** — run [`@hippo`](./hippo.md)'s recall (`hippo snapshot` / `hippo search`) to ground in prior sessions, and **batch-add any ad-hoc/live work items** not already in the plan's checklist to `hippo todo` so nothing is lost if context truncates. The plan's checklist is the durable *plan-of-record*; `hippo todo` holds the live/ad-hoc items and any friction alongside it.

For each coherent **chunk** of the checklist (typically 1–3 related items):

### 1. Think

Before writing any code, run **`@deep-thinker`** on the chunk's scope:

- Feed it the checklist item(s), the plan's *Proposed approach*, relevant DESIGN `§` refs, and any existing code that will be touched.
- Ask it to surface: the best interface shape, edge cases and failure modes, security invariants to uphold, and whether a simpler approach exists.
- Use the output to settle the design before implementation starts — **do not skip this step for non-trivial chunks**. For trivial changes (< ~20 lines, pure mechanical, no security surface), this step may be omitted.

### 2. Implement

- Read the checklist item(s) and the plan's *Proposed approach* + *Target code paths* for intent.
- Gather codebase context — read referenced files, search for patterns, follow existing conventions.
- Implement the item(s), keeping Harbor's **pure-core / thin-I/O** separation (§1.7) so logic stays unit-testable.

### 3. Validate (Harbor's Go stack)

- **[`@validate`](./validate.md)** — the fast inner loop on changed files: `gofmt`/`go vet`/`golangci-lint`, spec-lint (`spectral`/`buf lint`), and the **codegen-drift** check.
- **[`@go-test`](./go-test.md)** — unit tests for the changed package(s); add **`-race`** for anything touching the hot path or shared caches (JWKS, revocation filter); integration (`-tags=integration`, real Postgres/Redis) where relevant.
- **[`@go-build`](./go-build.md)** — `go build ./...` compile sanity; a build failure is a hard stop.
- Fix every failure before proceeding — never `t.Skip`/pending to get green (per `go-test.md`).

### 4. Review (iterate until only nits remain)

After static analysis is green, run the two-layer review **in a loop** until no Critical/High/Medium findings remain:

**Layer 1 — Harbor-specific:** Run **[`@harbor-reviewer`](./harbor-reviewer.ts)** on the chunk. It checks privacy/security/sovereignty/spec-first/testing invariants and calls through to `@deep-code-reviewer` for general quality.

**Layer 2 — Deep code quality:** Run **`@deep-code-reviewer`** explicitly on the diff. This is the authoritative quality gate for correctness, error handling, naming, test coverage, and DESIGN compliance.

**Iteration rule:**

```
loop:
  run @harbor-reviewer + @deep-code-reviewer (in parallel)
  fix all Critical findings          # security/correctness — blocking
  fix all High findings              # serious bugs/gaps — blocking
  fix Medium findings if < 5 min     # else note in plan and proceed
  if any new Critical/High surfaced → restart loop from top
  if only Low/Nit findings remain → exit loop
```

- **Never commit with an open Critical or High finding** — fix first, re-review, then commit.
- Harbor is security-critical (OIDC/WebAuthn/PPID): the **negative/security tests** the checklist calls for must be green before the chunk is done.

### 5. Commit & push

Delegate to **`@github-flow`** with a Harbor-scoped conventional-commit message, e.g.:

```
feat(oidc): refresh-token rotation — mint+rotate+revoke
```

Mid-build settings: `skipCi: true` (we validate locally), `createPr: false` (PR is opened once, at the end or a milestone), `syncWithMaster: false` (avoid repeated mid-build merges). **`worktree`:** Harbor is a single Go repo — pass a sibling worktree path if you're building in one, else `worktree: "none"`.

> **Committing/pushing is not "done."** Pushing a branch — or merging it into another **agent/`weft/*` branch** — does **not** land the code on `main`. The plan is only shipped once its PR is merged **into `main`** with green CI (the `merged` gate). Never flip the plan to a done state at this step.

### 6. Update progress

Tick the landed checklist items to `- [x]` in `docs/plans/<slug>.md`, and note any deviations/decisions inline in the plan.

### 7. Repeat

Move to the next chunk until the specified scope is complete.

## Contract & codegen

Any change to the `api/` contracts (OpenAPI/Protobuf) is **spec-first**: edit the spec, then regenerate with **[`@codegen`](./codegen.md)** and re-run **`@validate`** (its codegen-drift check must be clean). **Never hand-edit generated files** (Go stubs, TS client, `sqlc` queries) — regenerate them (§1.2–§1.5).

## Milestone boundaries

If the plan marks milestones, at each one run the fuller gate before committing: full **`@go-test`** + `-race` + integration, **`@validate`**, and the **review loop** (`@harbor-reviewer` + `@deep-code-reviewer` until only nits — same rule as step 4) on the cumulative changes since the last milestone. Then commit via `@github-flow` with `createPr: true`, `skipCi: false`, `syncWithMaster: true`. If the plan has no milestones, skip this section.

## Decision-making rules

| Situation | Action |
|---|---|
| Multiple valid approaches | Match the pattern most consistent with existing code |
| Missing context in the plan | Read the plan's *Problem*/*Proposed approach* + the cited DESIGN `§` |
| Migration needed | Use **`@db-migrate`** (expand/contract); never hand-write migration files |
| Contract change | Edit `api/` then **`@codegen`**; never hand-edit generated files |
| Test fails unexpectedly | Debug & fix; never `t.Skip`/pending (per `go-test.md`) |
| Review finding conflicts with the plan | Prefer the review finding (code quality > plan adherence) |
| Plan task seems wrong/outdated | Implement what fits the current code; note the deviation in the plan |

## Chunk sizing

Group checklist items into review/commit chunks by coherence:

- **A pure core function + its table-driven unit tests** → one chunk.
- **A migration via `@db-migrate` + the model/query changes it enables** → one chunk.
- **HTTP glue + its wire tests** → one chunk.
- **Several small related items** in the same file/area → one chunk.

Avoid chunks larger than ~300 lines of diff; split if needed.

## Error recovery

- **Capture friction the moment it appears:** on any build/test/lint failure or blocker, immediately record it as a `hippo todo` (command · error · file · hypothesis) so it survives truncation, then continue the main chunk — circle back and `hippo todo done <id>` once resolved. See [`@hippo`](./hippo.md).
- **Build/vet/lint or test failures:** fix and re-run via the Go skills — non-negotiable, never skip.
- **Codegen drift:** regenerate with `@codegen`, then confirm `@validate` is clean; never work around it.
- **Review Critical findings:** fix before committing, then re-review to confirm.
- **Git conflicts:** resolve using the branch's intent; prefer the newer code if unclear.

## Completion

When all in-scope checklist items are done:

1. Confirm the plan's Implementation checklist is fully `- [x]` and its *Definition of done* is met.
2. Final **`@validate`** + **`@go-test`** (full + `-race` + integration) pass.
3. Final review loop — **`@harbor-reviewer`** + **`@deep-code-reviewer`** (in parallel, same iterate-until-nits rule as step 4) on the full change set.
4. **OpenSpec gate** — the paired OpenSpec change must pass **`openspec validate <slug> --strict`** (the formal spec gate) before promote; once shipped, **`@openspec archive <slug>`** merges its spec deltas into `openspec/specs/`.
5. **Open the PR against `main` and get it merged** — `@github-flow` with `createPr: true`, `skipCi: false`, `syncWithMaster: true`, `prBaseBranch: main`. Wait for CI (`agent-check` + `e2e`) to go green and the PR to actually **merge into `main`**. Merging into any other branch does not count.
6. **Verify + mark `merged`** — run the *merged gate* (`@plan merged <slug> <pr#>`): `git fetch origin main`; confirm the PR is `MERGED` with `baseRefName: main`; confirm every `targets:` path resolves under `git ls-tree -r origin/main`; confirm any migration number is unique on `main` (**no collision**). Only then flip `status: merged`. If any check fails, the plan stays `in-progress` — fix the real gap.
7. **`@plan promote <slug>`** — only now graduate the (now `merged`) plan into a feature doc (`@docs new`), record provenance, and move its row to Features in `docs/README.md`.
8. Report what was built, the PR number and its merge-to-`main` status, any deviations noted in the plan, and remaining items.

## Relationship to other skills

- **`@plan`** — provides the Implementation checklist `@build` works through, and receives the completed work via `@plan promote`.
- **`@docs`** — the promotion target: `@plan promote` calls `@docs new` to write the feature doc; both maintain the single `docs/README.md` TOC.
- **`@validate` / `@go-test` / `@go-build` / `@codegen`** — the validation stack every chunk runs through.
- **[`@db-migrate`](./db-migrate.md)** — the only way to add schema migrations (expand/contract).
- **`@harbor-reviewer`** — the review gate after each chunk and at completion.
- **`@github-flow`** — stages, commits, and pushes each chunk.
- **[`@openspec`](./openspec.md)** — the paired formal spec that must **verify** (`openspec validate <slug> --strict`) before promote, and be **archived** (`@openspec archive <slug>`) on ship.
- **[`@hippo`](./hippo.md)** — cross-session agent memory: recall at start, drive live/ad-hoc items and captured friction through `hippo todo` while working the plan's checklist.

## Checklist

- [ ] **Recalled** at session start (`@hippo`) and any ad-hoc/live items + friction captured in `hippo todo`?
- [ ] Building from a plan whose `status` is **approved**, flipped to **in-progress** on start?
- [ ] Each chunk **thought through (`@deep-thinker`) → implemented → validated (`@validate`/`@go-test`/`@go-build`) → reviewed iteratively (`@harbor-reviewer` + `@deep-code-reviewer` until only nits) → committed (`@github-flow`)**?
- [ ] Any `api/` change regenerated via **`@codegen`** with `@validate` drift clean (no hand-edited generated files)?
- [ ] **Negative/security tests** from the checklist green before each chunk is done?
- [ ] Checklist `- [x]` boxes ticked and deviations noted **in the plan** as work lands?
- [ ] Paired **OpenSpec change verified** (`openspec validate <slug> --strict`) before promote, and **archived** (`@openspec archive <slug>`) on ship?
- [ ] Plan kept **`in-progress` until its PR is merged into `main`** (a working-branch/`weft/*` merge does **not** count)?
- [ ] On completion: *Definition of done* met, PR **merged into `main`** with CI green, then **verified via the merged gate** (`@plan merged <slug> <pr#>`: PR merged to `main`, `targets:` paths present on `origin/main`, migration number unique) before `status: merged`?
- [ ] Only after `merged`: **`@plan promote <slug>`** graduates the plan into a feature doc and updates `docs/README.md`?
