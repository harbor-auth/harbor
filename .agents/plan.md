---
name: plan
description: Author future-work plans and graduate them into feature docs as they ship — Harbor's plan→doc lifecycle.
---

Plan a feature **in full before building it**, then — as it ships — **graduate the plan into a feature doc**. This is the same living-toolkit lifecycle as `code-review → harbor-reviewer` in [`.agents/README.md`](./README.md): intent is captured, refined, and promoted once it's real. Because we build **exclusively with agentic systems**, a good plan is the executable brief an implementer (or `@build`) works straight through.

> **Update this skill:** if the plan layout, lifecycle, or promotion workflow below drift from how we actually work, fix this file as part of your change. A stale skill is a bug.

## Principle

A **plan** is future WHAT (`docs/plans/`); a **feature doc** is as-built WHAT+HOW (`docs/features/`). Plans sit **below `DESIGN.md`** in the hierarchy and must align with it (§ cross-refs); they sit **above the feature docs** they eventually become. When the work lands, the plan **promotes** into a feature doc and its row moves from the Plans table to the Features table in [`docs/README.md`](../docs/README.md).

Alongside each plan we author a **paired, formal OpenSpec change** (`openspec/changes/<slug>/`, same slug) — the machine-verifiable spec of WHAT changes — managed by [`@openspec`](./openspec.md). The plan is the plan-of-record; the OpenSpec change is its validated contract, gated by `openspec validate <slug> --strict`.

## Invocation

```
@plan new <slug>                 # author a new plan from the template
@plan status <slug> <state>       # advance lifecycle (draft→approved→in-progress→merged→…)
@plan merged <slug> <pr#>         # mark code as landed on main (VERIFY against origin/main first)
@plan promote <slug>              # graduate a merged plan into a feature doc
```

## Layout

```
docs/
  README.md              # Plans table (index) lives here
  DESIGN.md              # authoritative design — now an INDEX (§ → file map)
  design/                # the design tree: focused files, each ≤ ~2,000 words
    principles/  product/  protocol/  architecture/
    security/  backend/  flows/  governance/  threat-model/
  plans/<slug>.md        # future-work plans
  _templates/plan.md
```

**Resolving a DESIGN `§`:** DESIGN.md is an **index, not a monolith**. When a plan cites a `design_refs` like `§3.2`, open [`docs/DESIGN.md`](../docs/DESIGN.md), read the **`§ → file` map**, and navigate to the one file that owns that section (e.g. `§3.2` → `design/protocol/ppid.md`). Never assume the prose lives inline in `DESIGN.md`.

## Lifecycle

```
draft → approved → in-progress → merged → promoted
                              ↘ abandoned
```

- **draft** — authored, still taking shape.
- **approved** — agreed as the plan of record; ready to build.
- **in-progress** — being implemented; the **implementation checklist is ticked** as tasks land.
- **merged** — the plan's code has **actually landed on `main`**: its PR is merged, CI (`agent-check` + `e2e`) was green, and its migrations/paths are present on `main`. This is the gate that separates "an agent finished on a branch" from "shipped" — **do not skip it** (see *The merged gate* below).
- **promoted** — merged **and** graduated into a feature doc (terminal; the plan stays as historical provenance).
- **abandoned** — dropped; kept for the record with a note on why.

> **There is no `completed` state.** "Done" is the two-step `merged → promoted`: first prove the code is on `main`, then write the feature doc. A plan whose branch was merged into *another agent branch* (e.g. an ephemeral `weft/*` branch) but never into `main` is **not `merged`** — its status must stay `in-progress` until the code is verifiably on `main`.

## The merged gate — why it exists

A past incident: several plans were marked done and had their branches merged **on the agent's own throwaway `weft/*` branches**, but the code **never actually landed on `main`**. Nothing caught it, because:

- Plan status (`status:` / `promoted_to:`) is honor-system YAML — no tool verifies the referenced code or feature doc exists on `main`.
- `agent-check` deliberately has **no git-history dependency** (§1.8), so it cannot ask "does `main` contain this plan's code?"
- Merging an ephemeral branch into another ephemeral branch is **not** merging into `main`. The workflow conflated "agent finished" with "shipped."
- The tell-tale sign was a wave of **migration-number collisions** (multiple branches all grabbing the same `NNNN_` prefix) — proof nobody was integrating against `main`.

The **`merged` state is the fix**: a plan may only advance to `merged` after an agent has **verified against `main`**, not against a working branch:

```
git fetch origin main
git log origin/main --oneline | grep <the plan's merge commit / PR #>   # PR is on main
git ls-tree -r origin/main --name-only | grep -E '<targets: paths>'      # code is on main
ls db/migrations/ | grep <migration prefix>                              # migration present, no collision
gh pr view <#> --json state,mergedAt,statusCheckRollup                   # merged + CI green
```

Only once `origin/main` demonstrably contains the plan's code (and CI was green on the PR that landed it) may the frontmatter flip to `merged`. `promoted` then requires the feature doc on top of that.

## Workflows

### Author (`@plan new <slug>`)

1. `cp docs/_templates/plan.md docs/plans/<slug>.md`.
2. Fill the frontmatter (`design_refs`, predicted `targets`, `created`).
3. Write **Problem → Proposed approach → DESIGN alignment → Target code paths → Implementation checklist → Risks → Definition of done**. The **implementation checklist** is the executable to-do list — make it concrete (include negative/security tests).
4. Add a row to the **Plans** table in `docs/README.md` (`status: draft`).
5. Author the **paired OpenSpec change** with **`@openspec new <slug>`** (proposal + spec deltas + tasks) and **verify it with `openspec validate <slug> --strict`** before the plan is ready to build. Keep the **same slug** so the plan and its spec pair 1:1.

Advance state as work proceeds with `@plan status <slug> <state>` (update the frontmatter `status` **and** the Plans table row together).

### Mark merged (`@plan merged <slug> <pr#>`) — the anti-drift gate

Before a plan can be promoted, its code must be **proven on `main`**. This is a separate, explicit step precisely because "an agent finished on a branch" is *not* "shipped" (see *The merged gate* above). Do **not** flip a plan to `merged` off the strength of a working-branch merge — verify against `origin/main`:

1. `git fetch origin main` — refresh the ref you're about to check against.
2. Confirm the **PR is merged into `main`**: `gh pr view <pr#> --json state,mergedAt,baseRefName` shows `state: MERGED`, a non-null `mergedAt`, and `baseRefName: main`.
3. Confirm **CI was green** on that PR (`agent-check` + `e2e`): `gh pr view <pr#> --json statusCheckRollup`.
4. Confirm the **code is actually on `main`**: every path in the plan's `targets:` resolves under `git ls-tree -r origin/main`, and any migration has a **unique** number (no collision with another migration on `main`).
5. Only then flip the frontmatter to `status: merged` (update the Plans-table row together).

If any check fails — PR not merged to `main`, red CI, missing code, or a migration-number collision — the plan stays `in-progress`; fix the real gap, don't paper over it with a status flip.

### Promote (`@plan promote <slug>`) — the crucial hand-off

**Precondition:** the plan is already `merged` (its code is verifiably on `main`). Never promote straight from `in-progress` — promoting an unmerged plan is exactly the drift the `merged` gate exists to prevent.

Once the plan is `merged` and its **Definition of done** is met:

1. **Create the feature doc** via **`@docs new <slug>`**, drawing the content from the plan (the plan's *Proposed approach* + *Target code paths* become the feature's *Behavior* + *Code map*), reconciled against the **actual** code on `main`.
2. **Record bidirectional provenance:** set the feature doc's `plan: plans/<slug>.md`, and the plan's `promoted_to: features/<slug>.md`.
3. **Flip** the plan's `status: promoted`.
4. **Move the row** from the Plans table to the Features table in `docs/README.md`.
5. **Leave the promoted plan in place** as historical provenance — **do not delete it**.

## Relationship to other skills

- **`@docs`** — promotion calls `@docs new` to create the feature doc; both skills maintain the single `docs/README.md` TOC. Query existing docs with `@docs query` before authoring a plan (avoid duplicating a shipped feature).
- **`@build`** — a plan's **Implementation checklist** is exactly what [`@build`](./build.md) works through: it drives the build straight from `docs/plans/<slug>.md`, ticking the `- [ ]` boxes as tasks land. When the checklist is done and the *Definition of done* is met, `@build` hands off to **`@plan promote`** to graduate the plan into a feature doc.
- **[`@openspec`](./openspec.md)** — each plan is paired **1:1** with an OpenSpec change of the **same slug**; `@openspec verify` (`openspec validate <slug> --strict`) is the formal gate on the spec. OpenSpec does **not** replace `@plan` — the plan stays the plan-of-record.

## Checklist

- [ ] Checked with **`@docs query`** that this isn't already a shipped feature?
- [ ] Plan copied from the **template**; frontmatter (`design_refs`, `targets`, `created`) filled?
- [ ] **Implementation checklist** is concrete and includes tests (incl. negative/security)?
- [ ] **DESIGN aligned** — cites `§`, and any design change is surfaced explicitly (not smuggled in)?
- [ ] Row added to the **Plans** table in `docs/README.md`?
- [ ] Paired **OpenSpec change** authored (`@openspec new <slug>`) and **verified** (`openspec validate <slug> --strict`) — same slug as the plan?
- [ ] Before `merged`: **verified against `origin/main`** — PR merged to `main`, CI green, `targets:` paths present, migration number unique (no collision)?
- [ ] On promote: plan was already **`merged`**, feature doc created via `@docs`, **bidirectional provenance** set, `status: promoted`, row **moved** to Features, plan **left in place**?
