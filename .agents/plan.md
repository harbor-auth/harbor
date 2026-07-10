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
@plan status <slug> <state>       # advance lifecycle (draft→approved→in-progress→…)
@plan promote <slug>              # graduate a shipped plan into a feature doc
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
draft → approved → in-progress → promoted
                              ↘ abandoned
```

- **draft** — authored, still taking shape.
- **approved** — agreed as the plan of record; ready to build.
- **in-progress** — being implemented; the **implementation checklist is ticked** as tasks land.
- **promoted** — shipped and graduated into a feature doc (terminal; the plan stays as historical provenance).
- **abandoned** — dropped; kept for the record with a note on why.

## Workflows

### Author (`@plan new <slug>`)

1. `cp docs/_templates/plan.md docs/plans/<slug>.md`.
2. Fill the frontmatter (`design_refs`, predicted `targets`, `created`).
3. Write **Problem → Proposed approach → DESIGN alignment → Target code paths → Implementation checklist → Risks → Definition of done**. The **implementation checklist** is the executable to-do list — make it concrete (include negative/security tests).
4. Add a row to the **Plans** table in `docs/README.md` (`status: draft`).
5. Author the **paired OpenSpec change** with **`@openspec new <slug>`** (proposal + spec deltas + tasks) and **verify it with `openspec validate <slug> --strict`** before the plan is ready to build. Keep the **same slug** so the plan and its spec pair 1:1.

Advance state as work proceeds with `@plan status <slug> <state>` (update the frontmatter `status` **and** the Plans table row together).

### Promote (`@plan promote <slug>`) — the crucial hand-off

Once the plan's **Definition of done** is met:

1. **Create the feature doc** via **`@docs new <slug>`**, drawing the content from the plan (the plan's *Proposed approach* + *Target code paths* become the feature's *Behavior* + *Code map*), reconciled against the **actual** code.
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
- [ ] On promote: feature doc created via `@docs`, **bidirectional provenance** set, `status: promoted`, row **moved** to Features, plan **left in place**?
