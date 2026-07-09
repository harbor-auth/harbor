---
title: Adopt Hippo as standing agent memory
status: promoted           # draft | approved | in-progress | promoted | abandoned
design_refs: [§1.9]        # DESIGN.md sections this work serves
targets: [.agents/hippo.md, .agents/README.md, .agents/build.md]
promoted_to: features/hippo-usage.md   # features/<slug>.md once implemented, else null
created: 2026-07-08        # date this plan was authored
---

# Adopt Hippo as standing agent memory (plan)

## Problem

We build Harbor **exclusively with agents**, across many sessions whose context
windows get **truncated**. Without a disciplined memory practice, prior context,
in-flight work, and friction/blockers are silently lost between (and within)
sessions. Hippo is installed (persistent memory + knowledge graph, with `todo` /
`tasks` / `wm`), but there is **no codified practice** for using it every session
— so its value is left on the table.

## Proposed approach

Adopt the **`@hippo`** skill (which this plan promotes) as a **standing ritual**:

1. **Recall** at session start (`hippo snapshot` / `search` / `context-search`).
2. **Drive work from `hippo todo`** — batch-add all known tasks up front, then
   work through the durable list, marking each `done` as it lands.
3. **Capture friction as a todo** the moment it appears (error/blocker/unknown),
   with enough info for a fresh session to act, then continue the main task and
   circle back to close the loop.
4. **Store learnings** and run `hippo session-summary` at the end.

Make it habitual by lightly cross-referencing the ritual from the other workflow
skills (notably `@build`). Keep the durable-`todo` vs session-`tasks` vs
working-memory (`wm`) distinction explicit.

**Alternatives considered:** (a) rely on the in-repo `@plan`/`@docs` only —
*rejected*: those track durable *design/feature* truth, not live per-session
working state and recall. (b) rely on the assistant's own `write_todos` —
*rejected*: it does not survive truncation or cross sessions (though it is the
correct **fallback** when the Hippo backend is unavailable).

## DESIGN alignment

Serves **§1.9** (living toolkit — capture repeated work as a skill; *a stale
skill is a bug*). It does **not** change `DESIGN.md`. It **complements** the
knowledge hierarchy (DESIGN → plans → features → code) with a **cross-session
working-memory layer** that is explicitly *not* a substitute for the in-repo
docs — durable design/feature truth still lives in `docs/`.

## Target code paths

- `.agents/hippo.md` — the skill (recall / `wm` / `todo` / `tasks` / `store`,
  plus the friction→todo→circle-back loop).
- `.agents/README.md` — Index row for `@hippo`.
- Light references from other skills (e.g. `@build` session-start + error
  recovery).

## Implementation checklist

- [x] Author the `@hippo` skill (`.agents/hippo.md`) with **real** Hippo CLI
      examples (recall / `wm` / `todo` / `tasks` / `store`) and the
      friction→todo→circle-back loop.
- [x] Index `@hippo` in `.agents/README.md`.
- [x] Reference `@hippo` from `@build`'s session-start (recall + drive from
      `hippo todo`) and its **Error Recovery** (capture friction as a todo) —
      lightweight cross-links.
- [x] Add a short **connectivity** note (`hippo health`) so agents detect when
      Hippo is unavailable and degrade gracefully to `write_todos`.
- [x] Tests/validation: docs/skills only — validate **consistency** (frontmatter
      valid, every CLI command matches `hippo --help`, index rows present, links
      resolve).
- [x] Reconcile & promote: `@plan promote hippo-usage` once the practice is in
      steady use (it graduates into a feature doc, or stays a standing skill).

> **Promoted 2026-07-08** → [`features/hippo-usage.md`](../features/hippo-usage.md). Note: during implementation the skill **graduated into a dedicated agent** (`.agents/hippo.ts`) that auto-recalls at session start — the second skill→agent graduation after `harbor-reviewer`.

## Risks & open questions

- **Backend availability:** the Hippo backend (OpenSearch/Neo4j) may be down in
  some environments. Agents must **degrade gracefully** (fall back to
  `write_todos`) and never block; the skill must stay honest that `hippo todo`
  is the durable list **only when the backend is up**.
- **Open question:** should friction-todos that **recur** graduate automatically
  into a `@plan` item? *(Proposed: yes — when the same friction is hit ≥2
  times, promote it to a plan.)*

## Definition of done

The `@hippo` skill exists and is indexed; the plan row is in `docs/README.md`;
the other workflow skills cross-reference the recall + `hippo todo` ritual; and
in practice agents reliably **recall at start** and **capture friction as
todos**. Consistency checks pass (valid frontmatter, CLI commands match the real
`hippo` surface, index rows and links resolve).
