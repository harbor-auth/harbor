---
# Plan template — copy to docs/plans/<kebab-slug>.md and fill in.
# Then add a row to docs/README.md (Plans table). A plan describes FUTURE work;
# once shipped it graduates into a feature doc via `@plan promote`.
title: <Human-readable feature name>
status: draft              # draft | approved | in-progress | promoted | abandoned
design_refs: [§0.0]        # DESIGN.md sections this work serves
targets: [internal/<pkg>/] # PREDICTED code paths (refined as work proceeds)
promoted_to: null          # features/<slug>.md once implemented, else null
openspec: changes/<slug>   # paired OpenSpec change (same slug) — @openspec new <slug>; verify: openspec validate <slug> --strict
created: YYYY-MM-DD        # date this plan was authored
---

# <Feature name> (plan)

## Problem

<!-- What gap or need this addresses. Why now. -->

## Proposed approach

<!-- The intended design at enough depth to build from. Note alternatives
     considered and why they were rejected. -->

## DESIGN alignment

<!-- How this fits the north star: cite the DESIGN § it serves and confirm it
     does NOT contradict the design. If it WOULD change the design, say so — a
     DESIGN change is explicit, not smuggled in via a plan (docs/README.md). -->

## Target code paths

<!-- The packages/files expected to be created or changed. These become the
     feature doc's `code:` map on promotion. -->

## Implementation checklist

<!-- The executable to-do list an implementer / `@build` works through. Tick
     each box as it lands; when all are done the plan is ready to promote. -->

- [ ] <task 1>
- [ ] <task 2>
- [ ] Tests: <what to cover, incl. negative/security tests>
- [ ] Author & verify paired OpenSpec change: `@openspec new <slug>` then `openspec validate <slug> --strict`
- [ ] Reconcile & promote: `@plan promote <slug>` → creates the feature doc

## Risks & open questions

<!-- Security/privacy risks, unknowns to resolve, decisions needing sign-off. -->

## Definition of done

<!-- The concrete, checkable conditions under which this is "shipped" and
     ready to graduate into docs/features/ (build/vet/tests green, invariants
     enforced, docs written). -->
