---
title: Hippo as standing agent memory
status: implemented        # planned | in-progress | implemented | deprecated
design_refs: [§1.9]        # DESIGN.md sections this realizes (house § convention)
code:  [.agents/hippo.md, .agents/hippo.ts, .agents/README.md, .agents/build.md]   # repo paths that implement this feature (drift anchor)
spec:  []                  # contract paths, e.g. api/openapi/harbor.yaml (or [])
tests: []                  # test paths covering this feature
depends_on: []             # other feature slugs this builds on (or [])
plan: plans/hippo-usage.md # provenance: plans/<slug>.md it graduated from, or null
last_reconciled: 2026-07-08 # date the doc was last verified against the code
---

# Hippo as standing agent memory

## Summary

Harbor is built **exclusively by agents** whose context windows get **truncated**, so any
working state that isn't captured externally is silently lost between (and within) sessions.
Hippo — persistent memory plus a knowledge graph, driven from the `hippo` CLI — is Harbor's
**cross-session working memory**. This capability is the standing **ritual** for using it every
session, codified as the [`@hippo`](../../.agents/hippo.md) skill (`.agents/hippo.md`) and
operationalized by the dedicated `hippo` agent (`.agents/hippo.ts`). It realizes DESIGN **§1.9**
(the living toolkit — capture repeated work as a skill; *a stale skill is a bug*). It does **not**
change `DESIGN.md`; it adds a **cross-session working-memory layer** that complements — and is not
a substitute for — the in-repo knowledge hierarchy (`DESIGN.md → docs/plans/ → docs/features/ → code`).

## Behavior (as-built)

1. **Recall first.** At the start of any task, ground in prior sessions with `hippo health`
   (backend connectivity), `hippo snapshot` (recent activity), `hippo sessions`, and then narrow
   with `hippo search "<topic>"` / `hippo context-search "<question>"`. The dedicated `hippo` agent
   **auto-recalls at session start** via a `handleSteps` generator whose first step runs the recall
   commands; the command is **guarded by `command -v hippo`** so a missing binary degrades
   gracefully instead of erroring.
2. **Track on the durable list.** `hippo todo` (`add` / `done` / `list`) is the **project-level,
   truncation-surviving** to-do list. When a task has many parts, **batch-add them all up front**,
   then work the list top to bottom, running `hippo todo done <id>` as each lands. A fresh or
   truncated session just runs `hippo todo list` to see what remains.
3. **Per-session state.** `hippo tasks` (`add` / `list` / `update`) holds ephemeral within-session
   sub-steps, and `hippo wm` (`goal` / `plan` / `advance` / `complete` / `context` / `show` / `list`
   / `clear`) holds the current session's goal/plan/context so the next session can pick up where
   this one left off. Durable work belongs in `hippo todo`.
4. **Capture friction.** The instant an error, blocker, or uncertainty appears, immediately
   `hippo todo add` a concrete entry (**command · error · file · hypothesis**) and **continue the
   main task**, circling back later with `hippo todo done <id>`. Record enough that a cold-start
   session could act on it — "tests broken" is useless after truncation.
5. **Store learnings.** Persist durable insight with `hippo store` (distinct from actionable
   `todo`s), and end a working session with `hippo session-summary` so the next agent can recall it.
   `hippo undo` removes the most recent mis-stored run.
6. **Degrade gracefully.** If `hippo health` shows the backend (OpenSearch/Neo4j) is unavailable,
   **don't block** — fall back to the assistant's own in-session todos and resume Hippo once it's
   reachable. `hippo todo` is the durable list **only when the backend is up**.

The project is auto-detected from `.hippo/project.yaml`, so commands need no `--project`. The
version is `hippo version` (there is **no** `--version` flag).

## Interfaces / Endpoints

There are **no HTTP endpoints** — the surface is the `hippo` CLI plus two `.agents/` artifacts:

- **`hippo` CLI** (top-level): `health`, `snapshot`, `sessions`, `search`, `context-search`,
  `recall`, `context`, `explain`, `timeline`, `stats`, `store`, `session-summary`, `undo`,
  `wm`, `todo`, `tasks`, `version`.
- **`@hippo` skill** — invoked inline as `@hippo`; a thin pointer to the canonical CLI ritual.
- **`hippo` agent** — spawned as an agent (`@hippo`); auto-recalls at session start and drives the
  ritual.

## Code map

| Path | Role |
|---|---|
| `.agents/hippo.md` | The `@hippo` skill — canonical CLI ritual (recall / `wm` / `todo` / `tasks` / `store`) plus the friction→todo→circle-back loop. |
| `.agents/hippo.ts` | The dedicated `hippo` agent — auto-recalls at session start via a `handleSteps` generator (guarded by `command -v hippo`) and drives the ritual. |
| `.agents/README.md` | Living-toolkit index — skill-row pointer, a Dedicated agents row, and the "Second graduation" note. |
| `.agents/build.md` | Cross-links the recall + friction-capture ritual into the `@build` execution loop and error recovery. |

## Security & privacy invariants

- **No end-user data in Hippo.** Hippo stores agent working memory and developer notes — **never**
  Harbor end-user **PII, tokens, keys, or PPIDs** (aligns with the DESIGN **§2.2 / §6.5.7** privacy
  posture). Friction todos capture **commands, errors, and hypotheses**, not secrets.
- **Fail open for work, not for data.** Backend (OpenSearch/Neo4j) connectivity failures must
  **degrade gracefully** and never block the main task; work continues on the assistant's own todos
  until Hippo is reachable again.

## Tests

There are **no automated Go tests** — verification is a **consistency check** (the plan's validation
step):

- frontmatter valid (skill and plan);
- every `hippo` command referenced in `.agents/hippo.md` and `.agents/hippo.ts` matches the live
  `hippo --help` surface (top-level commands; `todo` = `add`/`done`/`list`; `tasks` =
  `add`/`list`/`update`; `wm` = `goal`/`plan`/`advance`/`complete`/`context`/`show`/`list`/`clear`);
- index rows present in `.agents/README.md` and `docs/README.md`;
- all relative markdown links resolve.

Re-run this consistency check whenever the `hippo` CLI surface changes.

## Known gaps / TODOs

- **Open question (from the plan):** should friction-todos that **recur** (hit ≥2 times)
  auto-graduate into a `@plan` item?
- **Follow-ups:** sync a one-line mention into DESIGN **§1.9**; ensure the `hippo` CLI is installed
  in the devcontainer/CI so agents avoid the degraded fallback path.
- Provenance: graduated from [`../plans/hippo-usage.md`](../plans/hippo-usage.md).
