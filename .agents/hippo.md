---
name: hippo
description: Use Hippo persistent memory every session — recall context, track work with `hippo todo`, and capture friction as todos so nothing is lost when context truncates.
---

Hippo is Harbor's cross-session **agent memory** — persistent memory plus a knowledge graph, driven from the `hippo` CLI. Because we build Harbor **exclusively with agents** whose context windows get **truncated**, Hippo is how work survives across sessions: we **recall** before starting, **track** everything on the durable `hippo todo` list, and **capture** any friction as a todo so we can circle back and close the loop. This is `docs/DESIGN.md` §1.9 (the living toolkit — capture repeated work) applied to the agent's own working state.

> **Update this skill:** if the `hippo` CLI surface, subcommands, or the ritual below drift from how we actually work, fix this file as part of your change. A stale skill is a bug.

## Principle

**Truncation is inevitable; unrecorded work is lost work.** So, every session:

1. **Recall first.** Before starting any task, ground yourself in prior sessions (`hippo snapshot` / `search` / `context-search`). Don't re-derive what a past session already figured out.
2. **Track on the durable list.** When you have many things to do, add them **all** to `hippo todo` **up front**, then work through them, marking each `done` as it lands. **The list is the memory — not your context window.**
3. **Capture friction the moment it appears.** The instant you hit an error, blocker, or uncertainty — or you don't know how to do something — immediately `hippo todo add` a concrete entry (with the error text and your best hypothesis) and **keep going on the main task**. Circle back to close the loop later. Never let a side-quest silently derail the main goal or be forgotten at truncation.

The project is auto-detected from `.hippo/project.yaml` (already initialized in this repo), so commands need no `--project`. Add `--quiet` in scripts to suppress info logs.

> **Don't guess the CLI.** Use `hippo <command> --help` for exact subcommands and argument shapes before scripting them — the surface evolves. (Note: the version is `hippo version`; there is **no** `--version` flag.)

The friction loop at the heart of this skill:

```
  working the MAIN task
         │
         ▼
   hit error / blocker / "how do I…?"
         │
         ├──►  hippo todo add "<command · error · file · hypothesis>"   (capture, don't dive in)
         │
         ▼
  keep going on the MAIN task ─────────────────────────┐
         │                                              │
         ▼                                              │
   main task lands                                      │
         │                                              │
         ▼                                              ▼
   hippo todo list  ──►  resolve friction  ──►  hippo todo done <id>   (close the loop)
```

## Start of session — recall first

```bash
hippo health                       # confirm OpenSearch/Neo4j are reachable (see "Degrade gracefully")
hippo snapshot                     # recent memory activity — what happened lately
hippo sessions                     # list recent sessions
hippo search "oidc token flow" --limit 10       # keyword/semantic search of memory
hippo context-search "why does /token peek before consume?"   # smart, LLM-powered context
hippo recall                       # walk the full recall workflow interactively
```

Start broad (`snapshot`, `sessions`) then narrow (`search`, `context-search`) on the specific topic you're about to work on. `search` supports `--format json`, `--limit`, `--since`/`--until` (e.g. `--since 7d`), and `--full`/`--verbose`. A few more read-only lenses when you need them:

```bash
hippo context "pkce verifier length"   # retrieve context for a query
hippo explain "<query>"                 # why results are relevant to a query
hippo timeline                          # chronological timeline of memory runs
hippo stats                             # memory system statistics
```

## Working memory (the current session's goal + plan)

Use `hippo wm` to hold the **current** session's intent, so a fresh session can pick up exactly where this one left off:

```bash
hippo wm goal "Backfill golden vectors for PPID and PKCE"   # set the session goal
hippo wm plan "1) freeze ppid vectors 2) freeze pkce vectors 3) wire byte-equality tests"
hippo wm show                      # show this session's goal/plan/context
hippo wm advance                   # move to the next plan step
hippo wm context                   # manage session context variables (see `hippo wm context --help`)
hippo wm complete                  # mark the goal completed
```

`wm` is **per-session** working state (goal/plan/context). It complements — but does not replace — the durable `hippo todo` list below.

## Durable to-dos (`hippo todo`) — the anti-truncation list

`hippo todo` is the **project-level** task list (durable, survives truncation and new sessions). This is the backbone of the ritual:

```bash
hippo todo add "Freeze PPID golden vectors in internal/identity/testdata"
hippo todo add "Add import-boundary test: harbor-hot must not import db/"
hippo todo list                    # all todos, including completed
hippo todo done <id>               # close a todo as it lands
```

**The rule:** when a task has many parts, **batch-add them all to `hippo todo` before starting**, then work the list top to bottom, running `hippo todo done <id>` as each completes. Because it persists, a truncated or brand-new session just runs `hippo todo list` to see exactly what remains.

**`hippo todo` vs `hippo tasks`:** `todo` is the **durable project list** (use this for real work items). `hippo tasks` is **within-session** working-memory tasks, handy for ephemeral sub-steps of the current session:

```bash
hippo tasks add "regenerate sqlc after schema tweak"
hippo tasks list
hippo tasks update <id> done
```

When in doubt, use `hippo todo` — durability is the whole point.

## Capture friction as a todo (close the loop)

This is the highest-value habit. **The moment something goes sideways, record it and continue** — don't lose the main thread chasing a side-quest, and don't lose the side-quest either.

Worked example — mid-way through implementing a feature, `go test` fails:

```bash
# You were building feature X; a test breaks. DON'T silently dive in and forget X.
# Immediately record the friction with enough info for a FRESH session to act:
hippo todo add "fix: go test ./internal/oidc failing — TestToken_ReusedCode: \
  got invalid_request want invalid_grant; suspect errors.go mapping; retry after \
  checking token.go consume path"

# ...keep working the MAIN task (feature X). Later, circle back:
hippo todo list                    # find the friction todo
# resolve it, then:
hippo todo done <id>
```

**Record enough that a cold-start session could act on it:** the exact command, the error text, the file(s) involved, and your hypothesis for the fix. A friction todo with just "tests broken" is nearly useless after truncation.

## Store learnings (regular memory)

Beyond actionable todos, persist **durable insights** about the codebase so future sessions inherit them:

```bash
hippo store                        # persist a run/learning into memory (see `hippo store --help` for args)
hippo session-summary              # LLM summary of this session (run at the end)
hippo undo                         # delete the most recently stored run (mis-store)
```

`store` is for **durable insight** ("the hot path verifies JWTs offline via cached JWKS — never add a DB call there"); `todo` is for **actionable work**. End a working session with `hippo session-summary` so the next agent can recall it.

## Degrade gracefully

If `hippo health` shows the backend (OpenSearch/Neo4j) is unavailable, **don't block** — fall back to the assistant's own `write_todos` for in-session tracking and note the degraded state, then resume Hippo (recall + `hippo todo`) once it's reachable. `hippo todo` is the durable list **only when the backend is up**.

## Relationship to other skills

- **`@plan` / `@docs`** are Harbor's **in-repo memory** — durable *design* (`docs/plans/`) and *as-built feature* (`docs/features/`) truth, versioned with the code. **`@hippo`** is **cross-session agent memory** — live working state, recall, and friction. They're complementary layers, not substitutes: a friction todo that recurs and becomes real work should **graduate into a `@plan`**; a durable learning about how the codebase works belongs in a **`@docs`** feature doc.
- **`@build`** works a plan's implementation checklist; while it runs, use `hippo todo` to track the **live and ad-hoc** items (and any friction) that aren't in the plan's checklist — then reconcile back to the plan/docs when the work lands.

## Checklist

- [ ] **Recalled** at session start (`snapshot` / `search` / `context-search`) and confirmed `hippo health`?
- [ ] Session **goal + plan** set in `hippo wm`?
- [ ] **All known tasks** added to `hippo todo` **before** starting the work?
- [ ] **Friction captured** as a `hippo todo` the moment it appeared — with enough info (command, error, file, hypothesis) for a fresh session to act?
- [ ] Todos marked **`done`** as they land, so `hippo todo list` always reflects reality?
- [ ] **Learnings stored** (`hippo store`) and the session **summarized** (`hippo session-summary`) at the end?
