---
name: openspec
description: Author and VERIFY a formal OpenSpec change (proposal + spec deltas + tasks) alongside every Harbor plan — spec-driven development gated by `openspec validate --strict`.
---

Harbor plans the WHAT in `docs/plans/` (see [`@plan`](./plan.md)); **OpenSpec** adds a **formal, machine-VERIFIABLE spec artifact right next to it** — a reviewable `openspec/changes/<slug>/` holding requirements + scenarios that the [OpenSpec CLI](https://github.com/Fission-AI/OpenSpec) checks with `openspec validate --strict`. Because we build Harbor **exclusively with agents** (`docs/DESIGN.md` §1.9, the living toolkit), a spec a *tool* can validate keeps human and agent aligned on WHAT before any code is written. **The rule: we can have a plan, but we must ALWAYS have an OpenSpec spec, and we must VERIFY it (`openspec validate --strict`) afterwards.**

> **Update this skill:** if the `openspec` CLI surface, the `openspec/` layout, or the pair-with-a-plan workflow below drift from how we actually work, fix this file as part of your change. A stale skill is a bug. **Don't guess the CLI** — run `openspec <command> --help` for exact flags before scripting them; the surface evolves (parts are beta).

## Principle

Two complementary layers, neither of which replaces the other:

- **`@plan` (`docs/plans/<slug>.md`) — the plan-of-record (PRIMARY).** The executable brief an implementer / [`@build`](./build.md) works straight through.
- **OpenSpec (`openspec/changes/<slug>/`) — the paired formal spec (VERIFIABLE).** The reviewable contract of *what changes*: requirements and `#### Scenario:` blocks that `openspec validate --strict` structurally checks.

They pair **1:1 by slug**: `docs/plans/add-refresh-rotation.md` ↔ `openspec/changes/add-refresh-rotation/`. Cross-link them in both frontmatters so the plan and its spec never drift apart. Neither contradicts **`DESIGN.md`** (the north star, per [`docs/README.md`](../docs/README.md)); a genuine design change is still surfaced **explicitly** (edit `DESIGN.md`), never smuggled in through a plan or an OpenSpec change.

**OpenSpec does NOT replace `@plan`.** The plan stays the plan-of-record; OpenSpec is the formal, CLI-validated spec that travels alongside it.

## Install (one-time)

OpenSpec is the npm package **`@fission-ai/openspec`** (CLI: `openspec`). **Requires Node ≥ 20.19** (already provided by the pinned toolchain).

In Harbor's hermetic model the tool is **pinned in [`flake.nix`](../flake.nix) (Foundation F3)**, so prefer:

```bash
nix develop                 # openspec is on PATH inside the pinned shell
openspec --version
```

Fallback for environments without Nix (uses the pinned Node's npm):

```bash
npm install -g @fission-ai/openspec@latest
```

Initialize once per repo (creates the `openspec/` scaffold; `openspec/` is **committed**, versioned with the code like `docs/`):

```bash
openspec init                 # interactive (see `openspec init --help` for non-interactive tool selection)
```

> Telemetry is anonymous and off in CI; opt out anywhere with `export OPENSPEC_TELEMETRY=0` (or `DO_NOT_TRACK=1`).

## Invocation

```
@openspec new <slug>       # author openspec/changes/<slug>/ (proposal.md + specs/ + tasks.md)
@openspec verify <slug>    # openspec validate <slug> --strict     (the mandatory gate)
@openspec verify all       # openspec validate --all --strict
@openspec show <slug>      # openspec show <slug> [--json]
@openspec list             # openspec list [--json]   (browse changes/specs)
@openspec archive <slug>   # openspec archive <slug>  (merge deltas into openspec/specs/)
```

`@openspec new` is **our convention** for "author the change folder" — it maps to creating `openspec/changes/<slug>/` directly, not necessarily a literal CLI subcommand (**confirm any scaffolding subcommand with `openspec --help`; author the files directly if none exists**). Agents add `--json` to `verify`/`show`/`list` for structured output (and may pass `--concurrency <n>` to `validate`). Slug is lowercase kebab-case, cannot start with a number; prefix external tickets like `ticket-123-add-notifications`.

## Layout

```
openspec/
├── specs/                       # the accepted specifications (source of truth)
├── changes/
│   ├── <slug>/                  # one proposed change (pairs with docs/plans/<slug>.md)
│   │   ├── proposal.md          # why + what's changing
│   │   ├── specs/               # requirement + `#### Scenario:` DELTAS
│   │   ├── design.md            # technical approach (where non-trivial)
│   │   └── tasks.md             # implementation checklist
│   └── archive/YYYY-MM-DD-<slug>/  # archived, merged changes
└── project.md                   # project context / configuration
```

## Workflow (the spine)

### (a) New — author the change

Create the change folder `openspec/changes/<slug>/` and author its files directly (confirm any scaffolding subcommand with `openspec --help`; if none exists, just create the files):

- **`proposal.md`** — why + what's changing.
- **`specs/`** — the requirement DELTAS, each with `#### Scenario:` blocks.
- **`design.md`** — technical approach, where the change is non-trivial.
- **`tasks.md`** — the implementation checklist.

**Keep the slug identical to `docs/plans/<slug>.md`** so the plan and its spec pair 1:1.

### (b) Verify — the non-negotiable gate

```bash
openspec validate <slug> --strict       # one change; agents add --json
openspec validate --all --strict         # everything
```

**`--strict` MUST pass** before the change is considered ready — this is the "verify it afterwards" the workflow requires. Fix the spec (missing requirement, malformed scenario, absent tasks) until it validates. A non-zero exit is a hard stop, exactly like a failed [`@validate`](./validate.md).

### (c) Build — implement against the spec

Implement against `tasks.md` (and the paired plan's checklist). This is where [`@build`](./build.md) and Harbor's Go validation stack (`@validate` / `@go-test` / `@go-build` / `@codegen`) run. Track progress with `openspec show <slug>` / `openspec list`.

### (d) Archive — merge the spec into the source of truth

```bash
openspec archive <slug>                   # validates, merges deltas into openspec/specs/, moves to archive/
```

Once shipped, archiving folds the change's spec deltas into `openspec/specs/` (the accepted spec) and moves the change under `openspec/changes/archive/`. See `openspec archive --help` for flags (e.g. non-interactive / skip-specs for a tooling/doc-only change with no spec delta to merge).

## Relationship to other skills

- **[`@plan`](./plan.md)** — the **primary** plan-of-record. Pair **every** plan with an OpenSpec change of the **same slug**, and cross-link both frontmatters. OpenSpec does **not** replace `@plan`.
- **[`@build`](./build.md)** — works `tasks.md` / the plan's checklist; the **OpenSpec verify gate (`openspec validate --strict`) runs before promote**, alongside the Go validation stack.
- **[`@docs`](./docs.md)** — on promotion, the feature doc can **cite the archived OpenSpec spec** as the formal WHAT it realizes.
- **[`@validate`](./validate.md) / [`@codegen`](./codegen.md)** — keep *code ↔ spec/contract* honest (§1.5). **OpenSpec keeps *human ↔ intent* honest — one layer up.** Together they're Harbor's anti-drift stack, top to bottom.
- **[`@hippo`](./hippo.md)** — capture any OpenSpec friction as a `hippo todo` the moment it appears so it survives context truncation.

## Checklist

- [ ] A paired OpenSpec change exists at `openspec/changes/<slug>/` with the **same slug** as `docs/plans/<slug>.md`?
- [ ] **`proposal.md`** + **`specs/`** (requirements + `#### Scenario:` blocks) + **`tasks.md`** authored (`design.md` where non-trivial)?
- [ ] **`openspec validate <slug> --strict` passes** (the mandatory verify — a non-zero exit is a hard stop)?
- [ ] **Plan ↔ spec cross-links** set in **both** frontmatters (same slug, pointing at each other)?
- [ ] **DESIGN aligned** — cites the `§` it serves; any design change surfaced explicitly (not smuggled in)?
- [ ] On ship: **`openspec archive <slug>`** merged the deltas into `openspec/specs/` (skip-specs for tooling/doc-only — see `openspec archive --help`)?

> A stale skill is a bug — if the OpenSpec CLI or this workflow drifts, fix this file in the same change.
