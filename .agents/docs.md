---
name: docs
description: Manage, query, and reconcile Harbor's feature docs against the codebase — the agent-consumable memory of the system.
---

Harbor's feature docs are the **agent-consumable memory** of what the system does. Because we build **exclusively with agentic systems**, an implementer's first move is to *query the docs* for grounding, and our standing obligation is to keep those docs **true to the code**. A doc that disagrees with the code is a bug — **reconcile it**.

> **Update this skill:** if the doc layout, frontmatter schema, or the reconcile workflow below drift from how we actually work, fix this file as part of your change. A stale skill is a bug.

## Principle

The knowledge hierarchy (see [`docs/README.md`](../docs/README.md)):

```
DESIGN.md → docs/plans/ → docs/features/ → code
```

`DESIGN.md` is now a **navigable index** (not one monolith): its `§ → file` map points into a tree of focused files under `docs/design/` (each ≤ ~2,000 words, per the small-files principle §1.10). The `§`-numbering is preserved across the split, so any `design_refs: [§x.y]` still resolves — via the map in `DESIGN.md` — to exactly one file.

**Source-of-truth rule:** for a **feature doc, the code is reality** — on drift, reconcile the doc to the code. Docs **never contradict `DESIGN.md`**; a real divergence from the design is a **DESIGN change**, surfaced explicitly by editing the **owning file in the design tree** (resolve the `§` via `DESIGN.md`'s map, then edit that file — e.g. `design/protocol/tokens.md`), not by quietly documenting the deviation in a feature doc. This mirrors `@validate`/`@codegen`, which keep *code ↔ spec* honest (§1.5) — `@docs reconcile` keeps *doc ↔ code* honest, one layer up.

## Invocation

```
@docs query <topic>          # find the doc(s) for a topic — grounding before you build
@docs reconcile [slug|all]    # detect & fix doc↔code drift (the centerpiece)
@docs new <slug>              # create a new feature doc from the template
@docs update <slug>           # revise an existing feature doc after a code change
```

## Layout

```
docs/
  README.md            # THE feature/plan index (TOC) — always start here
  DESIGN.md            # authoritative design — now an INDEX (§ → file map)
  design/              # the design tree: focused files, each ≤ ~2,000 words
    principles/  product/  protocol/  architecture/
    security/  backend/  flows/  governance/  threat-model/
  OIDC-LOGIN-FLOW.md   # index into the §11.2 flow walkthrough
  oidc-flow/           # the 4-part Authorization Code + PKCE walkthrough
  ARCHITECTURE.md      # one-page high-level on-ramp
  features/<slug>.md   # as-built feature docs
  _templates/feature.md
```

**Resolving a DESIGN `§`:** never grep the whole tree blindly. Open [`docs/DESIGN.md`](../docs/DESIGN.md), read its **`§ → file` map**, and jump to the one file that owns that section (e.g. `§3.2.1` → `design/protocol/ppid.md`, `§11.2` → `OIDC-LOGIN-FLOW.md` → `oidc-flow/`). The map is the single source of truth for where a section lives.

## Frontmatter (the machine-readable layer that makes reconcile possible)

Every feature doc carries the frontmatter from [`docs/_templates/feature.md`](../docs/_templates/feature.md). The **drift-anchor** fields:

- `code`, `spec`, `tests` — repo paths reconcile checks for existence and change.
- `last_reconciled` — the date the doc was last verified against the code (the drift clock).
- `status`, `design_refs`, `depends_on`, `plan` — status, DESIGN cross-refs, dependency slugs, and provenance (the plan it graduated from).

## Workflows

### (a) Query — grounding before building

**Always read `docs/README.md` first** (the TOC), then narrow with ripgrep:

```bash
rg -l '§3.1' docs/features/            # docs realizing a DESIGN section
rg -l 'internal/oidc' docs/features/    # docs that map to a code path
rg -li 'pkce|passkey|ppid' docs/features/   # docs by topic/keyword
```

Return the matching doc **plus its `design_refs` and `code` paths**, so the implementer starts grounded in the right DESIGN sections and packages. If no doc exists, say so — that's a gap to fill with `@docs new` (or a `@plan`).

**Grounding in the design itself?** Resolve the `§` through `DESIGN.md`'s map rather than searching prose across the tree:

```bash
rg -n '§3.2' docs/DESIGN.md             # find the file that owns the section
rg -l 'pkce|ppid|relay' docs/design/    # topic search across the design tree
```

The map yields the one file to read (e.g. `design/protocol/ppid.md`); the §11.2 login flow lives in `OIDC-LOGIN-FLOW.md` → `oidc-flow/`.

### (b) Create / Update

1. `cp docs/_templates/feature.md docs/features/<slug>.md`.
2. Fill the frontmatter (real `code`/`spec`/`tests` paths) and write the body sections.
3. Cross-link the DESIGN `§` it realizes and any `depends_on` docs.
4. **Add/refresh its row** in the Features table of `docs/README.md`.
5. Set `last_reconciled` to **today** (you just verified it against the code).

**Update** is the same, minus the copy: revise the body + frontmatter after a code change and re-stamp `last_reconciled`.

### (c) Reconcile — detect & fix doc↔code drift (the centerpiece)

Run for one `slug` or `all`. Produce a **drift report grouped by severity**.

1. **Path existence** — every `code`/`spec`/`tests` path resolves:
   ```bash
   for p in <paths-from-frontmatter>; do test -e "$p" || echo "MISSING: $p"; done
   ```
2. **Change-since-anchor** — has the code moved since the doc was last verified?
   ```bash
   git log --oneline --since=<last_reconciled> -- <code paths>
   ```
   Any commits ⇒ the doc is **possibly stale** — re-verify its body claims.
   (`--since=<date>` is robust on any clone; avoid the `@{<date>}` reflog syntax,
   which fails for dates without a reflog entry.)
3. **Claim spot-check** — read the doc's stated behavior/invariants and confirm each in the code. E.g. a doc claiming *"PKCE S256 only"* ⇒
   ```bash
   rg -n 'ChallengeMethodS256|S256' internal/oidc/
   ```
   A claim you can't confirm is a **stale claim** — fix the doc to match reality.
   To check a claim against the **design**, resolve its `§` via `DESIGN.md`'s map first, then read the one owning file under `docs/design/` (or `oidc-flow/` for §11.2) — don't assume `DESIGN.md` still holds the prose inline; it's an index now.
4. **Undocumented code (reverse check)** — enumerate the code and subtract what's documented:
   ```bash
   ls -d internal/*/ cmd/*/                     # every package
   rg -o 'internal/\S+|cmd/\S+' docs/features/ | sort -u   # documented paths
   ```
   Packages in the first list but not the second are **undocumented** — flag them (candidates for `@docs new` or a `@plan`).
5. **design_refs integrity** — run the automated check to confirm every `design_refs: [§x.y]` resolves in `DESIGN.md`'s `§ → file` map:
   ```bash
   make docs-check          # exit 0 ⇒ all refs resolve; exit 1 ⇒ fix listed refs
   # or directly:
   python3 tools/check-design-refs.py
   ```
   A failure means either (a) update the feature doc's `design_refs` to a valid `§`, or (b) add the missing `§` to the map in `DESIGN.md`.
6. **Index sync** — every `docs/features/*.md` has a row in `docs/README.md`, and every Features row points at a real doc. A mismatch is an **index bug**.
7. **On a clean verify**, bump `last_reconciled` to today.

**Drift report buckets:** `missing paths` · `stale claims` · `undocumented code` · `index mismatch`.

### (d) Index maintenance

The Features/Plans tables in `docs/README.md` are authoritative. Any create/update/status change updates the index **in the same change**; `reconcile` enforces it (step 5).

## Relationship to other skills

- **`@validate` / `@codegen`** — keep *code ↔ spec* honest (contract drift, §1.5). **`@docs reconcile`** — keeps *doc ↔ code* honest. Same philosophy, one layer up; together they're Harbor's anti-drift stack.
- **`@plan`** — `@plan promote` calls `@docs new` to graduate a shipped plan into a feature doc; both maintain the single `docs/README.md` TOC.

## Checklist

- [ ] Queried **`docs/README.md` first**, then narrowed with `rg`?
- [ ] New/updated doc copied from the **template**, frontmatter filled with **real** `code`/`spec`/`tests` paths?
- [ ] DESIGN `§` and `depends_on` **cross-linked**?
- [ ] **Index row** in `docs/README.md` added/refreshed?
- [ ] On reconcile: paths exist · claims verified · undocumented code listed · index in sync?
- [ ] `last_reconciled` **stamped today** after verifying against code?
