# Harbor Docs — The Feature & Plan Index

The single entry point (TOC) for everything Harbor **does** and **plans to do**. This index exists so agents (and humans) can find the right doc fast, then reconcile it against the code. If you're building a feature, **start here**.

> **New to Harbor?** Read [`ARCHITECTURE.md`](ARCHITECTURE.md) first — a one-page, high-level map (hot/cold path, regions, KMS, the PII-free global plane) that's a gentler on-ramp than [`DESIGN.md`](DESIGN.md). [`DESIGN.md`](DESIGN.md) is now a **navigable index** into a tree of focused files under [`design/`](design/) (each ≤ ~2,000 words, per the small-files principle §1.10). Then see [`OIDC-LOGIN-FLOW.md`](OIDC-LOGIN-FLOW.md) for a step-by-step ASCII sequence diagram of the most complex sequence in the system (the Authorization Code + PKCE login flow, §11.2), backed by [`oidc-flow/`](oidc-flow/) sub-files.

> Managed by two skills: **[`@docs`](../.agents/docs.md)** (create / query / reconcile feature docs) and **[`@plan`](../.agents/plan.md)** (author future work and graduate it into feature docs).

## The knowledge hierarchy

```
DESIGN.md          → WHY + system-level WHAT — the design index (§0–§15)
   └─ design/       → topic-focused design files, each ≤ ~2,000 words
        └─ principles/, product/, protocol/, architecture/,
           security/, backend/, flows/, governance/, threat-model/
docs/plans/         → future WHAT — intent not yet built
   └─ docs/features/ → as-built WHAT + HOW — realized capabilities
        └─ code      → the ground truth for as-built behavior
```

**Source-of-truth rule:** for a **feature doc, the code is reality** — on drift, reconcile the *doc* to the *code* (`@docs reconcile`). Docs **never contradict `DESIGN.md`**; a genuine divergence from the design is a **DESIGN change**, surfaced explicitly (edit `DESIGN.md`, don't quietly document the deviation). This is the same anti-drift philosophy as `@validate`/`@codegen` (which keep *code ↔ spec* honest, §1.5) — one layer up, keeping *doc ↔ code* honest.

## Features (as-built)

| Doc | Status | DESIGN § | Code | Last reconciled |
|---|---|---|---|---|
| [ppid-identity](features/ppid-identity.md) | implemented | §3.2 | `internal/identity/` | 2026-07-08 |
| [webauthn-passkeys](features/webauthn-passkeys.md) | implemented | §3.1 | `internal/webauthn/`, `cmd/harbor-mgmt/` | 2026-07-08 |
| [oidc-authorization-code](features/oidc-authorization-code.md) | implemented | §3.1, §11.2, §11.7 | `internal/oidc/`, `internal/oidcapi/` | 2026-07-08 |
| [hippo-usage](features/hippo-usage.md) | implemented | §1.9 | `.agents/hippo.md`, `.agents/hippo.ts` | 2026-07-08 |
| [agentic-foundations](features/agentic-foundations.md) | implemented | §1.9, §A.8 | `invariants/`, `tools/`, `.github/`, `flake.nix` | 2026-07-08 |

## Plans (future / in progress)

| Plan | Status | DESIGN § | Promotes to |
|---|---|---|---|
| [envelope-encryption-kms](plans/envelope-encryption-kms.md) | draft | §4.4, §7.3, §10 | `internal/crypto/` |
| [real-token-issuance](plans/real-token-issuance.md) | draft | §3.3, §3.4, §7.3 | `internal/crypto/`, `internal/oidc/` |
| [client-grant-persistence](plans/client-grant-persistence.md) | draft | §3.2, §10 | `internal/oidc/`, `db/queries/` |
| [user-enrollment](plans/user-enrollment.md) | draft | §11.1, §10, §4.4 | `internal/identity/`, `internal/webauthn/` |
| [session-ppid-seam](plans/session-ppid-seam.md) | draft | §3.2, §11.2 | `internal/oidc/`, `internal/identity/` |
| [refresh-token-rotation](plans/refresh-token-rotation.md) | draft | §3.5, §10 | `internal/oidc/`, `db/queries/` |

> A plan appears here until it's implemented, then **`@plan promote`** moves its row into the **Features** table above. Author the next one with **`@plan new <slug>`**.

## How to use this index

- **Query starts here.** `@docs query <topic>` always reads this file first, then narrows into `docs/features/` (see the `@docs` skill).
- **`@docs reconcile` keeps it honest.** It verifies every doc's code/spec/test paths still exist, flags stale claims, lists undocumented code, and enforces that this table and `docs/features/*.md` stay in sync.
- **`@plan promote` moves a plan into Features.** When planned work ships, its row graduates from the Plans table to the Features table (bidirectional provenance is recorded in each doc's frontmatter).

## Templates

New docs are copied from [`docs/_templates/`](_templates/):

- [`_templates/feature.md`](_templates/feature.md) — an as-built feature doc.
- [`_templates/plan.md`](_templates/plan.md) — a future-work plan.

> **Update this index:** whenever a feature or plan doc is added, removed, or changes status, update the tables above **in the same change**. `@docs reconcile` treats an out-of-sync index as a drift bug.
