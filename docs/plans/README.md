# Harbor Plans — Dependency Graph & Build Order

This file is the **navigation layer** for `docs/plans/`. It answers one
question: **in what order do we build things, and what can we build in
parallel?** Read the individual `*.md` files for the full rationale, schema
snippets, and implementation checklists.

> **Source-of-truth rule:** Each plan's `## Dependency order` blockquote is
> canonical. The graph below is derived from those notes. On any discrepancy,
> the individual plan file wins.

> **Scope of this file:** the graph below tracks the **unbuilt** backlog. Once a
> plan ships it is **promoted** (its row moves from the Plans table to the
> Features table in [`../README.md`](../README.md)) and it **drops out of this
> graph** — it survives here only as a ✅ *shipped prerequisite* annotation on
> the plans that still depend on it. See [`../../.agents/plan.md`](../../.agents/plan.md)
> for the `draft → approved → in-progress → merged → promoted` lifecycle.

## ✅ Already shipped (promoted to Features)

These plans have landed on `main` and graduated into feature docs — they are **no
longer buildable work**. They appear below only as `✅` prerequisites of the
plans that still depend on them.

| Shipped feature | DESIGN § | Unblocked |
|---|---|---|
| [`real-token-issuance`](../features/real-token-issuance.md) | §3.3 · §3.4 · §7.3 | `signing-key-rotation` ✅, `token-introspection`, `userinfo-endpoint`, `session-ppid-seam`, `refresh-token-rotation`, `oidf-conformance` |
| [`signing-key-rotation`](../features/signing-key-rotation.md) | §7.3 · §3.5 · §3.3 | (leaf — JWKS `kid` lifecycle) |
| [`grant-id-fk`](../features/grant-id-fk.md) | §3.5 · §10 · §11.3 | `revocation-outbox` ✅ |
| [`revocation-outbox`](../features/revocation-outbox.md) | §3.5 · §10 | `bloom-filter-revocation` ✅ |
| [`bloom-filter-revocation`](../features/bloom-filter-revocation.md) | §3.5 · §7.4 | (leaf — emergency JWT kill) |

> **Why they're gone from the DAG:** all of Critical Path B ("Safe Revocation")
> and the token-signing root have shipped. The remaining graph is what's left to
> reach **Real Login** (Critical Path C) and a **fully green conformance suite**.

---

## Dependency graph (ASCII) — remaining work

`✅` marks a shipped prerequisite (see the table above). Unmarked boxes are
still to build.

```
┌──────────────────────────── LAYER 0 — no prerequisites ─────────────────────────────┐
│                                                                                      │
│  ┌─────────────────────┐  ┌─────────────────┐  ┌─────────────────┐  ┌────────────┐  │
│  │ envelope-encryption │  │  auth-code-     │  │ client-grant-   │  │ webauthn-  │  │
│  │ -kms  §4.4·§7.3·§10 │  │  persistence    │  │ persistence     │  │ session-   │  │
│  │   (in-progress)     │  │  §4.1 · §10    │  │  §3.2 · §10    │  │ store §4.4 │  │
│  └──────────┬──────────┘  └───────┬─────────┘  └───────┬─────────┘  └────────────┘  │
└─────────────┼─────────────────────┼───────────────────┼──────────────────────────────┘
              │                      │                   │
              │  LAYER 1             │                   │
              ▼                      │                   │
  ┌───────────────────┐  ┌───────────────────────┐      │
  │  user-enrollment  │  │  token-introspection  │      │
  │  §11.1 · §10·§4.4 │  │  §3.3  (+ ✅rti)      │      │
  └────────┬──────────┘  └───────────────────────┘      │
           │                                             │
           │  LAYER 2   (+ ✅ real-token-issuance)       │
           ▼                                             ▼
┌─────────────────────────┐              ┌────────────────────────────┐
│    session-ppid-seam    │              │    userinfo-endpoint       │
│     §3.2 · §11.2        │              │    §3.3 · §11.4 · §3.1     │
│      (approved)         │              │   (+ ✅rti + user-enroll)  │
└───────────┬─────────────┘              └────────────────────────────┘
            │
            │  LAYER 3   (all unblocked once session-ppid-seam lands)
┌───────────┼──────────────────────────────┐
▼           ▼                              ▼
┌─────────────────┐              ┌──────────────────────┐
│  bff-session-   │              │  refresh-token-      │
│  middleware     │              │  rotation §3.5·§10   │
│  §9·§11.1·§11.2 │              │   (+ ✅rti)          │
└─────────────────┘              └──────────────────────┘
  (end-to-end login —
   most urgent security fix)


──────────────────────── LAYER 4 — final integration gate ───────────────────
  (requires: ✅ real-token-issuance + auth-code-persistence + user-enrollment +
   session-ppid-seam; suite goes fully green only after all remaining layers land)

                           ┌──────────────────────────────┐
                           │       oidf-conformance        │
                           │      §1.8 · §11.7 · §3.1     │
                           └──────────────────────────────┘
```

---

## Build phases (parallel tracks) — remaining work

The graph above collapses into safe build phases. Within a phase, all items can
land in any order (or simultaneously on separate branches). Shipped
prerequisites (`✅`) are already satisfied.

| Phase | Plans | Gate / unlock |
|---|---|---|
| **0** | `envelope-encryption-kms` *(in-progress)* · `auth-code-persistence` · `client-grant-persistence` · `webauthn-session-store` *(approved)* | Nothing blocked — all roots |
| **1** | `user-enrollment` · `token-introspection` | `user-enrollment` unblocked by `kms`; `token-introspection` unblocked by ✅ `real-token-issuance` |
| **2** | `session-ppid-seam` *(approved)* · `userinfo-endpoint` | `session-ppid-seam` needs `user-enrollment` + `client-grant-persistence` + ✅ `real-token-issuance`; `userinfo-endpoint` needs ✅ `real-token-issuance` + `user-enrollment` |
| **3** | `bff-session-middleware` · `refresh-token-rotation` | Both unblocked once `session-ppid-seam` lands |
| **4** | `oidf-conformance` | Unblocked once ✅ `real-token-issuance` + `auth-code-persistence` + `user-enrollment` + `session-ppid-seam` land; suite goes fully green only after all phases |

---

## Edge list (machine-readable) — remaining work

Each row is `(plan, requires)`. **Type** distinguishes:
- **hard** — the plan literally cannot function without the prerequisite
- **soft** — the plan can be prototyped or partially validated without it, but production deployment requires it (see note in individual plan file)

A `✅` on a prerequisite means it has already shipped (see the *Already shipped*
table) — the edge is satisfied and kept only for traceability.

> **Note on `bff-session-middleware` direction:** Architecturally the BFF session
> *provides* the secure `user_id` to the SessionResolver, which might suggest
> `session-ppid-seam` should depend on BFF instead. The current edge is
> intentional: the seam is scaffolded first against the `?user_id` placeholder
> so its `SessionResolver` interface can be defined and tested independently;
> BFF then replaces that insecure source without changing the interface. The
> BFF plan requires the seam's interface to exist before it can be wired in.

| Plan | Requires | Type |
|---|---|---|
| `envelope-encryption-kms` | *(none)* | — |
| `auth-code-persistence` | *(none)* | — |
| `client-grant-persistence` | *(none)* | — |
| `webauthn-session-store` | *(none)* | — |
| `user-enrollment` | `envelope-encryption-kms` | hard |
| `token-introspection` | ✅ `real-token-issuance` | hard |
| `userinfo-endpoint` | ✅ `real-token-issuance` · `user-enrollment` | hard |
| `session-ppid-seam` | `user-enrollment` · `client-grant-persistence` · ✅ `real-token-issuance` | hard |
| `bff-session-middleware` | `user-enrollment` · `session-ppid-seam` | hard (see direction note above) |
| `refresh-token-rotation` | ✅ `real-token-issuance` · `session-ppid-seam` | hard |
| `oidf-conformance` | ✅ `real-token-issuance` · `auth-code-persistence` · `user-enrollment` · `session-ppid-seam` | hard |

---

## The critical paths

Each named path is the longest unbroken chain from a root (Layer 0) through to a
significant milestone. Plans on these paths cannot slip without delaying
everything downstream. **Critical Path B ("Safe Revocation") has fully shipped**
and is retained below for the record.

### Critical path A — "First Honest Token"

The sequence that yields a real, signed, pairwise-subject `id_token`:

```
✅ real-token-issuance
  └─► session-ppid-seam        (approved — next convergence point)
         └─► refresh-token-rotation
```

The token root has shipped; nothing produces a spec-compliant, per-RP `sub`
until `session-ppid-seam` and `refresh-token-rotation` also land.

### Critical path B — "Safe Revocation" (revocation core ✅ shipped)

The sequence that yields durable, scoped, near-instant revocation. The three
revocation links have **landed on `main`**; the two upstream roots remain on the
backlog (they were prototyped against, not yet fully wired):

```
client-grant-persistence*   └─► session-ppid-seam*
         └─► ✅ grant-id-fk
               └─► ✅ revocation-outbox
                     └─► ✅ bloom-filter-revocation
```

The bloom filter is the emergency kill lever (§3.5). *(`grant-id-fk`,
`revocation-outbox`, and `bloom-filter-revocation` shipped ahead of the full
`client-grant-persistence` / `session-ppid-seam` build-out; those two roots
(unmarked above) remain on the backlog to complete the production wiring they
prototyped against.)*

### Critical path C — "Real Login" (most urgent security fix)

The sequence that replaces the `?user_id` impersonation hack in
`webauthn/handlers.go` — the codebase's single worst security hole today:

```
envelope-encryption-kms       (in-progress)
  └─► user-enrollment
         └─► session-ppid-seam (approved)
               └─► bff-session-middleware
```

Until `bff-session-middleware` lands, any HTTP client can forge any user's
identity by supplying `?user_id=<arbitrary>`. This path has no dependency on the
(already-shipped) token-signing track — it can be driven independently. **This is
now the highest-priority remaining chain.**

---

## What to build next

Given what's already shipped, the optimal remaining sequence is:

1. **Finish Phase 0 (in flight + roots):** complete `envelope-encryption-kms`
   *(already in-progress — the root of Critical Path C)*, and in parallel
   `auth-code-persistence`, `client-grant-persistence`, and
   `webauthn-session-store` *(approved, no prerequisites)*.
2. **Then in parallel (Phase 1):** `user-enrollment` (unblocked by `kms`) ·
   `token-introspection` (unblocked by ✅ `real-token-issuance`).
3. **Then (Phase 2):** `session-ppid-seam` *(already approved — the convergence
   point of Critical Paths A and C)* · `userinfo-endpoint`.
4. **Then in parallel (Phase 3):** `bff-session-middleware` *(closes the
   `?user_id` hole)* + `refresh-token-rotation`.
5. **Finally (Phase 4):** `oidf-conformance` (the §1.8 Stage-7 gate — green CI
   confirms everything composes).

> **Tip for agents:** The token-signing root and all of Critical Path B have
> shipped. The highest-leverage remaining move is **`session-ppid-seam`**
> (already `approved`): it's the convergence point of Critical Path A ("First
> Honest Token") *and* Critical Path C ("Real Login"), and it unblocks
> `bff-session-middleware` and `refresh-token-rotation` simultaneously. Its only
> unbuilt prerequisites are `user-enrollment` and `client-grant-persistence` —
> land those first. Meanwhile `webauthn-session-store` (approved, no prereqs)
> and `envelope-encryption-kms` (in-progress) can proceed independently.
