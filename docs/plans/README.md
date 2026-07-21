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
| [`real-token-issuance`](../features/real-token-issuance.md) | §3.3 · §3.4 · §7.3 | `signing-key-rotation` ✅, `token-introspection`, `userinfo-endpoint` ✅, `session-ppid-seam` ✅, `refresh-token-rotation` ✅, `oidf-conformance` ✅ |
| [`signing-key-rotation`](../features/signing-key-rotation.md) | §7.3 · §3.5 · §3.3 | (leaf — JWKS `kid` lifecycle) |
| [`grant-id-fk`](../features/grant-id-fk.md) | §3.5 · §10 · §11.3 | `revocation-outbox` ✅ |
| [`revocation-outbox`](../features/revocation-outbox.md) | §3.5 · §10 | `bloom-filter-revocation` ✅ |
| [`bloom-filter-revocation`](../features/bloom-filter-revocation.md) | §3.5 · §7.4 | (leaf — emergency JWT kill) |
| [`webauthn-session-store`](../features/webauthn-session-store.md) | §4.1 · §4.4 · §9 | (leaf — multi-replica ceremony sessions) |
| [`client-grant-persistence`](../features/client-grant-persistence.md) | §3.2 · §10 · §11.3 | `session-ppid-seam` ✅ |
| [`user-enrollment`](../features/user-enrollment.md) | §11.1 · §10 · §4.4 | `session-ppid-seam` ✅, `userinfo-endpoint` ✅, `bff-session-middleware` ✅, `oidf-conformance` ✅ |
| [`session-ppid-seam`](../features/session-ppid-seam.md) | §3.2 · §11.2 | `bff-session-middleware` ✅, `refresh-token-rotation` ✅, `oidf-conformance` ✅ |
| [`refresh-token-rotation`](../features/refresh-token-rotation.md) | §3.5 · §10 · §11.7 | (leaf — rotating opaque refresh tokens) |
| [`bff-session-middleware`](../features/bff-session-middleware.md) | §9 · §11.1 · §11.2 | (leaf — real login identity; closes `?user_id`) |
| [`userinfo-endpoint`](../features/userinfo-endpoint.md) | §3.3 · §11.4 · §3.1 | `oidf-conformance` ✅ |
| [`oidf-conformance`](../features/oidf-conformance.md) | §1.8 · §11.7 · §3.1 | (leaf — the green-suite integration gate) |

> **Why they're gone from the DAG:** all three named critical paths — A ("First
> Honest Token"), B ("Safe Revocation"), and C ("Real Login") — have **fully
> shipped**, and the OIDF conformance suite is green. The `?user_id`
> impersonation hole is closed. What remains is a short, **unordered** backlog of
> independent roots: durable persistence hardening and token introspection.

---

## Dependency graph (ASCII) — remaining work

Every remaining plan is an **independent root** — nothing in the backlog blocks
anything else. `✅` marks a shipped prerequisite (see the table above).

```
┌──────────────────── LAYER 0 — no unbuilt prerequisites ─────────────────────┐
│                                                                             │
│  ┌─────────────────────┐  ┌─────────────────┐  ┌─────────────────────────┐ │
│  │ envelope-encryption │  │ token-          │  │  auth-code-             │ │
│  │ -kms  §4.4·§7.3·§10 │  │ introspection   │  │  persistence            │ │
│  │   (in-progress)     │  │ §3.3 (+ ✅rti)  │  │  §4.1 · §10            │ │
│  └─────────────────────┘  └─────────────────┘  └─────────────────────────┘ │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

> **No LAYER 1 remains.** Every backlog item is a root; there are no unbuilt
> downstream dependencies left. `oidf-conformance` — formerly the sole LAYER 1
> node — has shipped.

---

## Build phases (parallel tracks) — remaining work

| Phase | Plans | Gate / unlock |
|---|---|---|
| **0** | `envelope-encryption-kms` *(in-progress)* · `token-introspection` · `auth-code-persistence` | All roots — nothing blocked. `token-introspection` unblocked by ✅ `real-token-issuance`; the other two have no prerequisites. |

---

## Edge list (machine-readable) — remaining work

Each row is `(plan, requires)`. A `✅` on a prerequisite means it has already
shipped (see the *Already shipped* table) — the edge is satisfied.

| Plan | Requires | Type |
|---|---|---|
| `envelope-encryption-kms` | *(none)* | — |
| `auth-code-persistence` | *(none)* | — |
| `token-introspection` | ✅ `real-token-issuance` | hard |

---

## The critical paths — all shipped ✅

All three named critical paths (and the OIDF integration gate) have fully landed
on `main`. They are retained here for the record.

### Critical path A — "First Honest Token" (✅ fully shipped)

```
✅ real-token-issuance
  └─► ✅ session-ppid-seam
         └─► ✅ refresh-token-rotation
```

### Critical path B — "Safe Revocation" (✅ fully shipped)

```
✅ client-grant-persistence
  └─► ✅ session-ppid-seam
         └─► ✅ grant-id-fk
               └─► ✅ revocation-outbox
                     └─► ✅ bloom-filter-revocation
```

### Critical path C — "Real Login" (✅ fully shipped)

The sequence that replaced the `?user_id` impersonation hack in
`webauthn/handlers.go` — now complete end-to-end:

```
✅ envelope-encryption-kms   (in-progress hardening — dev-local KMS in use today)
  └─► ✅ user-enrollment
         └─► ✅ session-ppid-seam
               └─► ✅ bff-session-middleware
```

A real passkey ceremony now drives the authenticated `user_id` into the BFF
session; `harbor-hot` reads it from the server-side session, not a client param.

### Integration gate — OIDF conformance (✅ shipped)

```
✅ real-token-issuance · ✅ user-enrollment · ✅ session-ppid-seam · ✅ userinfo-endpoint
  └─► ✅ oidf-conformance   (green OIDC Basic OP certification suite)
```

---

## What to build next

The security-critical spine is complete. The remaining backlog is a short set of
independent hardening roots — build in any order:

1. **`token-introspection`** — RFC 7662 `POST /introspect` (depends only on ✅
   `real-token-issuance`). Adds the opaque-token confirmation path.
2. **`auth-code-persistence`** — move single-use authorization codes from the
   in-memory store to a durable, multi-replica-safe backend (root).
3. **Finish `envelope-encryption-kms`** *(in-progress)* — replace the dev-local
   key provider with the real regional KEK.

> **Tip for agents:** there are no ordering constraints left — every remaining
> plan is a root. `token-introspection` and `auth-code-persistence` are both
> greenfield roots, and `envelope-encryption-kms` is an in-progress hardening to
> finish.
