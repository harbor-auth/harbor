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
| [`real-token-issuance`](../features/real-token-issuance.md) | §3.3 · §3.4 · §7.3 | `signing-key-rotation` ✅, `token-introspection`, `userinfo-endpoint`, `session-ppid-seam` ✅, `refresh-token-rotation` ✅, `oidf-conformance` |
| [`signing-key-rotation`](../features/signing-key-rotation.md) | §7.3 · §3.5 · §3.3 | (leaf — JWKS `kid` lifecycle) |
| [`grant-id-fk`](../features/grant-id-fk.md) | §3.5 · §10 · §11.3 | `revocation-outbox` ✅ |
| [`revocation-outbox`](../features/revocation-outbox.md) | §3.5 · §10 | `bloom-filter-revocation` ✅ |
| [`bloom-filter-revocation`](../features/bloom-filter-revocation.md) | §3.5 · §7.4 | (leaf — emergency JWT kill) |
| [`webauthn-session-store`](../features/webauthn-session-store.md) | §4.1 · §4.4 · §9 | (leaf — multi-replica ceremony sessions) |
| [`client-grant-persistence`](../features/client-grant-persistence.md) | §3.2 · §10 · §11.3 | `session-ppid-seam` ✅ |
| [`user-enrollment`](../features/user-enrollment.md) | §11.1 · §10 · §4.4 | `session-ppid-seam` ✅, `userinfo-endpoint`, `bff-session-middleware`, `oidf-conformance` |
| [`session-ppid-seam`](../features/session-ppid-seam.md) | §3.2 · §11.2 | `bff-session-middleware`, `refresh-token-rotation` ✅, `oidf-conformance` |
| [`refresh-token-rotation`](../features/refresh-token-rotation.md) | §3.5 · §10 · §11.7 | (leaf — rotating opaque refresh tokens) |

> **Why they're gone from the DAG:** all of Critical Path A ("First Honest
> Token") and Critical Path B ("Safe Revocation") have **fully shipped**, and
> Critical Path C ("Real Login") is one link from complete — only
> `bff-session-middleware` remains to close the `?user_id` impersonation hole.
> The remaining graph is what's left to reach that final security fix and a
> **fully green conformance suite**.

---

## Dependency graph (ASCII) — remaining work

`✅` marks a shipped prerequisite (see the table above). Unmarked boxes are
still to build. Every remaining plan's *unbuilt* prerequisites are now few — the
foundational data/session/identity layers have all landed.

```
┌──────────────────── LAYER 0 — no unbuilt prerequisites ─────────────────────┐
│                                                                             │
│  ┌─────────────────────┐  ┌─────────────────┐  ┌────────────────────────┐  │
│  │ envelope-encryption │  │ token-          │  │  bff-session-          │  │
│  │ -kms  §4.4·§7.3·§10 │  │ introspection   │  │  middleware            │  │
│  │   (in-progress)     │  │ §3.3 (+ ✅rti)  │  │  §9·§11.1·§11.2        │  │
│  └─────────────────────┘  └─────────────────┘  │ (+ ✅enroll+ppid-seam) │  │
│                                                 │  🔴 closes ?user_id    │  │
│  ┌─────────────────────┐  ┌─────────────────┐   └────────────────────────┘  │
│  │  auth-code-         │  │  userinfo-      │                               │
│  │  persistence        │  │  endpoint       │                               │
│  │  §4.1 · §10        │  │ §3.3·§11.4·§3.1 │                               │
│  └──────────┬──────────┘  │ (+ ✅rti+enroll)│                               │
│             │             └─────────────────┘                               │
└─────────────┼───────────────────────────────────────────────────────────────┘
              │
              │  LAYER 1
              ▼
   ┌──────────────────────────────┐
   │       oidf-conformance        │
   │      §1.8 · §11.7 · §3.1     │
   │  (+ ✅rti/enroll/ppid-seam;   │
   │   needs auth-code-persistence)│
   └──────────────────────────────┘
```

> **🔴 `bff-session-middleware` is the single highest-priority item.** It is now
> a buildable root — both its prerequisites (`user-enrollment`,
> `session-ppid-seam`) have shipped — and it closes the `?user_id`
> impersonation hole (§9), the codebase's worst remaining security hole.

---

## Build phases (parallel tracks) — remaining work

The graph above collapses into safe build phases. Within a phase, all items can
land in any order (or simultaneously on separate branches). Shipped
prerequisites (`✅`) are already satisfied.

| Phase | Plans | Gate / unlock |
|---|---|---|
| **0** | `bff-session-middleware` 🔴 · `envelope-encryption-kms` *(in-progress)* · `auth-code-persistence` · `token-introspection` · `userinfo-endpoint` | All roots. `bff-session-middleware` unblocked by ✅ `user-enrollment` + ✅ `session-ppid-seam`; `token-introspection`/`userinfo-endpoint` unblocked by ✅ `real-token-issuance` (+ ✅ `user-enrollment`) |
| **1** | `oidf-conformance` | Needs `auth-code-persistence` (+ ✅ `real-token-issuance` + ✅ `user-enrollment` + ✅ `session-ppid-seam`); suite goes fully green only after all roots land |

---

## Edge list (machine-readable) — remaining work

Each row is `(plan, requires)`. **Type** distinguishes:
- **hard** — the plan literally cannot function without the prerequisite
- **soft** — the plan can be prototyped or partially validated without it, but production deployment requires it (see note in individual plan file)

A `✅` on a prerequisite means it has already shipped (see the *Already shipped*
table) — the edge is satisfied and kept only for traceability.

| Plan | Requires | Type |
|---|---|---|
| `envelope-encryption-kms` | *(none)* | — |
| `auth-code-persistence` | *(none)* | — |
| `token-introspection` | ✅ `real-token-issuance` | hard |
| `userinfo-endpoint` | ✅ `real-token-issuance` · ✅ `user-enrollment` | hard |
| `bff-session-middleware` | ✅ `user-enrollment` · ✅ `session-ppid-seam` | hard |
| `oidf-conformance` | `auth-code-persistence` · ✅ `real-token-issuance` · ✅ `user-enrollment` · ✅ `session-ppid-seam` | hard |

> **Note on `bff-session-middleware` direction:** Architecturally the BFF session
> *provides* the secure `user_id` to the SessionResolver. The seam was
> scaffolded first (against the `?user_id` placeholder) so its `SessionResolver`
> interface could be defined and tested independently; that seam has now shipped
> (`session-ppid-seam` ✅), so BFF replaces the insecure `?user_id` source
> without changing the interface.

---

## The critical paths

Each named path is the longest unbroken chain from a root through to a
significant milestone. **Critical Paths A and B have fully shipped**; Critical
Path C is one link from complete. All three are retained below for the record.

### Critical path A — "First Honest Token" (✅ fully shipped)

The sequence that yields a real, signed, pairwise-subject `id_token` — now
complete end-to-end:

```
✅ real-token-issuance
  └─► ✅ session-ppid-seam
         └─► ✅ refresh-token-rotation
```

Harbor now issues a spec-compliant, per-RP `sub` with rotating opaque refresh
tokens.

### Critical path B — "Safe Revocation" (✅ fully shipped)

The sequence that yields durable, scoped, near-instant revocation — every link,
including both upstream roots, has **landed on `main`**:

```
✅ client-grant-persistence
  └─► ✅ session-ppid-seam
         └─► ✅ grant-id-fk
               └─► ✅ revocation-outbox
                     └─► ✅ bloom-filter-revocation
```

The bloom filter is the emergency kill lever (§3.5).

### Critical path C — "Real Login" (one link remaining — most urgent)

The sequence that replaces the `?user_id` impersonation hack in
`webauthn/handlers.go` — the codebase's single worst security hole today:

```
✅ envelope-encryption-kms   (in-progress — dev-local KMS in use today)
  └─► ✅ user-enrollment
         └─► ✅ session-ppid-seam
               └─► bff-session-middleware   🔴 ONLY UNBUILT LINK
```

Everything up to the seam has shipped (`user-enrollment` runs today against a
dev-local key provider; `envelope-encryption-kms` is an in-progress hardening
that swaps in the real regional KEK). Until `bff-session-middleware` lands, any
HTTP client can forge any user's identity by supplying `?user_id=<arbitrary>`.
**This is the highest-priority remaining chain and it is now a buildable root.**

---

## What to build next

Given what's already shipped, the optimal remaining sequence is:

1. **`bff-session-middleware` 🔴 (do this first):** now a buildable root — both
   prerequisites (✅ `user-enrollment`, ✅ `session-ppid-seam`) have shipped. It
   closes the `?user_id` impersonation hole (§9), the worst remaining security
   gap, and completes Critical Path C ("Real Login").
2. **In parallel (Phase 0 roots):** `token-introspection` and `userinfo-endpoint`
   (both depend only on shipped work) · `auth-code-persistence` (root) ·
   finish `envelope-encryption-kms` *(in-progress — replaces the dev-local key
   provider with the real regional KEK)*.
3. **Finally (Phase 1):** `oidf-conformance` — its only unbuilt prerequisite is
   `auth-code-persistence`; the §1.8 Stage-7 gate goes fully green once all
   roots land.

> **Tip for agents:** Critical Paths A and B are done and C is one link away.
> The single highest-leverage move is **`bff-session-middleware`** — a now-
> unblocked root that closes the `?user_id` hole. After that, the remaining
> backlog is shallow: `token-introspection`, `userinfo-endpoint`, and
> `auth-code-persistence` are all roots, and only `oidf-conformance` waits on
> `auth-code-persistence`.
