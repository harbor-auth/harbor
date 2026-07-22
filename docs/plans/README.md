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
> impersonation hole is closed. What remains is a short backlog of hardening
> roots plus one deferred downstream (`rate-limiting`, gated on
> `token-introspection`).

---

## Wave 2 — active build (launched 2026-07-20)

Three parallel weft jobs launched simultaneously — all independent roots (the
only ordering is the **merge** protocol for `cmd/harbor-hot/main.go`, below):

| Job | Plan | Status | Goal |
|---|---|---|---|
| **W1** | [`auth-code-persistence`](auth-code-persistence.md) | `approved` → building | Redis-backed `AuthCodeStore` (SET NX EX + Lua atomic `Consume`, 2×-TTL consumed marker); delete the SCAFFOLD warning. **Sole owner of `main.go` — merges first.** |
| **W2** | [`token-introspection`](token-introspection.md) | `approved` → building | RFC 7662 `POST /introspect` on `harbor-hot`; Basic-auth clients, JWT verify, **reuse the shipped bloom-filter revocation seam**, cross-client `aud` isolation. Rebases onto post-W1 `main`. |
| **W3** | [`envelope-encryption-kms`](envelope-encryption-kms.md) | `in-progress` → finishing | Finish `kmsKeyProvider` (regional KEK, HSM boundary), crypto-shred tests, frozen vectors. Self-contained in `internal/crypto/`; never touches `main.go`. |

## Wave 3 — deferred

| Job | Plan | Status | Gate |
|---|---|---|---|
| **W0** | [`rate-limiting`](rate-limiting.md) | `draft` (authored this wave) | **Hard-gated on `token-introspection` (W2)** — must protect `/introspect` (which doesn't exist until W2 lands) and shares the hot-path router/middleware surface. Build after W2 is promoted. |

---

## Wave 5 — authored (2026-07-22)

Wave 5 is a batch of **six** privacy / compliance / data-residency hardening
plans, launched in **dependency-ordered gates** rather than all at once: the
**Gate-1 platform guardrails land first** (region-pinning + aggregate-only
metrics), and every later gate inherits those invariants. Two Wave-4 items have
since shipped — `consent-ledger` ✅ (PR #46) and `dynamic-client-registration` ✅
(PR #47) — and `consent-ledger` is a hard prerequisite for the Gate-3/Gate-4
consent-and-relay work below. Each plan's `## Dependency order` blockquote is
canonical; the gate table, graph, and edge list here are derived from them.

| Gate | Plan | Status | Depends on |
|---|---|---|---|
| **1** | [`regional-data-residency-routing`](regional-data-residency-routing.md) | `draft` | *(root — platform guardrail)* |
| **1** | [`observability-metrics`](observability-metrics.md) | `draft` | *(root — platform guardrail)* |
| **2** | [`user-account-recovery`](user-account-recovery.md) | `draft` | Gate 1; ✅ `user-enrollment`, ✅ `webauthn-session-store`, ✅ `envelope-encryption-kms` |
| **3** | [`consent-management-ui`](consent-management-ui.md) | `draft` | Gate 1–2; ✅ `consent-ledger`, `user-audit-trail`, ✅ `bff-session-middleware`; **soft:** `email-relay-service` |
| **3** | [`compliance-export`](compliance-export.md) | `draft` | Gate 1; `user-audit-trail`, ✅ `envelope-encryption-kms` (crypto-shred) |
| **4** | [`email-relay-service`](email-relay-service.md) | `draft` | Gate 1; ✅ `consent-ledger`, ✅ `client-grant-persistence` |

### Wave 5 dependency graph (ASCII)

The two Gate-1 guardrails are independent roots; every later gate inherits the
region-pinning + aggregate-only-metrics invariants (drawn as ordering edges).
`✅` marks a shipped prerequisite; a dotted `soft` edge is feature-detected and
non-blocking.

```
┌──────────────── GATE 1 — platform guardrails (roots, land first) ───────────┐
│                                                                             │
│  ┌─────────────────────────────┐        ┌─────────────────────────────┐    │
│  │ regional-data-residency-    │        │ observability-metrics       │    │
│  │ routing   §5·§4·§11.2       │        │ §6.5·§5·§11.2               │    │
│  └──────────────┬──────────────┘        └──────────────┬──────────────┘    │
│                 │      (region-pin + aggregate-only)    │                   │
└─────────────────┼───────────────────────────────────────┼───────────────────┘
                  ▼                                       ▼
┌──────────────── GATE 2 — user safeguards ───────────────────────────────────┐
│              ┌─────────────────────────────┐                                 │
│              │ user-account-recovery       │  + ✅ user-enrollment,          │
│              │ §11.7·§11.6·§4             │    ✅ webauthn-session-store,    │
│              └──────────────┬──────────────┘    ✅ envelope-encryption-kms   │
└─────────────────────────────┼───────────────────────────────────────────────┘
                              ▼
┌──────────────── GATE 3 — user-facing surfaces ──────────────────────────────┐
│  ┌─────────────────────────────┐   ┌─────────────────────────────┐          │
│  │ consent-management-ui       │   │ compliance-export           │          │
│  │ §2.1·§11.4·§9              │   │ §11.5·§11.6·§11.2           │          │
│  │ + ✅ consent-ledger,        │   │ + user-audit-trail,         │          │
│  │   user-audit-trail,         │   │   ✅ envelope-encryption-kms │          │
│  │   ✅ bff-session-middleware  │   │   (crypto-shred)            │          │
│  └──────────────┬──────────────┘   └─────────────────────────────┘          │
│                 ┊ soft (per-RP relay toggle, feature-detected)              │
└─────────────────┼───────────────────────────────────────────────────────────┘
                  ▼
┌──────────────── GATE 4 — email relay (last) ────────────────────────────────┐
│              ┌─────────────────────────────┐                                 │
│              │ email-relay-service         │  + ✅ consent-ledger,           │
│              │ §7.5·§5·§11.2 (Phase 1+2)  │    ✅ client-grant-persistence   │
│              └─────────────────────────────┘                                 │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Wave 5 edge list (machine-readable)

Each row is `(plan, requires)`. `✅` marks an already-shipped prerequisite;
plain names are Wave-5-internal gate/ordering edges. `soft` edges are
feature-detected and non-blocking.

| Plan | Requires | Type |
|---|---|---|
| `regional-data-residency-routing` | *(none)* | — |
| `observability-metrics` | *(none)* | — |
| `user-account-recovery` | `regional-data-residency-routing`, `observability-metrics` | ordering |
| `user-account-recovery` | ✅ `user-enrollment`, ✅ `webauthn-session-store`, ✅ `envelope-encryption-kms` | hard |
| `compliance-export` | `regional-data-residency-routing`, `observability-metrics` | ordering |
| `compliance-export` | `user-audit-trail`, ✅ `envelope-encryption-kms` | hard |
| `consent-management-ui` | `regional-data-residency-routing`, `observability-metrics` | ordering |
| `consent-management-ui` | ✅ `consent-ledger`, `user-audit-trail`, ✅ `bff-session-middleware` | hard |
| `consent-management-ui` | `email-relay-service` | soft |
| `email-relay-service` | `regional-data-residency-routing`, `observability-metrics` | ordering |
| `email-relay-service` | ✅ `consent-ledger`, ✅ `client-grant-persistence` | hard |

---

## Dependency graph (ASCII) — remaining work

The three Wave-2 roots are independent. `rate-limiting` is the one downstream
node — a **hard** edge on `token-introspection`. `✅` marks a shipped
prerequisite (see the table above).

```
┌──────────────────── LAYER 0 — no unbuilt prerequisites (Wave 2) ────────────┐
│                                                                             │
│  ┌─────────────────────┐  ┌─────────────────┐  ┌─────────────────────────┐ │
│  │ envelope-encryption │  │ token-          │  │  auth-code-             │ │
│  │ -kms  §4.4·§7.3·§10 │  │ introspection   │  │  persistence            │ │
│  │   (in-progress·W3)  │  │ §3.3 (+ ✅rti)·W2│  │  §4.1 · §10 · W1        │ │
│  └─────────────────────┘  └────────┬────────┘  └─────────────────────────┘ │
│                                    │ hard                                   │
└────────────────────────────────────┼────────────────────────────────────────┘
                                     ▼
┌──────────────────── LAYER 1 — gated (Wave 3) ──────────────────────────────┐
│                          ┌─────────────────────────┐                        │
│                          │  rate-limiting          │                        │
│                          │  §4.1 · §6.1 · §11.7 · W0│                        │
│                          └─────────────────────────┘                        │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Build phases (parallel tracks) — remaining work

| Phase | Plans | Gate / unlock |
|---|---|---|
| **0** *(Wave 2, active)* | `envelope-encryption-kms` *(in-progress)* · `token-introspection` · `auth-code-persistence` | All roots — nothing blocked. `token-introspection` unblocked by ✅ `real-token-issuance`; the other two have no prerequisites. |
| **1** *(Wave 3, deferred)* | `rate-limiting` | Gated on `token-introspection` (W2) — needs `/introspect` to exist and the hot-path middleware surface settled. |

---

## Edge list (machine-readable) — remaining work

Each row is `(plan, requires)`. A `✅` on a prerequisite means it has already
shipped (see the *Already shipped* table) — the edge is satisfied.

| Plan | Requires | Type |
|---|---|---|
| `envelope-encryption-kms` | *(none)* | — |
| `auth-code-persistence` | *(none)* | — |
| `token-introspection` | ✅ `real-token-issuance` | hard |
| `rate-limiting` | `token-introspection` | hard |

---

## `cmd/harbor-hot/main.go` merge protocol (Wave 2)

The three Wave-2 jobs are launched in parallel, but `cmd/harbor-hot/main.go` is
the one genuine textual hotspot. To avoid clobbering it, ownership — not
serialization — is enforced:

| Rule | Detail |
|---|---|
| **Sole owner** | **W1 (`auth-code-persistence`)** owns all substantive `main.go` edits this wave: swap `NewInMemoryAuthCodeStore()` → `RedisAuthCodeStore` when `REDIS_URL` is set, delete the SCAFFOLD warning, keep the in-memory dev fallback. |
| **Merge order** | **W1 merges first.** W2 then **rebases onto post-W1 `main`** before opening/updating its PR. |
| **W2 confinement** | **W2 (`token-introspection`)** makes **zero structural edits** to `main.go`. Route/handler registration goes in `internal/oidcapi/server.go` (where the generated router binds handlers). W2 may add **at most one constructor argument** to `oidcapi.NewServer` — a single-line `main.go` call-site change that rebases trivially. Anything larger means W2 violated confinement — fix W2, don't hand-merge. |
| **W3** | **W3 (`envelope-encryption-kms`)** never touches `main.go` (crypto consumers are enrollment/mgmt-side, already wired). Merges any time. |
| **W2 revocation guardrail** | W2 MUST **consume the already-shipped bloom-filter revocation seam** (the `internal/oidc` revocation filter from `bloom-filter-revocation`) rather than invent a new Redis-adjacent revocation path. Two independent revocation seams would be a semantic conflict CI can't catch. |

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

**Wave 2 is active** — three parallel jobs are building now (see *Wave 2 —
active build* above):

1. **W1 · `auth-code-persistence`** — Redis-backed multi-replica-safe
   authorization codes; sole owner of `main.go`, **merges first**.
2. **W2 · `token-introspection`** — RFC 7662 `POST /introspect`; reuses the
   shipped bloom-filter revocation seam; rebases onto post-W1 `main`.
3. **W3 · `envelope-encryption-kms`** *(in-progress)* — finish the real regional
   KEK provider; self-contained in `internal/crypto/`.

**Wave 3 (deferred):**

4. **W0 · `rate-limiting`** — per-client hot-path rate limiting. **Do not build
   until `token-introspection` (W2) is promoted** — it must protect
   `/introspect` and shares the hot-path middleware surface.

> **Tip for agents:** the only ordering that exists in Wave 2 is the `main.go`
> **merge** protocol (W1 before W2 — see above), not a launch order. All three
> Wave-2 jobs launch simultaneously. `rate-limiting` is the sole gated
> downstream and waits for Wave 3.
