# Harbor Plans — Dependency Graph & Build Order

This file is the **navigation layer** for `docs/plans/`. It answers one
question: **in what order do we build things, and what can we build in
parallel?** Read the individual `*.md` files for the full rationale, schema
snippets, and implementation checklists.

> **Source-of-truth rule:** Each plan's `## Dependency order` blockquote is
> canonical. The graph below is derived from those notes. On any discrepancy,
> the individual plan file wins.

---

## Dependency graph (ASCII)

```
┌──────────────────────────────── LAYER 0 — no prerequisites ─────────────────────────────────────┐
│                                                                                                  │
│  ┌─────────────────────┐  ┌──────────────────────┐  ┌─────────────────┐  ┌─────────────────┐   │
│  │ envelope-encryption │  │  real-token-issuance  │  │  auth-code-     │  │ client-grant-   │   │
│  │ -kms §4.4·§7.3·§10  │  │  §3.3 · §3.4 · §7.3   │  │  persistence    │  │ persistence     │   │
│  └──────────┬──────────┘  └──┬──────────────┬─────┘  │  §4.1 · §10    │  │  §3.2 · §10    │   │
└─────────────┼────────────────┼──────────────┼─────────┴─────────────────┴──┴─────────────────┴──┘
              │                │              │                                              │
              │         LAYER 1│              │                                              │
              ▼                ▼              ▼                                              │
  ┌───────────────────┐  ┌─────────────────┐  ┌────────────────────┐                       │
  │  user-enrollment  │  │ signing-key-    │  │ token-             │                       │
  │  §11.1 · §10·§4.4 │  │ rotation §7.3   │  │ introspection §3.3 │                       │
  └────────┬──────────┘  └─────────────────┘  └────────────────────┘                       │
           │                                                                                │
           └──────────────────── + real-token-issuance + ────────────────────────────────┘
                                              │
                             LAYER 2          │
          ┌──────────────────────────────────┐│
          ▼                                  ▼▼
┌─────────────────────────┐     ┌────────────────────────────┐
│    session-ppid-seam    │     │    userinfo-endpoint       │
│     §3.2 · §11.2        │     │    §3.3 · §11.4 · §3.1     │
└───────────┬─────────────┘     └────────────────────────────┘
            │
            │             LAYER 3
┌───────────┼──────────────────────────────┐
▼           ▼                              ▼
┌─────────────────┐  ┌──────────────┐  ┌──────────────────────┐
│  bff-session-   │  │  grant-id-fk │  │  refresh-token-      │
│  middleware     │  │ §3.5·§10·11.3│  │  rotation §3.5·§10   │
│  §9·§11.1·§11.2 │  └──────┬───────┘  └──────────┬───────────┘
└─────────────────┘         │                      │
  (end-to-end login)        └──────────┬───────────┘
                                       │
                            LAYER 4    ▼
                           ┌─────────────────────────┐
                           │    revocation-outbox    │
                           │    §3.5 · §3.5.2 · §10  │
                           └────────────┬────────────┘
                                        │  (+ real-token-issuance)
                            LAYER 5     ▼
                           ┌──────────────────────────────┐
                           │  bloom-filter-revocation     │
                           │ §3.5 · §3.5.2 · §3.5.4 · §7.4│
                           └──────────────────────────────┘


──────────────────────── LAYER 6 — final integration gate ───────────────────
  (requires: real-token-issuance + auth-code-persistence + user-enrollment +
   session-ppid-seam; fully green conformance suite only after all layers land)

                           ┌──────────────────────────────┐
                           │       oidf-conformance        │
                           │      §1.8 · §11.7 · §3.1     │
                           └──────────────────────────────┘
```

---

## Build phases (parallel tracks)

The graph above collapses into six safe build phases. Within a phase, all items
can land in any order (or simultaneously on separate branches).

| Phase | Plans | Gate / unlock |
|---|---|---|
| **0** | `envelope-encryption-kms` · `real-token-issuance` · `auth-code-persistence` · `client-grant-persistence` | Nothing blocked |
| **1** | `user-enrollment` · `signing-key-rotation` · `token-introspection` | `user-enrollment` unblocked by `kms`; `signing-key-rotation` + `token-introspection` unblocked by `real-token-issuance` |
| **2** | `session-ppid-seam` · `userinfo-endpoint` | `session-ppid-seam` needs `user-enrollment` + `client-grant-persistence` + `real-token-issuance`; `userinfo-endpoint` needs `real-token-issuance` + `user-enrollment` |
| **3** | `bff-session-middleware` · `grant-id-fk` · `refresh-token-rotation` | All three unblocked once `session-ppid-seam` lands |
| **4** | `revocation-outbox` | Unblocked once `refresh-token-rotation` + `grant-id-fk` land |
| **5** | `bloom-filter-revocation` | Unblocked once `revocation-outbox` + `real-token-issuance` land |
| **6** | `oidf-conformance` | Unblocked once `real-token-issuance` + `auth-code-persistence` + `user-enrollment` + `session-ppid-seam` land; suite goes fully green only after all phases |

---

## Edge list (machine-readable)

Each row is `(plan, requires)`. **Type** distinguishes:
- **hard** — the plan literally cannot function without the prerequisite
- **soft** — the plan can be prototyped or partially validated without it, but production deployment requires it (see note in individual plan file)

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
| `real-token-issuance` | *(none)* | — |
| `auth-code-persistence` | *(none)* | — |
| `client-grant-persistence` | *(none)* | — |
| `user-enrollment` | `envelope-encryption-kms` | hard |
| `signing-key-rotation` | `real-token-issuance` | hard |
| `token-introspection` | `real-token-issuance` | hard |
| `userinfo-endpoint` | `real-token-issuance` · `user-enrollment` | hard |
| `session-ppid-seam` | `user-enrollment` · `client-grant-persistence` · `real-token-issuance` | hard |
| `bff-session-middleware` | `user-enrollment` · `session-ppid-seam` | hard (see direction note above) |
| `grant-id-fk` | `client-grant-persistence` · `session-ppid-seam` | hard |
| `refresh-token-rotation` | `real-token-issuance` · `session-ppid-seam` | hard |
| `revocation-outbox` | `refresh-token-rotation` · `grant-id-fk` | soft — can prototype against `RevokeSessionsByUserClient` without `grant-id-fk` |
| `bloom-filter-revocation` | `real-token-issuance` · `revocation-outbox` | soft — can prototype with stub JTIs; `revocation-outbox` is the production-grade persistent kill path |
| `oidf-conformance` | `real-token-issuance` · `auth-code-persistence` · `user-enrollment` · `session-ppid-seam` | hard |

---

## The three critical paths

Each named path is the longest unbroken chain from a root (Layer 0) through
to a significant milestone. Plans on these paths cannot slip without delaying
everything downstream.

### Critical path A — "First Honest Token"

The sequence that yields a real, signed, pairwise-subject `id_token`:

```
real-token-issuance
  └─► session-ppid-seam
         └─► refresh-token-rotation
```

Nothing produces a spec-compliant `id_token` until all three land.

### Critical path B — "Safe Revocation"

The sequence that yields durable, scoped, near-instant revocation:

```
client-grant-persistence
  └─► session-ppid-seam
         └─► grant-id-fk
               └─► revocation-outbox
                     └─► bloom-filter-revocation
```

The bloom filter is the emergency kill lever (§3.5); every link in this chain
must be solid before it can be trusted.

### Critical path C — "Real Login" (most urgent security fix)

The sequence that replaces the `?user_id` impersonation hack in
`webauthn/handlers.go` — the codebase's single worst security hole today:

```
envelope-encryption-kms
  └─► user-enrollment
         └─► session-ppid-seam
               └─► bff-session-middleware
```

Until `bff-session-middleware` lands, any HTTP client can forge any user's
identity by supplying `?user_id=<arbitrary>`. This path has no blocked
dependency on `real-token-issuance` — it can be driven independently of the
token-signing track.

---

## What to build next

If starting from scratch today, the optimal sequence is:

1. **In parallel (Phase 0):** `envelope-encryption-kms` + `real-token-issuance` + `auth-code-persistence` + `client-grant-persistence`
2. **Then in parallel (Phase 1):** `user-enrollment` (unblocked by kms) · `signing-key-rotation` · `token-introspection` (both unblocked by real-token-issuance)
3. **Then in parallel (Phase 2):** `session-ppid-seam` (the convergence point) · `userinfo-endpoint` (needs real-token + user-enrollment)
4. **Then in parallel (Phase 3):** `bff-session-middleware` + `grant-id-fk` + `refresh-token-rotation`
5. **Then (Phase 4):** `revocation-outbox`
6. **Then (Phase 5):** `bloom-filter-revocation`
7. **Finally (Phase 6):** `oidf-conformance` (the §1.8 Stage-7 gate — green CI confirms everything composes)

> **Tip for agents:** Start with `real-token-issuance` if you can only do one
> plan — it unblocks `session-ppid-seam` (Phase 2), `signing-key-rotation`, and
> `token-introspection` (both Phase 1) simultaneously. It's the highest-leverage
> first move.
