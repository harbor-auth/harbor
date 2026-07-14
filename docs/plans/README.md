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
┌──────────────────────────────────────── LAYER 0 ────────────────────────────────────────────────┐
│  No prerequisites — build any or all in parallel                                                │
│                                                                                                  │
│  ┌──────────────────────────┐  ┌──────────────────────┐  ┌─────────────────────┐  ┌──────────────────────────┐
│  │ envelope-encryption-kms  │  │  real-token-issuance  │  │ auth-code-          │  │ client-grant-            │
│  │         [kms]            │  │       [token]         │  │ persistence         │  │ persistence              │
│  │  §4.4 · §7.3 · §10      │  │  §3.3 · §3.4 · §7.3  │  │  §4.1 · §10        │  │  §3.2 · §10             │
│  └──────────┬───────────────┘  └──────────┬───────────┘  └─────────┬───────────┘  └──────────┬─────────────┘
└─────────────┼──────────────────────────────┼───────────────────────┼───────────────────────────┼─────────────┘
              │                              │                        │                           │
              │                              │                        │                           │
              ▼                              │                        │                           │
  ┌───────────────────────┐                 │                        │                           │
  │    user-enrollment    │                 │                        │                           │
  │   §11.1 · §10 · §4.4  │                 │                        │                           │
  └───────────┬───────────┘                 │                        │                           │
              │                             │                        │                           │
              │            ┌────────────────┘                        │                           │
              │            │                                         │                           │
              └────────────┼─────────────────────────────────────────┼───────────────────────────┘
                           │         (needs: user-enrollment +        │
                           │          real-token-issuance +           │
                           │          client-grant-persistence)       │
                           ▼                                         │
              ┌─────────────────────────┐                            │
              │    session-ppid-seam    │                            │
              │     §3.2 · §11.2       │                            │
              └───────────┬─────────────┘                            │
                          │                                          │
          ┌───────────────┼────────────────────┐                    │
          │               │                    │                    │
          ▼               ▼                    ▼                    │
  ┌───────────────┐  ┌──────────────┐  ┌──────────────────────┐    │
  │ bff-session-  │  │  grant-id-   │  │  refresh-token-      │    │
  │ middleware    │  │  fk          │  │  rotation            │    │
  │ §9·§11.1·11.2 │  │ §3.5·§10·11.3│  │  §3.5 · §10         │    │
  └───────────────┘  └──────┬───────┘  └──────────┬───────────┘    │
   (end-to-end login)        │                     │                │
                             └──────────┬──────────┘                │
                                        │                           │
                                        ▼                           │
                           ┌─────────────────────────┐             │
                           │    revocation-outbox     │             │
                           │     §3.5 · §3.5.2 · §10  │             │
                           └────────────┬────────────┘             │
                                        │                           │
                                        │   ┌───────────────────────┘
                                        │   │  (also needs real-token-issuance)
                                        ▼   ▼
                           ┌──────────────────────────────┐
                           │  bloom-filter-revocation     │
                           │  §3.5 · §3.5.2 · §3.5.4·§7.4│
                           └──────────────────────────────┘


──────────────────────── FINAL INTEGRATION GATE ─────────────────────────────
  (requires real-token-issuance + auth-code-persistence + user-enrollment
   and — to have a fully green suite — effectively everything above)

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

Each row is `(plan, requires)` — `requires` must be in a merged state before
`plan` starts implementation.

| Plan | Requires |
|---|---|
| `envelope-encryption-kms` | *(none)* |
| `real-token-issuance` | *(none)* |
| `auth-code-persistence` | *(none)* |
| `client-grant-persistence` | *(none)* |
| `user-enrollment` | `envelope-encryption-kms` |
| `signing-key-rotation` | `real-token-issuance` |
| `token-introspection` | `real-token-issuance` |
| `userinfo-endpoint` | `real-token-issuance` · `user-enrollment` |
| `session-ppid-seam` | `user-enrollment` · `client-grant-persistence` · `real-token-issuance` |
| `bff-session-middleware` | `user-enrollment` · `session-ppid-seam` |
| `grant-id-fk` | `client-grant-persistence` · `session-ppid-seam` |
| `refresh-token-rotation` | `real-token-issuance` · `session-ppid-seam` |
| `revocation-outbox` | `refresh-token-rotation` · `grant-id-fk` |
| `bloom-filter-revocation` | `real-token-issuance` · `revocation-outbox` |
| `oidf-conformance` | `real-token-issuance` · `auth-code-persistence` · `user-enrollment` · `session-ppid-seam` |

---

## The three critical paths

There are two long chains from roots to the final gate — knowing them tells you
which plans are on the critical path and can't slip.

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

1. **In parallel:** `envelope-encryption-kms` + `real-token-issuance` + `auth-code-persistence` + `client-grant-persistence`
2. **Then:** `user-enrollment`
3. **Then:** `session-ppid-seam` (the convergence point for three Phase-0 plans)
4. **Then in parallel:** `bff-session-middleware` + `grant-id-fk` + `refresh-token-rotation`
5. **Then:** `revocation-outbox`
6. **Then:** `bloom-filter-revocation`
7. **Finally:** `oidf-conformance` (the §1.8 Stage-7 gate — green CI confirms everything composes)

> **Tip for agents:** Start with `real-token-issuance` if you can only do one
> plan — it unblocks `session-ppid-seam`, which in turn unblocks three more
> plans simultaneously. It's the highest-leverage first move.
