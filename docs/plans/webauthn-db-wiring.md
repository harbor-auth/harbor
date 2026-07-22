---
title: Wire sqlc-backed WebAuthn store in harbor-mgmt
status: draft
design_refs: [§4.1, §9]
targets: [cmd/harbor-mgmt/]
promoted_to: null
openspec: changes/webauthn-db-wiring
created: 2026-07-22
---

# Wire sqlc-backed WebAuthn store in harbor-mgmt (plan)

> **Dependency order:** This plan has no dependencies on other in-flight plans. It should
> land **before** `redis-enrollment-session` (which also touches `cmd/harbor-mgmt/main.go`)
> to minimize merge friction, and it is independent of `bff-flow-wiring`.

## Problem

`cmd/harbor-mgmt/main.go` unconditionally constructs the WebAuthn ceremony store with:

```go
// Dev ceremony stores (in-memory). Replace with sqlc-backed implementations
// once DATABASE_URL is wired
store := webauthn.NewInMemoryStore()
```

This line ignores the `pool` variable even when `DATABASE_URL` is set and a healthy
`*pgxpool.Pool` is available. Consequences:

- Registered credentials vanish on every process restart, even in DB-backed deployments.
- Multi-replica deployments cannot share credentials or ceremony state.
- The already-implemented and tested `webauthn.DBStore` (`internal/webauthn/store_db.go`)
  is dead code in the running binary.

The fix is purely a wiring change: everything needed already exists.

## Proposed approach

Replace the unconditional in-memory construction with a conditional selection based on
`pool`:

```go
var store webauthn.Store
if pool != nil {
    store = webauthn.NewDBStore(db.New(pool)).WithPool(pool)
    logger.Info("webauthn store: using DB-backed store")
} else {
    logger.Warn("DATABASE_URL not set — using in-memory WebAuthn store (dev only; credentials lost on restart)")
    store = webauthn.NewInMemoryStore()
}
```

Key points:

- `webauthn.NewDBStore(q dbStoreQuerier)` already exists and accepts the sqlc `db.New(pool)`
  querier.
- `.WithPool(pool)` already exists and enables the atomic credential-insert + user-activation
  transaction path; we must call it so finish-registration is transactional.
- `DBStore` already satisfies the `webauthn.Store` interface — no new interfaces, no adapters.
- The existing stale comment ("Replace with sqlc-backed implementations once DATABASE_URL
  is wired") is deleted as part of this change.

## DESIGN alignment

- **§4.1 (Persistence):** DB-backed stores must be used whenever `DATABASE_URL` is
  configured; in-memory stores are dev-only fallbacks. This change enforces exactly that
  policy for the WebAuthn store.
- **§9 (Operational logging):** Startup must log which backing store was selected, with
  `Warn` severity when running on a dev-only fallback. The proposed branches emit
  `Info`/`Warn` accordingly.

## Target code paths

- `cmd/harbor-mgmt/main.go` — the only file touched. Replace the
  `store := webauthn.NewInMemoryStore()` line (and stale comment) with the conditional
  block above. The `db` package import is already present (used for other pool wiring);
  verify and add only if missing.

Explicitly **not** touched:

- `internal/webauthn/store_db.go` — already complete.
- Migrations — the credential/ceremony tables already exist.
- Any interface definitions — `DBStore` already satisfies `webauthn.Store`.

## Implementation checklist

- [ ] In `cmd/harbor-mgmt/main.go`, delete the stale-TODO `store := webauthn.NewInMemoryStore()` line and comment.
- [ ] Add the `var store webauthn.Store` conditional: `pool != nil` →
      `webauthn.NewDBStore(db.New(pool)).WithPool(pool)` + `logger.Info`; else
      `logger.Warn` + `webauthn.NewInMemoryStore()`.
- [ ] Confirm the `db` package import exists in `main.go` (add if missing).
- [ ] `go build ./... && go vet ./...` pass.
- [ ] Author & verify paired OpenSpec change: `openspec validate webauthn-db-wiring --strict`.
- [ ] Reconcile & promote: `@plan promote webauthn-db-wiring`.

## Risks & open questions

- **Risk (low):** `WithPool` enables a transactional path; if omitted, credential insert
  and user activation would not be atomic. Mitigation: checklist explicitly requires
  `.WithPool(pool)` and code review verifies it.
- **Risk (low):** Behavior change for deployments that set `DATABASE_URL` but expected
  in-memory semantics (none known; DB semantics are strictly better).
- **Open question:** none. This is a ~5-line wiring fix, not a feature build.

## Definition of done

- With `DATABASE_URL` set, harbor-mgmt uses `webauthn.DBStore` (pool-enabled) and logs it
  at `Info`.
- Without `DATABASE_URL`, harbor-mgmt falls back to in-memory and logs a `Warn`.
- Credentials persist across restarts in DB mode.
- No files other than `cmd/harbor-mgmt/main.go` are modified; no new migrations or
  interfaces are introduced.
- `openspec validate webauthn-db-wiring --strict` passes; plan promoted from draft.
