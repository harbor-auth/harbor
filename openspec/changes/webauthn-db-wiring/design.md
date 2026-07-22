# Design: Wire the DB-backed WebAuthn credential store

## Key Decisions

### Decision 1: Conditional wiring in cmd/harbor-mgmt/main.go only
**Chosen:** Replace the unconditional `webauthn.NewInMemoryStore()` in
`cmd/harbor-mgmt/main.go` with a conditional: when `pool != nil` (i.e.
`DATABASE_URL` is configured), construct
`webauthn.NewDBStore(db.New(pool)).WithPool(pool)`; otherwise keep the
in-memory store.
**Rationale:** `webauthn.DBStore` already exists, already implements the
`webauthn.Store` interface, and is already fully tested
(`internal/webauthn/store_db.go`). The only missing piece is wiring — a
single conditional expression at construction time. No new code or interfaces
are required.
**Alternatives considered:** A separate env flag like `WEBAUTHN_STORE=db|memory`
(redundant with pool presence, risks drift between flag and reality, rejected).

### Decision 2: Always call `.WithPool(pool)` in the DB branch
**Chosen:** Construct as `webauthn.NewDBStore(db.New(pool)).WithPool(pool)`.
**Rationale:** `.WithPool(p txBeginner)` enables the atomic first-passkey
enrollment transaction (credential insert + pending→active status flip in one
transaction). Since we only enter the DB branch when `pool != nil`, wiring the
pool is always safe and always correct — omitting it would silently degrade to a
non-atomic best-effort path.
**Alternatives considered:** `NewDBStore` without `.WithPool` (loses atomicity of
enrollment completion, rejected).

### Decision 3: Declare `store` as the `webauthn.Store` interface
**Chosen:** `var store webauthn.Store` assigned in each branch.
**Rationale:** Both `*DBStore` and the in-memory store implement `Store`; typing
the variable to the interface keeps the downstream wiring identical and makes the
selection the only difference between the two paths.
**Alternatives considered:** Duplicating the wiring in each branch (more code,
easy to let the paths drift, rejected).

### Decision 4: Warn — but do not fail closed — on the in-memory fallback
**Chosen:** When `pool == nil`, log an explicit `Warn` ("dev only; credentials
lost on restart") and continue with the in-memory store.
**Rationale:** Local/dev bring-up must work without a database; a loud,
unambiguous warning gives operators the signal without blocking startup. Matches
the pattern used by every other conditional store selection in the binary.
**Alternatives considered:** Failing startup when `DATABASE_URL` is unset (breaks
frictionless local dev, rejected for this leaf wiring change).
