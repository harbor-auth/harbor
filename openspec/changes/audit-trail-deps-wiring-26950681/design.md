# Design: Wire AuditTrailDeps into harbor-mgmt

## Key Decisions

### Decision 1: Reuse DBComplianceUserLoader for Users dep
**Chosen:** `*clients.DBComplianceUserLoader` satisfies both
`identity.AuditUserLoader` (write-path) and `mgmtapi.AuditUserReader`
(read-path). It is passed as the `Users` field of `AuditTrailDeps`.
**Rationale:** The interface requires only `LoadUserForAudit(ctx, userID) (region, dekWrapped, error)` — exactly what `DBComplianceUserLoader` already provides. Creating a second adapter would be redundant and diverge the two paths.
**Alternatives considered:** A dedicated `DBAuditUserLoader` (rejected — pure duplication of existing code).

### Decision 2: Narrow `auditQuerier` interface in DBAuditStore
**Chosen:** `DBAuditStore` depends on a package-local `auditQuerier` interface exposing only `ListAuditEventsByUserWithPayload`. Production passes `*db.Queries`; tests pass a small fake struct.
**Rationale:** Consistent with `complianceUserQuerier`, `consentQuerier`, etc. already in `internal/clients/`. This is the established fake-querier pattern that keeps unit tests free of a real DB.
**Alternatives considered:** Accepting `*db.Queries` directly (rejected — prevents unit testing without a live DB).

### Decision 3: Pool-gate the auditTrailDeps block
**Chosen:** The `auditTrailDeps` variable is initialized inside `if pool != nil { … }`, mirroring the `complianceDeps` block immediately above it in `main.go`. When `pool` is nil (dev mode / no `DATABASE_URL`), `auditTrailDeps` stays nil and the endpoint returns 503 — correct fail-closed behaviour.
**Rationale:** All DB-backed deps in `main.go` use this pattern. Consistency makes the code readable and the dev-mode behaviour predictable.

### Decision 4: No new migrations or SQL queries
**Chosen:** This plan is wiring only. Migration `0013_audit_events` and `ListAuditEventsByUserWithPayload` already exist on `main`.
**Rationale:** The gap is only the adapter and the wiring call sites. Writing new SQL or migrations here would be scope creep and risk reintroducing already-merged work.

## Interface Satisfaction Map

| `mgmtapi.AuditTrailDeps` field | Interface | Satisfied by | Status |
|---|---|---|---|
| `Store` | `mgmtapi.AuditStore` | `clients.DBAuditStore` | ❌ CREATE |
| `Users` | `mgmtapi.AuditUserReader` | `*clients.DBComplianceUserLoader` | ✅ EXISTS |
| `Keys` | `mgmtapi.AuditKeyUnwrapper` | `crypto.KeyProvider` (`kp`) | ✅ EXISTS |
| `Decryptor` | `mgmtapi.AuditDecryptor` | `*crypto.Cipher` | ✅ EXISTS |
