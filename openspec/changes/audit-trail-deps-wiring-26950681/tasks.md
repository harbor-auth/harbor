# Tasks: Wire AuditTrailDeps into harbor-mgmt

## Prerequisites

- Migration `0013_audit_events` is on `main` ✅
- `internal/mgmtapi/audit.go` (`AuditTrailDeps`, `AuditStore`, `GetAuditEvents`) is on `main` ✅
- `internal/gen/db/audit_events.sql.go` (`ListAuditEventsByUserWithPayload`) is on `main` ✅
- `clients.DBComplianceUserLoader`, `kp`, `crypto.NewCipher()` all exist ✅

## Implementation

- [ ] Create `internal/clients/audit.go` with `DBAuditStore`:
  - `auditQuerier` narrow interface (only `ListAuditEventsByUserWithPayload`)
  - `DBAuditStore` struct + `NewDBAuditStore(q *db.Queries) *DBAuditStore`
  - `ListAuditEvents(ctx, userID, limit, offset)` — uses existing `parseUUID`, converts `[]db.AuditEvent` → `[]mgmtapi.RawAuditEvent`
- [ ] Wire `auditTrailDeps` in `cmd/harbor-mgmt/main.go`:
  - Pool-gated block (after `complianceDeps`) initializing `*mgmtapi.AuditTrailDeps`
  - Chain `.WithAuditTrail(auditTrailDeps)` on `mgmtServer`
  - Replace `nil` → `auditTrailDeps` in `bff.NewDashboardHandler` call

## Tests

- [ ] Create `internal/clients/audit_test.go`:
  - Fake querier returning fixed `[]db.AuditEvent` rows
  - Verify `ListAuditEvents` converts rows correctly (ID, EventType, ClientID, OccurredAt, PayloadEncrypted)
  - Verify invalid `userID` string → error propagated

## Validation

- [ ] `go build ./...`
- [ ] `go test ./internal/clients/... ./internal/mgmtapi/... ./cmd/harbor-mgmt/...`
- [ ] `make agent-check`
- [ ] `openspec validate audit-trail-deps-wiring-26950681 --strict`
