# Proposal: Wire AuditTrailDeps into harbor-mgmt (GET /audit-events read-path)

## Problem

`GET /audit-events` (mgmtapi) and the BFF `GET /profile/audit-events` (dashboard
activity view) both gate on a non-nil `AuditTrailDeps`. Both slots are currently
`nil` in `cmd/harbor-mgmt/main.go`, so both endpoints return `503 Service
Unavailable` in production — even though the underlying DB table, generated
queries, and HTTP handlers are fully implemented and tested on `main`. The only
missing piece is: (1) a thin `AuditStore` adapter in `internal/clients/` and (2)
two wiring lines in `cmd/harbor-mgmt/main.go`.

## Proposed Solution

1. **Create `clients.DBAuditStore`** — a narrow adapter over `*db.Queries` that
   satisfies `mgmtapi.AuditStore` by calling
   `ListAuditEventsByUserWithPayload` and converting rows to
   `[]mgmtapi.RawAuditEvent`. Uses the existing `parseUUID` helper (already in
   the package); do not redefine it.
2. **Wire `AuditTrailDeps` in `cmd/harbor-mgmt/main.go`** — add a pool-gated
   `auditTrailDeps` block mirroring the existing `complianceDeps` block, then
   chain `.WithAuditTrail(auditTrailDeps)` onto `mgmtServer` and replace the
   `nil` argument in `bff.NewDashboardHandler`.

All other deps (`Users`, `Keys`, `Decryptor`) are already wired via existing
adapters (`DBComplianceUserLoader`, `kp`, `crypto.NewCipher()`).

## Non-Goals

- Write-path audit emission (emitting events from login, token issue, etc.) —
  tracked in a separate plan. An empty list is correct until events are emitted.
- New DB migrations, new SQL queries, or schema changes — all exist on `main`.
- BYO-domain DB persistence — separate scaffold.
- Operator plaintext read path — Harbor's invariant (§2.1) prohibits it.

## Success Criteria

- [ ] `clients.DBAuditStore` created, satisfying `mgmtapi.AuditStore`.
- [ ] `auditTrailDeps` wired in `cmd/harbor-mgmt/main.go` (pool-gated).
- [ ] `.WithAuditTrail(auditTrailDeps)` chained on `mgmtServer`.
- [ ] `nil` → `auditTrailDeps` in `bff.NewDashboardHandler`.
- [ ] Unit test for `DBAuditStore` using fake querier pattern.
- [ ] `go build ./...` and `go test ./internal/clients/... ./internal/mgmtapi/... ./cmd/harbor-mgmt/...` pass.
- [ ] `make agent-check` clean.
