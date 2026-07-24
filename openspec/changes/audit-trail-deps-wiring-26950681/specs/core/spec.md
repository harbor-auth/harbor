# Spec: Wire AuditTrailDeps into harbor-mgmt (read-path activation)

Activates the existing `GET /audit-events` (mgmtapi) and dashboard activity
view (`GET /dashboard/activity`) by wiring the `AuditTrailDeps` struct that both
endpoints gate on. All underlying DB, query, and handler code is already on
`main`; this change is adapter + wiring only.

## ADDED Requirements

### Requirement: REQ-001 DBAuditStore satisfies mgmtapi.AuditStore

The system SHALL provide a `clients.DBAuditStore` that implements
`mgmtapi.AuditStore.ListAuditEvents(ctx, userID, limit, offset)` by calling
`db.Queries.ListAuditEventsByUserWithPayload` and converting each `db.AuditEvent`
row to a `mgmtapi.RawAuditEvent`. It MUST NOT redefine the `parseUUID` helper
already present in the package.

```go
type auditQuerier interface {
    ListAuditEventsByUserWithPayload(
        ctx context.Context,
        arg db.ListAuditEventsByUserWithPayloadParams,
    ) ([]db.AuditEvent, error)
}

type DBAuditStore struct { q auditQuerier }

func NewDBAuditStore(q *db.Queries) *DBAuditStore
func (s *DBAuditStore) ListAuditEvents(ctx context.Context, userID string, limit, offset int) ([]mgmtapi.RawAuditEvent, error)
```

#### Scenario: Happy-path row conversion

**Given** a fake querier returning one `db.AuditEvent` with known fields
**When** `DBAuditStore.ListAuditEvents` is called with a valid UUID string
**Then** the returned `[]mgmtapi.RawAuditEvent` has exactly one element with matching ID, EventType, ClientID, OccurredAt, and PayloadEncrypted

#### Scenario: Invalid userID propagates error

**Given** a userID string that is not a valid UUID
**When** `DBAuditStore.ListAuditEvents` is called
**Then** an error is returned and the querier is never called

### Requirement: REQ-002 AuditTrailDeps wired pool-gated in main

The system SHALL initialize `auditTrailDeps *mgmtapi.AuditTrailDeps` inside an
`if pool != nil` block in `cmd/harbor-mgmt/main.go`, using
`clients.NewDBAuditStore`, `clients.NewDBComplianceUserLoader`, `kp`, and
`crypto.NewCipher()`. When `pool` is nil, `auditTrailDeps` MUST remain nil so
the endpoint returns 503 (fail-closed).

#### Scenario: Pool present — deps wired

**Given** `DATABASE_URL` is set and `pool != nil`
**When** `main.go` initializes
**Then** `auditTrailDeps` is non-nil and `mgmtServer.WithAuditTrail` receives it

#### Scenario: Pool absent — endpoint returns 503

**Given** `DATABASE_URL` is not set and `pool == nil`
**When** `GET /audit-events` is called
**Then** the response is 503 Service Unavailable

### Requirement: REQ-003 WithAuditTrail chained on mgmtServer

The system SHALL chain `.WithAuditTrail(auditTrailDeps)` onto `mgmtServer` after
`.WithCompliance(complianceDeps)`.

### Requirement: REQ-004 DashboardHandler receives auditTrailDeps

The system SHALL replace the `nil` argument for `AuditTrailDeps` in
`bff.NewDashboardHandler(...)` with `auditTrailDeps`, enabling the
`GET /dashboard/activity` view to decrypt and render audit events.

#### Scenario: Dashboard activity renders events when deps wired

**Given** `auditTrailDeps` is non-nil and the user has audit events
**When** `GET /dashboard/activity` is requested
**Then** the handler decrypts and renders events rather than an empty view
