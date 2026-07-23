---
title: Wire AuditTrailDeps into harbor-mgmt (GET /audit-events + dashboard read-path)
status: draft
design_refs: [§2.1, §4.4, §10, §11.6]
targets: [internal/clients/, cmd/harbor-mgmt/main.go]
promoted_to: null
created: 2026-07-23
---

# Wire AuditTrailDeps into harbor-mgmt (plan)

> **Dependency:** Requires the `user-audit-trail` feature to be merged (it is —
> migration `0013_audit_events`, `internal/identity/audit.go`, and
> `internal/mgmtapi/audit.go` are all present on `main`). This plan is
> **wiring only** — no new DB migrations, no new SQL queries, no schema
> changes.

## Problem

`GET /audit-events` (mgmtapi) and the dashboard's `GET /profile/audit-events`
(bff) both gate on a non-nil `AuditTrailDeps`. Today both slots are `nil`:

```
# cmd/harbor-mgmt/main.go:327
nil, // AuditTrailDeps -- wired when audit-trail client adapter lands
```

Both endpoints therefore return `503 Service Unavailable` in production, even
though the underlying DB table, generated queries, and HTTP handlers are fully
implemented and tested. The only missing piece is:

1. A thin `AuditStore` adapter in `internal/clients/` that maps
   `*db.Queries.ListAuditEventsByUserWithPayload` → `[]mgmtapi.RawAuditEvent`.
2. Two lines in `cmd/harbor-mgmt/main.go` to build `mgmtapi.AuditTrailDeps`
   and pass it into both call sites.

## Interface satisfaction map

| `mgmtapi.AuditTrailDeps` field | Interface | Satisfied by | Status |
|---|---|---|---|
| `Store` | `mgmtapi.AuditStore` | new `clients.DBAuditStore` | ❌ needs creating |
| `Users` | `mgmtapi.AuditUserReader` | `*clients.DBComplianceUserLoader` | ✅ exists |
| `Keys` | `mgmtapi.AuditKeyUnwrapper` | `crypto.KeyProvider` (`kp` in main) | ✅ exists |
| `Decryptor` | `mgmtapi.AuditDecryptor` | `*crypto.Cipher` (`crypto.NewCipher()`) | ✅ exists |

`DBComplianceUserLoader.LoadUserForAudit` already satisfies both
`identity.AuditUserLoader` (write-path) and `mgmtapi.AuditUserReader`
(read-path) — it is the single canonical adapter for user DEK/region lookup.

## Proposed approach

### 1. Create `internal/clients/audit.go` — `DBAuditStore`

The `mgmtapi.AuditStore` interface requires:

```go
ListAuditEvents(ctx context.Context, userID string, limit, offset int) ([]mgmtapi.RawAuditEvent, error)
```

`*db.Queries` has `ListAuditEventsByUserWithPayload(ctx, arg ListAuditEventsByUserWithPayloadParams) ([]db.AuditEvent, error)`.
The adapter converts between the two types:

```go
// internal/clients/audit.go
package clients

import (
    "context"
    "fmt"

    "github.com/jackc/pgx/v5/pgtype"

    "github.com/harbor-auth/harbor/internal/gen/db"
    "github.com/harbor-auth/harbor/internal/mgmtapi"
)

// auditQuerier is the narrow interface over *db.Queries that DBAuditStore
// needs. Production code passes *db.Queries; tests pass a small fake.
type auditQuerier interface {
    ListAuditEventsByUserWithPayload(
        ctx context.Context,
        arg db.ListAuditEventsByUserWithPayloadParams,
    ) ([]db.AuditEvent, error)
}

// DBAuditStore adapts the audit_events table into the mgmtapi.AuditStore
// interface. It is the single place that converts a string UUID into a
// pgtype.UUID for the audit read-path.
type DBAuditStore struct {
    q auditQuerier
}

// NewDBAuditStore returns a store backed by q. q is typically *db.Queries
// obtained from a pgx connection pool.
func NewDBAuditStore(q *db.Queries) *DBAuditStore {
    return &DBAuditStore{q: q}
}

// ListAuditEvents implements mgmtapi.AuditStore. It returns the user's audit
// events newest-first with limit/offset pagination.
func (s *DBAuditStore) ListAuditEvents(
    ctx context.Context,
    userID string,
    limit, offset int,
) ([]mgmtapi.RawAuditEvent, error) {
    id, err := parseUUID(userID)
    if err != nil {
        return nil, fmt.Errorf("clients: audit: parse user ID %q: %w", userID, err)
    }
    rows, err := s.q.ListAuditEventsByUserWithPayload(ctx, db.ListAuditEventsByUserWithPayloadParams{
        UserID: id,
        Limit:  int32(limit),
        Offset: int32(offset),
    })
    if err != nil {
        return nil, fmt.Errorf("clients: audit: list events: %w", err)
    }
    out := make([]mgmtapi.RawAuditEvent, len(rows))
    for i, r := range rows {
        var idStr string
        if b, err2 := r.ID.Value(); err2 == nil && b != nil {
            idStr = fmt.Sprintf("%v", b)
        }
        var occurredAt time.Time
        if r.OccurredAt.Valid {
            occurredAt = r.OccurredAt.Time
        }
        out[i] = mgmtapi.RawAuditEvent{
            ID:               idStr,
            EventType:        r.EventType,
            ClientID:         r.ClientID,
            OccurredAt:       occurredAt,
            Region:           r.Region,
            PayloadEncrypted: r.PayloadEncrypted,
        }
    }
    return out, nil
}
```

> **Note:** `parseUUID` is already a package-level helper in `internal/clients/`
> (used by `compliance.go`, `users.go`, etc.) — do not redefine it.

### 2. Wire `AuditTrailDeps` in `cmd/harbor-mgmt/main.go`

Add an `auditTrailDeps` variable alongside the existing `complianceDeps` block
(both gate on `pool != nil`):

```go
// Audit-trail read-path. Reuses DBComplianceUserLoader for the user DEK/region
// lookup — it is the canonical adapter for both the compliance and audit paths.
var auditTrailDeps *mgmtapi.AuditTrailDeps
if pool != nil {
    q := db.New(pool)
    auditTrailDeps = &mgmtapi.AuditTrailDeps{
        Store:     clients.NewDBAuditStore(q),
        Users:     clients.NewDBComplianceUserLoader(q),
        Keys:      kp,
        Decryptor: crypto.NewCipher(),
    }
    logger.Info("audit trail: read-path enabled")
} else {
    logger.Warn("DATABASE_URL not set — audit-events endpoint will return 503 (dev mode)")
}
```

Then chain `.WithAuditTrail(auditTrailDeps)` onto `mgmtServer`:

```go
mgmtServer := mgmtapi.New(enroller, logger).
    WithConsentStore(consentStore).
    WithSessionRevoker(sessionRevoker).
    WithMFA(mfaService).
    WithCompliance(complianceDeps).
    WithAuditTrail(auditTrailDeps)   // ← add this
```

And replace the `nil` in `bff.NewDashboardHandler`:

```go
dashHandler := bff.NewDashboardHandler(
    dashConsentStore,
    dashSessionStore,
    dashCredStore,
    auditTrailDeps,   // was: nil
    dashRelayStore,
    dashTmpl,
    logger,
)
```

### 3. No new tests required at the wiring level

`internal/mgmtapi/audit_test.go` already has comprehensive tests for
`GetAuditEvents` using `newTestAuditDeps`. The new `DBAuditStore` adapter
should have a unit test in `internal/clients/audit_test.go` using the same
fake-querier pattern established by `compliance.go`, `users.go`, etc.

The test should exercise:
- `ListAuditEvents` → correct `pgtype.UUID` passed, correct `RawAuditEvent`
  slice returned.
- Invalid `userID` string → error propagated.

## Checklist

- [ ] Create `internal/clients/audit.go` with `DBAuditStore`
- [ ] Create `internal/clients/audit_test.go` with a fake-querier unit test
- [ ] Wire `auditTrailDeps` in `cmd/harbor-mgmt/main.go` (pool-gated block)
- [ ] Chain `.WithAuditTrail(auditTrailDeps)` on `mgmtServer`
- [ ] Replace `nil` → `auditTrailDeps` in `bff.NewDashboardHandler` call
- [ ] `go build ./...` passes
- [ ] `go test ./internal/clients/... ./internal/mgmtapi/... ./cmd/harbor-mgmt/...` passes

## Open questions

None — all interfaces are defined, all DB queries are generated, all crypto
helpers exist. This is pure wiring.

## Non-goals

- **Write-path call sites** (emitting audit events from login, token issue,
  etc.) — those belong to a separate "audit-trail-emission" plan. The read
  endpoint will return an empty list until events are emitted; that is correct
  and expected.
- **BYO-domain DB persistence** — the in-memory `BYODomainStore` scaffold is
  intentional and tracked separately.
