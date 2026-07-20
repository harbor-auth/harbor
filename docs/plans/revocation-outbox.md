---
title: Revocation outbox (durable theft-signal delivery)
status: completed
design_refs: [§3.5, §3.5.2, §10]
targets: [internal/oidc/, internal/clients/, db/migrations/, db/queries/]
promoted_to: docs/features/revocation-outbox.md
openspec: changes/revocation-outbox
created: 2026-07-14
---

# Revocation outbox (plan)

> **Dependency order:** depends on **`refresh-token-rotation`** (the theft
> signal already fires in `service.go`; this plan just makes its delivery
> durable) and **`grant-id-fk`** (the outbox row should reference the grant
> being revoked for audit provenance). Best built after both, but can be
> prototyped independently against `RevokeSessionsByUserClient`.

## Problem

Both `signalRefreshReuse()` and `signalCodeReuse()` in `internal/oidc/service.go`
carry this `TODO(security)`:

```go
// TODO(security): route revocation through a durable outbox so a transient
// failure is retried, not merely alerted (the in-process best-effort signal
// is the correct interim handling, not the final design).
```

And `Refresh()` itself acknowledges the window explicitly:

```go
// ACCEPTED RISK (RFC 6749 §10.4): if the HTTP response write fails after
// this point, the client loses the new token and cannot retry — presenting
// the (now-revoked) old token fires the theft signal and revokes the family.
// This is the standard refresh-rotation trade-off. A durable outbox pattern
// (write pending→after-commit→send) would eliminate the window but adds
// significant complexity. Documented in docs/DESIGN.md §3.5 for future
// revisit when SLA requirements are known.
```

The current in-process signal:
1. Detaches from the caller's context (`context.WithoutCancel`).
2. Attempts `RevocationSink.RevokeSessionsByUserClient` with a 10-second timeout.
3. On failure, logs with `slog.ErrorContext` — **and stops**. No retry, no
   persistent record that the revocation was attempted and failed.

This means a transient DB hiccup during a theft signal leaves the compromised
session family alive until the next token expiry. For a high-value account that
is an unacceptable silent failure.

## Proposed approach

### The outbox pattern

```
signalRefreshReuse / signalCodeReuse
    │
    ├─► INSERT INTO revocation_outbox (id, reason, user_id, client_id,
    │       grant_id, status='pending', created_at) — in the same DB
    │       transaction as the calling operation (if any), or standalone
    │
    └─► best-effort inline attempt (existing 10-second window)
            │
            ├─ success → UPDATE revocation_outbox SET status='delivered'
            └─ failure → leave status='pending' (worker picks it up)

Background worker (RevocationWorker):
    LOOP every ~5 s:
        SELECT ... FROM revocation_outbox WHERE status='pending'
            AND created_at > now() - INTERVAL '24 hours'  -- TTL
            FOR UPDATE SKIP LOCKED
        FOR EACH row:
            attempt RevocationSink.RevokeSessionsByUserClient
            success → DELETE (or status='delivered')
            failure → UPDATE retry_count++, next_attempt_at=now()+backoff
```

### Schema

```sql
-- db/migrations/0004_revocation_outbox.up.sql
CREATE TABLE revocation_outbox (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    reason       TEXT NOT NULL,           -- 'refresh_reuse' | 'code_reuse'
    user_id      UUID NOT NULL,
    client_id    TEXT NOT NULL,
    grant_id     UUID REFERENCES grants(id),   -- nullable until grant-id-fk lands
    status       TEXT NOT NULL DEFAULT 'pending',  -- 'pending' | 'delivered' | 'failed'
    retry_count  INT  NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX revocation_outbox_pending_idx
    ON revocation_outbox (next_attempt_at)
    WHERE status = 'pending';
```

### Implementation pieces

1. **`RevocationOutbox` interface** in `internal/oidc/store.go`:
   ```go
   type RevocationOutbox interface {
       Enqueue(ctx context.Context, entry OutboxEntry) error
       DeliverPending(ctx context.Context, sink RevocationSink) error
   }
   ```

2. **`InMemoryRevocationOutbox`** — for tests: records entries, `DeliverPending`
   iterates and calls the sink, collects failures. No retry needed in tests.

3. **`DBRevocationOutbox`** in `internal/clients/` — sqlc-backed impl. `Enqueue`
   does the INSERT; `DeliverPending` does the `SELECT … FOR UPDATE SKIP LOCKED`
   loop with exponential backoff (cap at 1 h, TTL 24 h).

4. **Wire into `signalRefreshReuse` / `signalCodeReuse`** — after the best-effort
   inline attempt, call `outbox.Enqueue` if the call failed (or always, and let
   `DeliverPending` be idempotent via the delivered status check).

5. **`RevocationWorker`** — a goroutine started in `cmd/harbor-hot/main.go`
   (alongside the existing signal functions) that ticks every 5 s and calls
   `outbox.DeliverPending`. Graceful shutdown via context cancellation.

### Retry policy

| Attempt | Wait |
|---|---|
| 1 | 5 s |
| 2 | 30 s |
| 3 | 5 min |
| 4 | 30 min |
| 5+ | 1 h (cap) |
| TTL | 24 h (then status='failed', alert) |

The TTL is generous: even 24 h of failed delivery is better than silent loss,
and a 24-h-old refresh token is likely expired anyway (default TTL).

## DESIGN alignment

Realizes the §3.5 "durable revocation" note. Satisfies the `TODO(security)`
in `service.go`. Adds the `revocation_outbox` table to §10's data model
(a minor DESIGN addendum, no architectural change). Does **not** change
the §3.5 bloom-filter kill design — the outbox is for persistent DB-backed
revocation; the bloom filter is for in-process near-instant kill (a separate
plan).

## Target code paths

- `db/migrations/0004_revocation_outbox.{up,down}.sql`
- `db/queries/revocation_outbox.sql`
- `internal/gen/db/revocation_outbox.sql.go` (regenerated)
- `internal/oidc/store.go` — `RevocationOutbox` interface + `OutboxEntry` type
- `internal/oidc/service.go` — wire outbox into signal functions; remove `TODO(security)`
- `internal/clients/revocation_outbox.go` — `DBRevocationOutbox`
- `cmd/harbor-hot/main.go` — start `RevocationWorker` goroutine
- `internal/oidc/*_test.go` — chaos test: outbox enqueues on sink failure

## Implementation checklist

- [x] Write migration `0009_revocation_outbox.{up,down}.sql`
- [x] Write `db/queries/revocation_outbox.sql` (Enqueue, FetchPending, MarkDelivered, IncrementRetry, MarkFailed)
- [x] Run `sqlc generate`
- [x] Define `RevocationOutbox` interface + `OutboxEntry` type in `internal/oidc/service.go`
- [x] Implement `DBRevocationOutbox` in `internal/clients/revocation_outbox.go`
- [x] Wire outbox into `signalRefreshReuse` and `signalCodeReuse` (remove `TODO(security)`)
- [x] Add `RevocationWorker` goroutine in `internal/oidc/worker.go`, started in `cmd/harbor-hot/main.go`
- [x] Add chaos test: sink failure → outbox.Enqueue called
- [x] `go test -race ./...` passes
- [x] `@validate` passes

## As-built notes (divergences from the draft above)

- **Migration number is `0009`**, not `0004` — it was renumbered from `0006`
  during the merge to main to avoid colliding with `0006_recovery_required`;
  it lands after the recovery-required, sessions-grant-id, and signing-keys
  migrations merged in the interim. Merged to main in PR #32.
- **The `RevocationOutbox` interface + `OutboxEntry` domain type live in
  `internal/oidc/service.go`, not `store.go`** — they must be in the `oidc`
  package (not `internal/clients`) because `clients` imports `oidc`; defining
  them there avoids a circular import. A default `noopRevocationOutbox` is the
  fallback when no outbox is wired (dev/test).
- **No standalone `InMemoryRevocationOutbox`** — tests use a `recordingOutbox`
  fake (in `internal/oidc/chaos_test.go`) that records `Enqueue` calls, plus the
  `mockOutboxQuerier`/`mockSessionStore` fakes in
  `internal/clients/revocation_outbox_test.go` for the `DeliverPending` retry/
  TTL/idempotency paths.
- **`RevocationWorker` lives in `internal/oidc/worker.go`** and reaches the
  concrete `DBRevocationOutbox.DeliverPending` via the `OutboxDeliverer`
  interface (again to avoid the `clients → oidc` import cycle). It is started as
  a background goroutine in `cmd/harbor-hot/main.go` and shuts down on context
  cancellation.
- **Durability invariant registered** as `INV-DURABLE-REVOCATION` in
  `invariants/registry.yaml`.
