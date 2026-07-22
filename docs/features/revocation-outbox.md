---
title: Revocation Outbox (durable theft-signal delivery)
status: implemented
design_refs: [§3.5, §10]
code:  [internal/oidc/, internal/clients/, db/migrations/, db/queries/]
spec:  []
tests: [internal/oidc/, internal/clients/]
depends_on: [oidc-authorization-code]
plan: revocation-outbox
last_reconciled: 2026-07-20
---

# Revocation Outbox (durable theft-signal delivery)

## Summary

Harbor's theft signals — the family revocations fired when a rotated refresh
token or a spent authorization code is replayed — are now **durable**
(docs/DESIGN.md §3.5). Previously `signalRefreshReuse()` and `signalCodeReuse()`
made a single best-effort, in-process `RevokeSessionsByUserClient` call and, on
failure, only logged: a transient DB hiccup during a theft signal left the
compromised session family alive until token expiry. The outbox pattern closes
that silent-failure window: every signal is **persisted to a `revocation_outbox`
table** and a background `RevocationWorker` retries delivery with exponential
backoff until it succeeds (or a 24 h TTL expires and the row is marked failed
for alerting). This satisfies the long-standing `TODO(security)` in the OIDC
service and makes revocation delivery survive process crashes and DB blips.

## Behavior (as-built)

**Schema (`0009_revocation_outbox`)** — a `revocation_outbox` table records each
pending revocation: `reason` (`refresh_reuse` | `code_reuse`), `user_id`,
`client_id`, nullable `grant_id`, `status` (`pending` | `delivered` | `failed`),
`retry_count`, `next_attempt_at`, and `created_at`. A partial index on
`next_attempt_at WHERE status = 'pending'` makes the worker's "what's due now?"
scan cheap.

**Enqueue path** — `signalRefreshReuse` / `signalCodeReuse` still attempt the
existing best-effort inline revocation, but now also `Enqueue` an outbox entry so
a failed (or never-attempted) delivery is guaranteed a durable retry. The
`TODO(security)` note is gone.

**Delivery worker (`RevocationWorker`)** — a background goroutine started in
`cmd/harbor-hot/main.go` ticks periodically and calls `DeliverPending`, which
pulls due `pending` rows (`SELECT … FOR UPDATE SKIP LOCKED`), attempts the sink's
`RevokeSessionsByUserClient`, and on success marks them `delivered` (idempotent
via the status check). On failure it increments `retry_count` and pushes
`next_attempt_at` out by an exponential backoff capped at 1 h; past the 24 h TTL
the row is marked `failed`. The worker shuts down cleanly on context cancellation.

**Fail-open on enqueue, fail-safe on delivery** — if no outbox is wired (dev /
test), a default `noopRevocationOutbox` is used so the service still runs; in
production the durable path is always present.

## Interfaces / Endpoints

No HTTP surface. Exported Go surface:

- `oidc.RevocationOutbox` — `Enqueue(ctx, OutboxEntry) error` (lives in
  `internal/oidc/service.go`, not `store.go`, to avoid a `clients → oidc` import
  cycle).
- `oidc.OutboxEntry` — the domain record enqueued on each theft signal.
- `oidc.OutboxDeliverer` — the interface the `RevocationWorker` calls to drive
  delivery, satisfied by the concrete `DBRevocationOutbox.DeliverPending`.
- `clients.DBRevocationOutbox` — sqlc-backed `Enqueue` + `DeliverPending`
  (retry / TTL / idempotency).

## Code map

| Path | Role |
|---|---|
| `db/migrations/0009_revocation_outbox.{up,down}.sql` | `revocation_outbox` table + partial pending index. |
| `db/queries/revocation_outbox.sql` | Enqueue, FetchPending, MarkDelivered, IncrementRetry, MarkFailed. |
| `internal/gen/db/revocation_outbox.sql.go` | Regenerated sqlc output. |
| `internal/oidc/service.go` | `RevocationOutbox` interface + `OutboxEntry` type; signal functions enqueue; `noopRevocationOutbox` default. |
| `internal/oidc/worker.go` | `RevocationWorker` — periodic `DeliverPending` via the `OutboxDeliverer` seam; context-cancellation shutdown. |
| `internal/clients/revocation_outbox.go` | `DBRevocationOutbox` — Enqueue + backoff/TTL delivery loop. |
| `cmd/harbor-hot/main.go` | Starts the `RevocationWorker` goroutine. |

## Security & privacy invariants

- **Durable revocation (§3.5)** — a theft signal is never silently lost: it is
  persisted before/alongside the inline attempt and retried until delivered or
  TTL-expired. Registered as `INV-DURABLE-REVOCATION` in
  `invariants/registry.yaml`.
- **Idempotent delivery** — re-delivering an already-`delivered` entry is a
  no-op (status-guarded), so worker retries and crash recovery cannot
  double-revoke or thrash.
- **Bounded retry, loud failure** — backoff caps at 1 h and the 24 h TTL flips a
  stuck entry to `failed` so it surfaces for alerting rather than retrying
  forever.
- **No PII in the outbox** — entries carry opaque `user_id` / `grant_id` UUIDs
  and an opaque `client_id`; no user-identifying data is persisted.

## Tests

- `internal/oidc/chaos_test.go` — a `recordingOutbox` fake asserts that a sink
  failure during a theft signal results in an `Enqueue` (the durability
  guarantee).
- `internal/clients/revocation_outbox_test.go` — `mockOutboxQuerier` /
  `mockSessionStore` fakes cover `DeliverPending`'s retry, backoff, TTL-expiry,
  and idempotency paths.

## Known gaps / TODOs

- **`grant_id` is nullable in the outbox** — until per-grant provenance is
  populated end-to-end (tracked by `grant-id-fk` / `session-ppid-seam`), some
  entries revoke at `(user, client)` scope rather than the narrower grant scope.
- **Single-node worker cadence** — `FOR UPDATE SKIP LOCKED` makes the worker
  safe to run on every replica, but delivery latency is bounded by the tick
  interval; a push/notify trigger could tighten it if SLAs demand.

## As-built note

Migration landed as `0009_revocation_outbox` (renumbered from the draft's `0004`
/ interim `0006` to avoid colliding with `0006_recovery_required` and the
sessions-grant-id / signing-keys migrations merged in the interim). The
`RevocationOutbox` interface and `OutboxEntry` type live in
`internal/oidc/service.go` (not `store.go`) to avoid a `clients → oidc` import
cycle, and the worker reaches the concrete DB impl through the `OutboxDeliverer`
seam for the same reason. Merged to `main` in PR #32.
