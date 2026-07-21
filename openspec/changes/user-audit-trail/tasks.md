# Tasks: User audit trail (user-owned, envelope-encrypted, crypto-shredded)

## Prerequisites

- [ ] **Soft-gated on `consent-ledger`.** That change defines the consent event
  taxonomy (`consent.granted`, `consent.scope_escalated`, `consent.revoked`)
  this trail consumes; align the event schema with it. The trail can **start
  independently** — it records login, token, and revocation events regardless,
  and adds the consent events once that taxonomy lands. No hot-path contention.
- [ ] **Migration prefix `0013` is reserved** for this change
  (`db/migrations/0013_user_audit_events.up.sql` / `.down.sql`). Do not reuse
  `0013` elsewhere (consent-ledger holds 0011, dynamic-client-registration 0012).

## Implementation

- [ ] Migration `0013_user_audit_events` (up/down): `user_audit_events(user_id,
  event_type, payload_encrypted, created_at)`, index on `(user_id, created_at)`.
- [ ] `db/queries/user_audit_events.sql` + `make codegen`: insert-event,
  list-by-user (paginated, newest-first).
- [ ] `internal/identity/` `AuditRecorder.Record(ctx, userID, eventType,
  detail)`: load the user's DEK, envelope-encrypt `detail` via the shipped
  `Encryptor`, insert the row.
- [ ] Define the closed `event_type` taxonomy (`auth.login`, `token.issued`,
  `token.refreshed`, `token.revoked`, + consent events aligned with
  `consent-ledger`).
- [ ] Wire emission at call sites (login, token issue/refresh/revoke, consent
  grant/revoke); emission is **best-effort / non-blocking** — a write failure
  logs + meters but never breaks the auth/token flow.
- [ ] `internal/mgmtapi/` user endpoint: list **the caller's own** events,
  decrypting `payload` under the caller's DEK; paginated.
- [ ] Strict ownership: a user reads only their own trail; there is **no
  operator plaintext read path** (operator sees only `user_id`/`event_type`/
  timestamp).

## Tests

- [ ] Recording an event encrypts the payload (the raw column is ciphertext, not
  plaintext).
- [ ] The owning user reads back the decrypted detail; a different user cannot
  read it.
- [ ] Best-effort emission failure does not break the parent flow.
- [ ] Crypto-shred (§11.6): after `users.dek_wrapped` is destroyed, the user's
  audit payloads are permanently unrecoverable (mirror the envelope
  crypto-shred test).
- [ ] Privacy: an operator-level table read exposes no event detail (only coarse
  `event_type` + timestamp); no cross-user leakage.

## Validation

- [ ] `go build ./... && go vet ./... && go test ./...`
- [ ] `make agent-check`
- [ ] `openspec validate user-audit-trail --strict`
