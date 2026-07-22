# Proposal: User audit trail (user-owned, envelope-encrypted, crypto-shredded)

## Problem

A **user-owned audit trail** is a named privacy pillar (§2.1: the user can see
exactly what happened to their identity — every login, consent change, token
issuance, and revocation) with **nothing shipped**. Two properties make it more
than a log table: (1) it must be **owned by the user, not the operator** — the
operator should not be able to mine it for behavioural tracking; and (2) it must
be **crypto-shredded with the user** — when the user is erased (§11.6), their
trail must become permanently unrecoverable, even against immutable backups.
The shipped `internal/crypto/` envelope encryption (per-user DEK wrapped under a
regional KEK) is the exact primitive that delivers both: encrypt each event
under the user's DEK, and destroying `users.dek_wrapped` renders the whole trail
irrecoverable.

## Proposed Solution

1. **Data model (`0013_user_audit_events`)** — a `user_audit_events` table keyed
   by `user_id`, with a coarse `event_type`, `created_at`, and an
   **envelope-encrypted `payload` (🔒)** holding the event detail (RP/client,
   scopes, JTI, IP/user-agent where relevant). The payload is encrypted under
   the user's **DEK** via the shipped `Encryptor`, so the operator browsing the
   table sees only `user_id` + `event_type` + timestamp.
2. **Event taxonomy** — a closed set of `event_type`s: `auth.login`,
   `token.issued`, `token.refreshed`, `token.revoked`, plus the consent events
   from `consent-ledger` (`consent.granted`, `consent.scope_escalated`,
   `consent.revoked`). Align the schema with the consent-ledger seam.
3. **Emission seam (`internal/identity/`)** — an `AuditRecorder`
   (`Record(ctx, userID, eventType, detail)`) that uses the user's DEK,
   envelope-encrypts the detail, and inserts the row. Emission MUST be
   **best-effort / non-blocking** where it sits on the hot path — an
   audit-write failure logs + meters but never breaks authentication.
4. **User-facing read (`internal/mgmtapi/`)** — a user-authenticated endpoint
   that lists **the caller's own** decrypted events (decrypt under their DEK at
   read time). Strict ownership: a user reads only their own trail; the
   operator has **no plaintext read path**.
5. **Crypto-shred integration (§11.6)** — the trail piggybacks on the existing
   crypto-shred erasure: because every payload is encrypted under the user's
   DEK, deleting `users.dek_wrapped` already makes the trail unrecoverable. A
   test proves trail payloads are unreadable after the wrapped DEK is destroyed.

## Non-Goals

- A plaintext or operator-readable audit log — the operator must never get a
  behavioural-tracking read path (§2.1).
- Emitting the user-owned trail to an external SIEM — that moves PII off the
  user's regional, crypto-shreddable footprint (operator observability metrics,
  counters-only with no PII, are a separate concern).
- Encrypting under a global/audit key — a global key can't be crypto-shredded
  per-user, so erasure wouldn't reach the trail.
- Cross-region audit aggregation — the trail is regional, with the user's row.

## Success Criteria

- [ ] `user_audit_events` table (migration 0013): `user_id`, `event_type`, encrypted `payload`, `created_at`; index on `(user_id, created_at)`.
- [ ] The `payload` column stores ciphertext (encrypted under the user's DEK via the shipped `Encryptor`) — never plaintext detail.
- [ ] A closed `event_type` taxonomy (`auth.login`, `token.issued`, `token.refreshed`, `token.revoked`, + `consent.*` aligned with `consent-ledger`).
- [ ] `AuditRecorder.Record` envelope-encrypts and inserts; emission is best-effort / non-blocking (a failure logs + meters, never breaks the parent auth/token flow).
- [ ] Emission wired at login, token issue/refresh/revoke, and consent grant/revoke call sites.
- [ ] A user-authenticated `harbor-mgmt` endpoint lists the caller's own decrypted events; the operator has no plaintext read path.
- [ ] Strict ownership: a user cannot read another user's trail; the operator sees only `user_id`/`event_type`/timestamp.
- [ ] Crypto-shred (§11.6): after `users.dek_wrapped` is destroyed, the user's audit payloads are permanently unrecoverable (test mirrors the shipped envelope crypto-shred test).
- [ ] `make agent-check` clean.
