---
title: User audit trail (user-owned, envelope-encrypted, crypto-shredded event log)
status: draft
design_refs: [§2.1, §4.4, §10, §11.6]
targets: [internal/identity/, internal/mgmtapi/, internal/crypto/, db/migrations/, db/queries/]
promoted_to: null
openspec: changes/user-audit-trail
created: 2026-07-21
---

# User audit trail (plan)

> **Dependency order:** **soft-gated** on `consent-ledger`. That plan defines
> the consent event taxonomy (`consent.granted`, `consent.scope_escalated`,
> `consent.revoked`) this trail consumes; the trail's event schema should align
> with it. But the trail can **start independently** — it records login, token,
> and revocation events regardless, and simply adds consent events to the
> schema once that taxonomy lands. No hot-path contention.
>
> **Migration prefix `0013` is reserved** for this plan
> (`db/migrations/0013_user_audit_events.up.sql` / `.down.sql`). Do not reuse
> `0013` elsewhere — the reservation prevents the migration-collision failure
> mode.

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
under the user's DEK, and destroying `users.dek_wrapped` renders the whole
trail irrecoverable.

## Proposed approach

1. **Data model (`0013_user_audit_events`)** — a `user_audit_events` table keyed
   by `user_id`, with `event_type`, `created_at`, and an
   **envelope-encrypted `payload` (🔒)** holding the event detail (RP/client,
   scopes, JTI, IP/user-agent where relevant). The payload is encrypted under
   the user's **DEK** via the shipped `Encryptor` — so the operator, browsing
   the table directly, sees only `user_id` + `event_type` + timestamp, never
   the sensitive detail. (Whether `event_type` itself is encrypted is an open
   question below; default is to keep the coarse type in the clear for
   filtering, encrypt the detail.)
2. **Event taxonomy** — a closed set of `event_type`s: `auth.login`,
   `token.issued`, `token.refreshed`, `token.revoked`, plus the consent events
   from `consent-ledger` (`consent.granted`, `consent.scope_escalated`,
   `consent.revoked`). Align the schema with the consent-ledger seam.
3. **Emission seam (`internal/identity/`)** — a small `AuditRecorder`
   (`Record(ctx, userID, eventType, detail)`) that fetches/uses the user's DEK,
   envelope-encrypts the detail, and inserts the row. Call sites (login, token
   issue/refresh/revoke, consent grant/revoke) emit through it. Emission MUST
   be **best-effort / non-blocking on the hot path** where applicable — an
   audit-write failure must never break authentication (log + metric, don't
   fail the flow).
4. **User-facing read (`internal/mgmtapi/`)** — a user-authenticated endpoint
   that lists **the caller's own** decrypted events (decrypt under their DEK at
   read time). Strict ownership: a user can only read their own trail; the
   operator has no plaintext read path.
5. **Crypto-shred integration (§11.6)** — the trail piggybacks on the existing
   crypto-shred erasure: because every payload is encrypted under the user's
   DEK, deleting `users.dek_wrapped` already makes the trail unrecoverable. Add
   a test proving trail payloads are unreadable after the wrapped DEK is
   destroyed (mirrors the shipped envelope crypto-shred test).

**Alternatives considered.** *A plaintext audit log* — rejected: it hands the
operator exactly the behavioural-tracking capability Harbor promises to deny
(§2.1), and it survives crypto-shred (an erased user's history would persist in
backups). *Encrypt under a global/audit key* — rejected: a global key can't be
crypto-shredded per-user, so erasure wouldn't reach the trail. *Emit to an
external SIEM* — rejected for the user-owned trail: it moves PII off the user's
regional, crypto-shreddable footprint (operator observability metrics — §6.5,
counters only, no PII — are a separate concern).

## DESIGN alignment

Realises §2.1 (user-owned, tracking-resistant audit trail), §4.4 (reuses the
per-user DEK envelope), §10 (a new 🔒 data-model table), and §11.6
(crypto-shred erasure reaches the trail). It does **not** change `DESIGN.md` —
the user-owned audit trail is already a stated pillar; this plan builds it on
the shipped envelope-encryption primitive. The trail is **regional** (lives
with the user's row), consistent with §5 — no cross-region audit aggregation.

## Target code paths

- `db/migrations/0013_user_audit_events.up.sql` / `.down.sql` — the
  `user_audit_events` table with an encrypted `payload` column (**reserved
  prefix 0013**).
- `db/queries/user_audit_events.sql` — sqlc queries (insert, list-by-user).
- `internal/identity/` — `AuditRecorder` (envelope-encrypt detail under the
  user DEK, insert); best-effort emission helpers.
- `internal/crypto/` — reused (`Encryptor`/`Decryptor`, DEK); no new crypto,
  possibly a thin helper if a per-event encrypt convenience is warranted.
- `internal/mgmtapi/` — user-authenticated "list my audit events" endpoint
  (decrypt under the caller's DEK).

## Implementation checklist

- [ ] Migration `0013_user_audit_events` (up/down): `user_audit_events(user_id, event_type, payload_encrypted, created_at)`, index on `(user_id, created_at)`. **Prefix 0013 is reserved for this plan.**
- [ ] `db/queries/user_audit_events.sql` + `make codegen`: insert-event, list-by-user (paginated, newest-first).
- [ ] `internal/identity/` `AuditRecorder.Record(ctx, userID, eventType, detail)`: load the user's DEK, envelope-encrypt `detail` via the shipped `Encryptor`, insert the row.
- [ ] Define the closed `event_type` taxonomy (`auth.login`, `token.issued`, `token.refreshed`, `token.revoked`, + consent events aligned with `consent-ledger`).
- [ ] Wire emission at call sites (login, token issue/refresh/revoke, consent grant/revoke); emission is **best-effort / non-blocking** — an audit-write failure logs + meters but never breaks the auth/token flow.
- [ ] `internal/mgmtapi/` user endpoint: list **the caller's own** events, decrypting `payload` under the caller's DEK; paginated.
- [ ] Strict ownership: a user can only read their own trail; there is **no operator plaintext read path** (operator sees only `user_id`/`event_type`/timestamp).
- [ ] Tests: recording an event encrypts the payload (raw column is ciphertext, not plaintext); the owning user reads back the decrypted detail; a different user cannot read it; best-effort emission failure does not break the parent flow.
- [ ] Tests (crypto-shred, §11.6): after `users.dek_wrapped` is destroyed, the user's audit payloads are permanently unrecoverable (mirror the envelope crypto-shred test).
- [ ] Tests (privacy): operator-level table read exposes no event detail (only coarse `event_type` + timestamp); no cross-user leakage.
- [ ] Author & verify paired OpenSpec change: `openspec validate user-audit-trail --strict`
- [ ] Reconcile & promote: `@plan promote user-audit-trail`

## Risks & open questions

- **Migration-number collision** — **0013 is reserved**; consent-ledger holds
  0011 and dynamic-client-registration 0012. Parallel plans must not reuse
  these prefixes.
- **`event_type` in the clear vs encrypted** — keeping the coarse type
  unencrypted enables filtering/pagination but reveals *that* an event of a
  category occurred to the operator. Default: encrypt the *detail*, keep the
  coarse type clear; revisit if the type itself is deemed sensitive.
- **Hot-path emission cost** — encrypting an event on every login/token op adds
  a DEK-unwrap + AEAD-encrypt. Emission must be best-effort and, where it sits
  on the hot path, asynchronous / non-blocking so it never regresses the
  stateless verification SLA (§4.1, §6.1).
- **DEK availability at read** — reading the trail requires unwrapping the
  user's DEK (regional KMS once `kms-provider-integration` lands); a KMS outage
  makes the trail temporarily unreadable (acceptable — cold path, fails closed).
- **Retention** — how long events are retained (and whether the user can prune
  their own trail) is a product question; default is retain-until-erasure.

## Definition of done

`go build/vet/test ./...` green; `user_audit_events` (migration 0013) present
with an envelope-encrypted payload; auth/consent/token/revocation events are
recorded (best-effort, non-blocking) encrypted under the user's DEK; the owning
user can list their decrypted trail via harbor-mgmt while the operator sees no
plaintext detail; destroying the user's wrapped DEK renders the trail
unrecoverable (crypto-shred test passes); no cross-user leakage; `make
agent-check` clean. Ready to `@plan promote`.
