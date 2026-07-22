# Proposal: Compliance export & erasure (DSAR)

## Problem

A privacy-first OP must honour **data-subject rights** (§11.5): a user has the
right to **export** all their data (access / portability) and to **erase** it
(right to be forgotten). Harbor holds each user's PII under a per-user
envelope-encryption DEK (§11.6), so erasure can be **provable** — destroy the
DEK and all envelope-encrypted PII is permanently unrecoverable — but there is
**no user-facing DSAR flow** to export or erase. Harbor therefore cannot satisfy
GDPR/CCPA today, and its strongest privacy property (crypto-shred erasure) is
unreachable by the users it protects.

## Proposed Solution

1. **EXPORT (access / portability)** — assemble the **caller's own decrypted**
   data (profile, consent grants, `user-audit-trail` events, relay mappings)
   into a portable bundle, decrypted only under the caller's DEK. Strictly
   caller-scoped, **no operator plaintext path**, no cross-user read.
2. **ERASE (right to be forgotten)** — **crypto-shred** by destroying the user's
   wrapped DEK (`users.dek_wrapped`); every envelope-encrypted record for that
   user becomes **permanently unrecoverable** at once, with no per-table
   row-delete sweep to miss a table. Erasure is **irreversible** and audited.
3. **Bundle handling** — the export bundle is itself PII: it is **region-pinned**
   and **short-lived**, never cached cross-region or retained after delivery.
4. **Guardrails** — export and erase are user-authenticated, region-pinned,
   metered **aggregate-only**, and emit `user-audit-trail` events.

## Non-Goals

- **No new table** — reads existing user-scoped stores; erases the existing DEK.
- **No operator-initiated export/erase** and **no operator plaintext path** to a
  user's data.
- **No row-delete erasure** — erasure is crypto-shred (destroy the DEK), not a
  per-table sweep.
- **Legal-hold policy** — hold vs erase adjudication is an operator concern
  layered above this mechanism; here we only record the erase decision in the
  audit trail.

## Success Criteria

- [ ] EXPORT returns **only the caller's own** decrypted data (no cross-user leak, no operator plaintext path).
- [ ] The export bundle is region-pinned and short-lived.
- [ ] ERASE crypto-shreds by destroying `users.dek_wrapped`; the user's envelope-encrypted PII becomes **permanently, provably unrecoverable**.
- [ ] A prior export bundle cannot re-hydrate erased data.
- [ ] Export and erase are region-pinned, metered aggregate-only, and audited.
- [ ] Erasure is irreversible (the destroyed DEK cannot be reconstructed).
- [ ] `make agent-check` clean.
