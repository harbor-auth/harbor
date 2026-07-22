# Design: Compliance export & erasure (DSAR)

## Key Decisions

### Decision 1: Erase by crypto-shred, not row-delete
**Chosen:** Erasure destroys the user's wrapped DEK (`users.dek_wrapped`); every
envelope-encrypted record for that user becomes permanently unrecoverable at
once.
**Rationale:** A per-table row-delete sweep can miss a table, a backup, or a
derived copy — and can't *prove* the data is gone. Destroying the single key
that decrypts the user's PII makes erasure atomic and cryptographically
provable: without the DEK, the ciphertext is noise. This is exactly what §11.6
designs the DEK for.
**Alternatives considered:** Row-delete every user table (rejected — miss-prone,
unprovable, races with writes); tombstone + async purge (rejected — leaves a
recoverable window and more moving parts than key destruction).

### Decision 2: Strictly caller-scoped export, no operator plaintext path
**Chosen:** The export bundle is assembled by decrypting **only** under the
caller's DEK; there is no operator or cross-user read path.
**Rationale:** DSAR export is a user right, not an operator capability. Any code
path that could assemble another user's plaintext — or let an operator read a
user's export — would reintroduce exactly the operator-omniscience Harbor's
crypto model exists to prevent.
**Alternatives considered:** An operator "export on behalf of" tool (rejected —
operator plaintext path); a shared service DEK (rejected — defeats per-user
isolation and crypto-shred).

### Decision 3: The export bundle is region-pinned, DEK-encrypted, and short-lived
**Chosen:** The assembled bundle is region-pinned and short-lived; it is never
cached cross-region or retained after delivery. The bundle itself is a complete
copy of the user's PII, so it MUST be encrypted under the **caller's own DEK**
with a short TTL — there is no operator-readable plaintext bundle at rest.
Because the bundle is DEK-encrypted, a later crypto-shred (Decision 1) that
destroys the user's wrapped DEK renders an un-downloaded bundle permanently
unrecoverable.
**Rationale:** The bundle is the most sensitive artefact in the system. If it
lingered (or crossed a region), it would be a second copy of everything
crypto-shred is meant to be able to destroy, and a §5 residency breach.
Encrypting it under the user's DEK ties its lifetime to the same key that
erasure destroys, so it cannot outlive an erase and is never operator-readable.
**Alternatives considered:** Durable, resumable export downloads (rejected — a
standing PII store); email the bundle (rejected — sends PII out of region and
out of the user's control); operator-readable plaintext bundle at rest (rejected
— reintroduces an operator plaintext path and survives a later crypto-shred).

### Decision 4: Erasure is irreversible and audited
**Chosen:** Erasure is a one-way operation; the erase decision is recorded in
the user's audit trail (`compliance.erase_*`).
**Rationale:** "Right to be forgotten" means the data cannot come back; an
irreversible crypto-shred delivers that. Auditing the *decision* (not the erased
data) preserves accountability and surfaces the legal-hold-vs-erase tension
without retaining any erased PII.
**Alternatives considered:** Soft-erase with an undo window (rejected —
contradicts irreversibility and leaves recoverable PII); no audit (rejected —
loses accountability for a destructive, compliance-critical action).

### Decision 5: The crypto-shred survival set contains no recoverable PII
**Chosen:** Whatever **survives** an erase MUST contain no recoverable PII.
Concretely: recovery `code_hash` rows (derived from user secrets) are deleted on
erase; audit-trail rows keyed by a **pseudonymous** `user_id` may survive as
pseudonymous references, but any free-text / PII fields on them are
envelope-encrypted under the user DEK so they shred with it; consent-ledger rows
survive only as pseudonymous references (no plaintext PII).
**Rationale:** Crypto-shred is only as complete as its survival set is clean. If
a surviving table held plaintext PII (or a hash derived directly from a user
secret), erasure would be incomplete and the "right to be forgotten" promise
would break. Enumerating and constraining the survival set makes the guarantee
checkable.
**Alternatives considered:** Assume DEK destruction alone suffices (rejected —
rows not encrypted under the DEK, e.g. `code_hash`, would survive readable);
retain audit free-text for debugging (rejected — that free-text is exactly the
PII erasure must destroy).

## Interface sketch

```go
package identity

// ExportBundle assembles the caller's OWN decrypted data (profile, grants,
// audit events, relay mappings). It decrypts only under the caller's DEK and
// has no operator/cross-user path.
func ExportBundle(ctx context.Context, caller UserID) (Bundle, error)

// Erase crypto-shreds the user by destroying users.dek_wrapped, rendering all
// their envelope-encrypted PII permanently unrecoverable. Irreversible; audited.
func Erase(ctx context.Context, caller UserID) error
```

## Security & privacy invariants

- Export decrypts only under the caller's DEK; no operator or cross-user
  plaintext path (Decision 2).
- The export bundle is region-pinned, encrypted under the caller's DEK, and
  short-lived; never cross-region cached or retained, and an un-downloaded
  bundle dies with a later crypto-shred (Decision 3).
- The crypto-shred survival set contains no recoverable PII: recovery
  `code_hash` rows are deleted on erase, and surviving audit/consent rows carry
  only a pseudonymous `user_id` with any free-text envelope-encrypted under the
  user DEK (Decision 5).
- Erase destroys the DEK, making the user's envelope-encrypted PII permanently,
  provably unrecoverable; a prior export cannot re-hydrate it (Decision 1).
- Erasure is irreversible and the decision is audited without retaining erased
  PII (Decision 4).
