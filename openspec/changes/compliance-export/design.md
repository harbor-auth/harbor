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

### Decision 3: The export bundle is region-pinned and short-lived
**Chosen:** The assembled bundle is region-pinned and short-lived; it is never
cached cross-region or retained after delivery.
**Rationale:** The bundle is a complete copy of the user's PII — the most
sensitive artefact in the system. If it lingered (or crossed a region), it would
be a second copy of everything crypto-shred is meant to be able to destroy, and
a §5 residency breach.
**Alternatives considered:** Durable, resumable export downloads (rejected — a
standing PII store); email the bundle (rejected — sends PII out of region and
out of the user's control).

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
- The export bundle is region-pinned and short-lived; never cross-region cached
  or retained (Decision 3).
- Erase destroys the DEK, making the user's envelope-encrypted PII permanently,
  provably unrecoverable; a prior export cannot re-hydrate it (Decision 1).
- Erasure is irreversible and the decision is audited without retaining erased
  PII (Decision 4).
