# Design: User audit trail (user-owned, envelope-encrypted, crypto-shredded)

## Key Decisions

### Decision 1: Encrypt each event payload under the user's DEK
**Chosen:** Store the event detail in an envelope-encrypted `payload` column,
encrypted under the **user's DEK** via the shipped `Encryptor`; keep only a
coarse `event_type` + timestamp in the clear.
**Rationale:** This is the single decision that delivers both pillar properties:
the operator cannot mine event detail for behavioural tracking (they see only
`user_id`/`event_type`/timestamp), and the trail is crypto-shreddable with the
user (Decision 4). It reuses the shipped envelope primitive rather than
inventing new crypto.
**Alternatives considered:** A plaintext audit log (rejected — hands the operator
exactly the tracking capability Harbor denies, and survives crypto-shred);
encrypt under a global/audit key (rejected — a global key can't be
crypto-shredded per-user, so erasure never reaches the trail).

### Decision 2: Closed event taxonomy aligned with consent-ledger
**Chosen:** A closed set of `event_type`s — `auth.login`, `token.issued`,
`token.refreshed`, `token.revoked` plus the `consent.*` events emitted by
`consent-ledger`.
**Rationale:** A closed set keeps the trail queryable/paginatable on the coarse
type without leaking detail, and aligning with the consent-ledger seam avoids a
taxonomy fork between the two changes.
**Alternatives considered:** Free-form event strings (rejected — unbounded,
un-auditable, and reveal more in the clear); a separate consent-only trail
(rejected — the user wants one unified history).

### Decision 3: Best-effort, non-blocking emission on the hot path
**Chosen:** `AuditRecorder` emission is best-effort — a write failure logs +
meters but never breaks the auth/token flow — and, where it sits on the hot
path, is asynchronous / non-blocking.
**Rationale:** An audit-trail write must never regress the stateless
verification SLA (§4.1, §6.1) or fail a login. Correctness of authentication
outweighs completeness of the trail for a single dropped event (which is logged
and metered).
**Alternatives considered:** Synchronous, must-succeed emission (rejected —
an audit-store hiccup would break authentication); fire-and-forget with no
logging/metric (rejected — silent loss is un-observable).

### Decision 4: Crypto-shred reaches the trail via the user's DEK
**Chosen:** The trail relies on the shipped crypto-shred erasure (§11.6):
because every payload is encrypted under the user's DEK, destroying
`users.dek_wrapped` already renders the whole trail unrecoverable, with a test
proving it.
**Rationale:** Erasure must reach the audit trail even in immutable backups; a
key-destruction model achieves that without deleting rows from append-only
stores. Reusing the existing crypto-shred path means no second erasure mechanism.
**Alternatives considered:** Row deletion on erasure (rejected — can't reach
immutable backups); a separate audit-key shredding scheme (rejected —
duplicates the DEK lifecycle for no benefit).

### Decision 5: User-only read path — no operator plaintext access
**Chosen:** Only the owning user can read their decrypted trail (via a
user-authenticated `harbor-mgmt` endpoint that decrypts under the caller's DEK);
there is no operator plaintext read path.
**Rationale:** "User-owned" is meaningful only if the operator cannot read the
detail. Enforcing decryption under the caller's own DEK makes operator plaintext
access structurally impossible, not merely policy-gated.
**Alternatives considered:** An operator/admin read path "for support" (rejected
— reintroduces the tracking capability); decrypt server-side with an operator
key (rejected — same problem, and breaks crypto-shred).
