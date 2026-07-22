# Design: User account recovery (fail-closed Phase 1)

## Key Decisions

### Decision 1: Recovery codes stored as salted hashes, single-use
**Chosen:** Generate single-use recovery codes; persist only a salted SHA-256
hash; show the plaintext to the user exactly once. Consuming a code is an atomic
"mark used only if unused" operation.
**Rationale:** Mirrors the shipped hash-at-rest posture for refresh tokens — the
operator (and a DB dump) never yields a usable code, and single-use prevents
replay. This is the minimum-trust way to store an out-of-band secret.
**Alternatives considered:** Reversibly-encrypted codes (rejected — an operator
with the KEK could recover usable codes); plaintext codes (rejected —
catastrophic on a DB leak); multi-use codes (rejected — a leaked code is a
standing bypass).

### Decision 2: Recovery re-authenticates but keeps the account fail-closed
**Chosen:** A successful code/fallback recovery re-establishes a session but the
account remains `recovery_required` until the user enrolls a **fresh passkey**;
only then is the guard cleared.
**Rationale:** Recovery is the prime attack surface. Granting a fully-privileged
session off a single recovery secret would make code theft equivalent to full
account takeover. Requiring a fresh strong factor before clearing the guard
bounds the blast radius of a stolen code.
**Alternatives considered:** Fully re-privilege on code entry (rejected — code
theft == takeover); require an operator to approve (rejected — reintroduces an
operator backdoor).

### Decision 3: Fallback authenticators are just additional registered credentials
**Chosen:** Multiple passkeys and a hardware key are independent recovery
factors registered through the shipped WebAuthn path — no bespoke factor store.
**Rationale:** Reuses a hardened, audited registration path; the strongest
recovery is another strong authenticator, not a shared secret. Encouraging a
second passkey is the best real-world recovery UX.
**Alternatives considered:** A separate recovery-only credential type (rejected —
duplicates the WebAuthn store with weaker scrutiny).

### Decision 4: Defer social / M-of-N recovery
**Chosen:** Phase 1 ships codes + fallback authenticators only; guardian/
trusted-contact/M-of-N recovery is a later wave.
**Rationale:** Social recovery has a materially larger threat model (collusion,
social engineering of guardians, guardian PII). Shipping the safe minimum first
delivers the recovery capability without the harder risk surface.
**Alternatives considered:** Ship social recovery now (rejected — scope + threat
model too large for a safe Phase 1).

## Interface sketch

```go
package identity

type RecoveryManager interface {
    // GenerateCodes returns freshly-minted plaintext codes ONCE and persists
    // only their salted hashes.
    GenerateCodes(ctx context.Context, userID UserID, n int) ([]string, error)
    // ConsumeCode atomically marks a matching unused code used; returns an
    // error (grants nothing) on no-match or already-used.
    ConsumeCode(ctx context.Context, userID UserID, code string) error
}
```

## Security & privacy invariants

- Recovery codes are stored only as salted hashes; plaintext is never persisted
  and is not operator-readable (Decision 1).
- Consume is atomic and single-use; replay is rejected (Decision 1).
- Recovery keeps the account `recovery_required` until a fresh passkey is
  enrolled (Decision 2).
- Recovery is rate-limited, region-pinned, metered aggregate-only, and audited;
  endpoints do not reveal user/code existence.
