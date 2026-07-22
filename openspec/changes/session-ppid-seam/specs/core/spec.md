# Spec: Session & PPID seam

Introduces the `SessionResolver` seam that turns an authenticated WebAuthn login into a pairwise subject (PPID) and a consent grant. Defines the resolver contract, the deterministic PPID derivation, and the unlinkability/fail-closed invariants that guarantee no token is ever emitted with a raw or fallback subject.

## ADDED Requirements

### Requirement: REQ-001 SessionResolver contract

The system SHALL provide a SessionResolver that resolves an authenticated session into a pairwise subject.

The system MUST provide a `SessionResolver` that resolves an authenticated session for a given client into a pairwise subject and an approval decision.

```go
package oidc

type SessionResolver interface {
    Resolve(ctx context.Context, client Client) (subject string, approved bool, err error)
}
```

The real resolver flow: WebAuthn login ceremony ⇒ authenticated `user_id` ⇒ `GrantStore.FindGrant(user_id, client_id)` ⇒ **if found**, return `grant.PairwiseSub` directly (§3.2.3 — no re-derivation on repeat login); **if new grant**, unwrap DEK + decrypt `pairwise_secret` ⇒ `ClientRegistry.sector_id` ⇒ `identity.DerivePPID(pairwise_secret, sector_id, user_id)` ⇒ `sub` ⇒ `GrantStore.CreateGrant` (persist `pairwise_sub`).

#### Scenario: Successful resolution returns a pairwise subject

**Given** a completed WebAuthn login and a client with a `sector_id`  
**When** `Resolve` runs the full flow  
**Then** it returns the pairwise `sub` (read from `grant.PairwiseSub` for returning users, or derived via `DerivePPID` and persisted for new grants) with `approved = true`

#### Scenario: WebAuthn login failure denies

**Given** a failed WebAuthn login ceremony  
**When** `Resolve` is called  
**Then** it denies and returns an error, emitting no subject

### Requirement: REQ-002 Deterministic PPID derivation

The system SHALL derive the subject deterministically as a pairwise identifier.

The subject MUST be derived deterministically as a pairwise identifier so the same user and sector always yields the same `sub`, while different sectors yield uncorrelatable subjects.

PPID derivation: `sub = B64URL(HMAC-SHA256(pairwise_secret, sector_id || user_id))`

> **Implementation note:** The `||` concatenation MUST use length-prefixed encoding — 8-byte big-endian `len(sector_id)`, then `sector_id` bytes, then `user_id` bytes — to make the encoding injective and prevent injection attacks where `("a", "bc")` and `("ab", "c")` would produce the same HMAC input. See `internal/identity/ppid.go`.

#### Scenario: Stability across logins

**Given** the same user and the same sector  
**When** the user logs in on separate occasions  
**Then** the derived `sub` is identical every time

#### Scenario: Unlinkability across sectors

**Given** the same user authenticating to two clients in different sectors  
**When** their subjects are derived  
**Then** the two `sub` values are uncorrelatable

### Requirement: REQ-003 Fail-closed subject emission

The system SHALL fail closed and never emit a raw or fallback subject.

Resolution MUST fail closed. `sub` is always a PPID and never the raw `user_id`. Any error MUST deny, and the system MUST NEVER emit a token with a fallback or raw subject. The `pairwise_secret` MUST never be logged or persisted in plaintext.

#### Scenario: DEK unwrap or secret decrypt failure denies

**Given** DEK unwrap or `pairwise_secret` decryption fails  
**When** `Resolve` is called  
**Then** it denies (fail closed) and never falls back to `user_id`

#### Scenario: Missing sector_id denies

**Given** a relying party with no `sector_id`  
**When** `Resolve` is called  
**Then** it denies and emits no subject

#### Scenario: Secret hygiene maintained

**Given** resolution is in progress  
**When** logs or persistence occur  
**Then** `pairwise_secret` is never written in plaintext

#### Scenario: GrantStore failure denies

**Given** `GrantStore.FindGrant` or `CreateGrant` returns a database error  
**When** `Resolve` is called  
**Then** it denies (fail closed) and no token is issued

### Requirement: REQ-004 Scoped consent enforcement

The system SHALL enforce scoped consent.

Consent grants MUST be scoped, and a user rejecting consent MUST result in `access_denied`.

#### Scenario: User rejects consent

**Given** an authenticated user prompted for consent  
**When** the user rejects consent  
**Then** the result is `access_denied` and no token is issued

#### Scenario: Existing grant covers requested scopes

**Given** an existing consent grant that covers all requested scopes  
**When** `Resolve` is called  
**Then** consent is not re-prompted and the existing `pairwise_sub` is returned

#### Scenario: New scopes requested triggers re-consent

**Given** an existing grant missing one or more requested scopes  
**When** `Resolve` is called  
**Then** the user is prompted for consent for the new scopes before proceeding
