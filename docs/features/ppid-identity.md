---
title: Pairwise Pseudonymous Identifiers (PPID)
status: implemented
design_refs: [§3.2, §2.2, §1.7]
code:  [internal/identity/]
spec:  []
tests: [internal/identity/]
depends_on: []
plan: null
last_reconciled: 2026-07-08
---

# Pairwise Pseudonymous Identifiers (PPID)

## Summary

The PPID is the anti-tracking core of Harbor (docs/DESIGN.md §3.2): a stable,
opaque OIDC `sub` derived per `(user, RP-sector)` pair so that two RPs see
*unrelated* subjects for the same user and cannot correlate identities across
services. `internal/identity` holds the derivation as a **pure, deterministic**
function (no I/O), exactly the design §1.7 favours for security-critical logic —
it is exhaustively unit-testable without mocks.

## Behavior (as-built)

`DerivePPID(userPairwiseSecret, sectorIdentifier, userID)` computes:

```
ppid = Base64URL( HMAC-SHA256( key = user_pairwise_secret,
                               msg = len8(sector) || sector || user_id ) )
```

- **Keyed one-way:** the per-user secret is the HMAC *key* (not a message
  input), so a `sub` cannot be computed or reversed without it.
- **Deterministic:** the same inputs always yield the same `sub`, so logins are
  stable without storing a row per `(user, RP)` up front.
- **Injective message encoding:** the sector is length-prefixed with a fixed
  8-byte big-endian length before the user id, so distinct pairs can never
  collide (e.g. `("a","bc")` ≠ `("ab","c")`). A naive `sector || userID`
  concatenation would let one RP predict another RP's `sub`.
- **Base64url, no padding** (`base64.RawURLEncoding`).
- **Input guards (defense-in-depth on the hot path):** empty secret/sector/userID
  are rejected (`ErrEmptySecret`, `ErrEmptySector`, `ErrEmptyUserID`); each input
  is length-bounded (`MaxSecretLen=1024`, `MaxSectorLen=2048`, `MaxUserIDLen=256`)
  so a pathologically large attacker-influenced input can't turn HMAC into a DoS
  vector (`ErrSecretTooLong`, `ErrSectorTooLong`, `ErrUserIDTooLong`).

## Interfaces / Endpoints

Exported Go surface (no HTTP — this is a pure library used at token issuance):

- `func DerivePPID(userPairwiseSecret []byte, sectorIdentifier, userID string) (string, error)`
- Bounds: `MaxSecretLen`, `MaxSectorLen`, `MaxUserIDLen`.
- Errors: `ErrEmptySecret`, `ErrEmptySector`, `ErrEmptyUserID`, `ErrSecretTooLong`,
  `ErrSectorTooLong`, `ErrUserIDTooLong`.

## Code map

| Path | Role |
|---|---|
| `internal/identity/ppid.go` | `DerivePPID` + the injective `encodeMessage` helper, input-length guards, and the bound/error constants. |

## Security & privacy invariants

- **No global correlation secret (§3.2.1):** the HMAC key is *per user*, so a key
  compromise deanonymizes one user, never the whole population — unlike a global
  salt/pepper scheme.
- **Non-correlating across RPs (§2.4, §3.2.4):** different sectors yield unrelated
  `sub`s; RPs cannot join a user across services.
- **One-way (§2.2):** a leaked `sub` reveals nothing about the user or their
  `sub` at any other RP.
- **Injective encoding (§3.2.1):** the fixed-width length prefix guarantees no two
  distinct `(sector, user)` pairs encode to the same HMAC message.

## Tests

`internal/identity/ppid_test.go` pins a golden known-answer vector (locks the
derivation against silent change) and covers determinism, cross-sector
non-correlation, the injectivity property, and every input guard (empty and
over-length).

## Known gaps / TODOs

- The `user_pairwise_secret` lifecycle — generation at signup, envelope
  encryption under the regional KEK, and region-local storage (§3.2.3, §4.4) —
  lives outside this package and is not yet implemented.
- Materialization of `pairwise_sub` into the `grants` table for cheap hot-path
  lookup / reverse lookup (§3.2.3, §10) is pending the data layer.
