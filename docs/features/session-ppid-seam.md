---
title: Session Seam — login → PPID → token subject
status: implemented
design_refs: [§3.2, §11.2]
code:  [internal/oidc/, internal/clients/, cmd/harbor-hot/]
spec:  []
tests: [internal/oidc/, internal/clients/]
depends_on: [ppid-identity, client-grant-persistence, real-token-issuance]
plan: session-ppid-seam
last_reconciled: 2026-07-20
---

# Session Seam — login → PPID → token subject

## Summary

Harbor resolves the **per-RP pairwise subject (`sub`)** on the hot path by
running the real §11.2 login→PPID→consent step, replacing the
`stubSessionResolver` that auto-approved a fixed `demo-subject-ppid`. The new
`oidc.PPIDSessionResolver` authenticates the user (via an `AuthSource` over the
BFF session — never a client-supplied value), loads and decrypts the user's
`pairwise_secret` (`oidc.UserSecretLoader` → `clients.DBSecretLoader`), looks up
the RP's `sector_id`, and derives-or-reads the PPID that flows into the token's
`sub` claim. This is the seam that finally connects authentication to the OIDC
flow so a real, unlinkable per-RP subject (§3.2) reaches the issued token — and
it is **wired live** in `cmd/harbor-hot/main.go`.

## Behavior (as-built)

**AuthSource seam (`oidc.AuthSource`)** — `AuthenticatedUserID(ctx) (string, error)`
reads the signed-in subject from the BFF session (WebAuthn login already
complete), never from a request parameter. Keeping it an interface keeps
`internal/oidc` free of `internal/webauthn` (enforced by the arch test).
`oidc.FixedAuthSource` is a **DEV-ONLY scaffold** used in `harbor-hot` until the
BFF-session-backed source lands.

**Secret loading (`oidc.UserSecretLoader` → `clients.DBSecretLoader`)** — loads
`UserSecret{Region, Secret}` for a user. The DB-backed loader unwraps the user's
DEK under the regional KEK, then AES-256-GCM-decrypts `users.pairwise_secret`
with the user-bound AAD (§4.4). The plaintext secret is held **only transiently**
during resolution — never persisted, never logged (§6.5.7) — and any failure is
fail-closed (`ErrUserSecretNotFound` is distinct from a decrypt failure so the
caller can respond without leaking which failed). An `InMemorySecretLoader` (which
defensively clones the secret slice) exists for dev/test.

**Resolution (`oidc.PPIDSessionResolver.Resolve`)** — for the authenticated
user + requested `Client`:

1. **Returning user (grant found via `GrantStore.FindGrant`):** read
   `grant.PairwiseSub` directly — no PPID re-derivation (§3.2.3, the
   materialized `pairwise_sub` is the cheap hot-path source of truth).
2. **First consent (no grant):** derive `sub = DerivePPID(pairwise_secret,
   sector_id, user_id)` (§3.2) and record the new grant via
   `GrantStore.CreateGrant`, storing the `pairwise_sub`.

The resolver **fails closed** — it never falls back to a raw `user_id` as `sub`
on any error, because leaking `user_id` would break cross-RP unlinkability.

**Wiring** — `cmd/harbor-hot/main.go` constructs
`oidc.NewPPIDSessionResolver(PPIDSessionResolverConfig{Auth, Loader, Grants})`
and passes it as the service's `Sessions`. The lingering `stubSessionResolver`
remains in `internal/oidc/service.go` as a **test-only** scaffold and is no
longer on the hot path.

## Interfaces / Endpoints

- No new HTTP endpoints — the `/authorize` → code → `/token` path is unchanged;
  the resolved PPID flows through it into the token `sub`.
- Exported Go surface:
  - `oidc.AuthSource` + `oidc.NewFixedAuthSource(userID)` (DEV-ONLY).
  - `oidc.UserSecret`, `oidc.UserSecretLoader`, `oidc.NewInMemorySecretLoader()`, `oidc.ErrUserSecretNotFound`.
  - `oidc.NewPPIDSessionResolver(oidc.PPIDSessionResolverConfig{Auth, Loader, Grants})`.
  - `clients.DBSecretLoader` (implements `oidc.UserSecretLoader`).

## Code map

| Path | Role |
|---|---|
| `internal/oidc/resolver.go` | `AuthSource`, `UserSecretLoader`, `InMemorySecretLoader`, and `PPIDSessionResolver` (login → PPID → consent). |
| `internal/clients/secretloader.go` | `DBSecretLoader` — unwrap DEK + decrypt `pairwise_secret` (fail-closed, never logged). |
| `internal/identity/ppid.go` | `DerivePPID` (reused unchanged) — the HMAC-based pairwise derivation. |
| `internal/oidc/service.go` | Retains the test-only `stubSessionResolver` scaffold (off the hot path). |
| `cmd/harbor-hot/main.go` | Wires the real `PPIDSessionResolver` into the service (`Sessions`). |

## Security & privacy invariants

- **Stable per-RP subject (§3.2.3)** — `INV-SESSION-PPID-STABLE`: after first
  consent the grant's frozen `pairwise_sub` is returned on every subsequent
  `Resolve` (same user + same RP ⇒ same `sub`).
- **Cross-RP unlinkability (§3.2)** — `INV-SESSION-PPID-UNLINKABLE`: different
  `sector_id`s yield unrelated `sub`s for the same user; RPs cannot correlate.
- **Never leak the raw user_id (§11.7)** — `INV-SESSION-PPID-NO-RAW-UID`: the
  resolver fails closed and never emits `user_id` as `sub`.
- **`pairwise_secret` is transient (§6.5.7)** — decrypted only in memory for the
  duration of resolution; never persisted, never logged.

## Tests

- `internal/oidc/resolver_test.go` — same user + same RP ⇒ stable `sub`
  (`INV-SESSION-PPID-STABLE`); same user + different sector ⇒ different `sub`
  (`INV-SESSION-PPID-UNLINKABLE`); fail-closed on load/derive error, no raw uid
  (`INV-SESSION-PPID-NO-RAW-UID`); grant recorded once; `pairwise_secret` absent
  from any output.
- `internal/clients/secretloader_test.go` — DEK unwrap + GCM decrypt round-trip
  with the user-bound AAD; wrong-user AAD fails authentication; not-found vs
  decrypt-failure distinction.

## Known gaps / TODOs

- **`FixedAuthSource` is a SCAFFOLD** — `harbor-hot` authenticates as a fixed
  dev user; the real BFF-session-backed `AuthSource` is delivered by
  [bff-session-middleware](../plans/bff-session-middleware.md).
- **Hosted login/consent UI (§11.2)** is a larger follow-up; v1 wires the
  resolver against a minimal/programmatic consent step. The PPID derivation +
  grant recording — the security-critical parts — are live now.
