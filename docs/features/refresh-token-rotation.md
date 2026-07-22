---
title: Refresh Token Rotation (opaque, rotating, one-time-use)
status: implemented
design_refs: [§3.5, §10, §11.7]
code:  [internal/oidc/, internal/clients/, cmd/harbor-hot/]
spec:  [api/openapi/harbor.yaml]
tests: [internal/oidc/, internal/clients/, internal/oidcapi/]
depends_on: [real-token-issuance, session-ppid-seam]
plan: refresh-token-rotation
last_reconciled: 2026-07-20
---

# Refresh Token Rotation (opaque, rotating, one-time-use)

## Summary

Harbor issues **opaque, server-side, one-time-use refresh tokens** and rotates
them on every use, implementing §3.5's universal rule — *the long-lived
credential must be opaque and server-side, never a JWT*. On the `/token` code
exchange (when `offline_access` is granted) the service mints a CSPRNG token and
stores **only its SHA-256 hash** in the `sessions` table; on
`grant_type=refresh_token` it atomically revokes the old session and creates a
new one, minting fresh access/ID tokens. Presenting an already-revoked token
fires the §11.7 **theft signal** — the whole session family for that user↔RP
pairing is revoked. This makes "log out everywhere" / "remove app" (§11.3) and
theft-detection-by-rotation real.

## Behavior (as-built)

**Opaque token (`oidc.refresh`)** — a refresh token is 32 bytes (256 bits) of
CSPRNG entropy, base64url-encoded, returned to the client **exactly once**. Only
`sha256(plaintext)` is stored (`RefreshSession.TokenHash`); the plaintext is
never persisted (§7.4). Default TTL is 14 days (§3.5).

**Session record (`oidc.RefreshSession`)** — carries `ID`, `Region`, `UserID`,
`GrantID` (FK to the consent grant, migration `0007`), `ClientID`,
`DeviceLabel`, `TokenHash`, `ExpiresAt`, `RevokedAt`, plus `AuthTime`/`ACR`/`AMR`
for OIDC Core §2 claim continuity across rotation.

**Rotation (`SessionStore.RotateSession`)** — on `grant_type=refresh_token`:
hash the presented token, `GetSessionByTokenHash`, then **atomically** revoke
the old row and insert the new one in a single DB transaction
(`clients.DBSessionStore` uses a `txBeginner`), closing the crash window that a
separate revoke+create would open. A fresh access/ID token + new refresh token
are minted.

**Reuse / theft detection (§11.7)** — the store distinguishes
`ErrRefreshTokenNotFound` (unknown/expired) from `ErrRefreshTokenRevoked` (hash
found but already revoked). A revoked-token presentation is treated as theft:
`RevokeSessionsByUserClient` revokes the entire session family for that user↔RP
pairing and the exchange returns `invalid_grant`. NULL `expires_at` fails closed
(never treated as non-expiring). Additional store methods support §11.3
per-app disconnect (`RevokeSessionsByGrant`) and future global logout
(`RevokeSessionsByUser`).

> **Accepted TOCTOU (documented, not fixed):** two concurrent `Refresh()` calls
> with the same valid token can both pass the lookup before either rotates,
> yielding two successor sessions. This is a bounded race window; eliminating it
> would require `SELECT … FOR UPDATE`/optimistic locking on the session row.

**Contract** — `api/openapi/harbor.yaml` allows `grant_type=refresh_token` and
adds `refresh_token` to the token response (regenerated stubs in
`internal/gen/openapi`). All stores are per-region (§5), so rotation never
crosses a jurisdiction.

## Interfaces / Endpoints

- `POST /token` now routes `grant_type=refresh_token` (in addition to
  `authorization_code`) and returns a `refresh_token` when `offline_access` is
  granted.
- Exported Go surface:
  - `oidc.RefreshSession`, `oidc.SessionStore` (Create/GetByTokenHash/Revoke/Rotate/family-revoke).
  - `oidc.ErrRefreshTokenNotFound`, `oidc.ErrRefreshTokenRevoked`.
  - `clients.DBSessionStore` (sqlc-backed, transactional rotation) + in-memory stub.

## Code map

| Path | Role |
|---|---|
| `internal/oidc/refresh.go` | Opaque-token mint/hash, `RefreshSession`, `SessionStore` seam, rotation + reuse-detection logic. |
| `internal/oidc/token.go` | `/token` routing for `grant_type=refresh_token`. |
| `internal/clients/sessions.go` | `DBSessionStore` over `sessions.sql`; atomic `RotateSession` via a pgx transaction. |
| `db/queries/sessions.sql` | Session queries (create/get-by-hash/revoke/family-revoke). |
| `api/openapi/harbor.yaml` | Adds `refresh_token` grant + response field (regen `internal/gen/openapi`). |
| `cmd/harbor-hot/main.go` | Wires the `SessionStore` into the service. |

## Security & privacy invariants

- **Hash-at-rest (§7.4)** — `INV-REFRESH-HASH-AT-REST`: only `sha256(plaintext)`
  is stored; a DB compromise leaks the hash, not a presentable token.
- **Hash-lookup, not hash-as-token (§7.4)** — `INV-REFRESH-HASH-LOOKUP`:
  presenting the stored hash as a token misses the lookup (`invalid_grant`); DB
  read access does not enable replay.
- **Expiry hard-enforced (§3.5)** — `INV-REFRESH-EXPIRY-ENFORCED`: expired (and
  NULL-expiry) tokens are rejected as `invalid_grant` at both service and HTTP
  layers.
- **Rotation invalidates the old token (§3.5, §11.7)** —
  `INV-REFRESH-ROTATION-INVALIDATES-OLD`: a rotated token is immediately
  tombstoned; replay fires the theft signal + family revoke.

## Tests

- `internal/oidc/refresh_test.go` — mint/hash round-trip; rotation returns a
  *new* token and invalidates the old; replaying a rotated token ⇒ theft signal
  + family revoke; expired/revoked ⇒ `invalid_grant`; the four `INV-REFRESH-*`
  invariant tests.
- `internal/clients/sessions_test.go` — sqlc-backed store: get-by-hash,
  transactional `RotateSession` atomicity, family-revoke by user↔client and by
  grant, region populated.
- `internal/oidcapi/` — `/token` `grant_type=refresh_token` wire behavior incl.
  expired-token rejection.

## Known gaps / TODOs

- **Concurrent-rotation TOCTOU** is accepted and documented (see above), not yet
  closed with row-level locking.
- **Global "sign out everywhere"** (`RevokeSessionsByUser`) is wired in the store
  but not yet exposed as a user-facing endpoint.
- Refresh tokens are only issued when `offline_access` is consented — gated on
  the grant recorded by [session-ppid-seam](session-ppid-seam.md).
