---
title: Signing Key Rotation (JWKS kid lifecycle)
status: implemented
design_refs: [§7.3, §3.5, §3.3]
code:  [internal/crypto/, internal/clients/, internal/oidcapi/, cmd/harbor-hot/]
spec:  [api/openapi/harbor.yaml]
tests: [internal/crypto/, internal/clients/, internal/oidcapi/]
depends_on: [real-token-issuance]
plan: signing-key-rotation
last_reconciled: 2026-07-20
---

# Signing Key Rotation (JWKS kid lifecycle)

## Summary

Harbor's ES256 signing keys now have a full rotation lifecycle
(docs/DESIGN.md §7.3, §3.5.4). Keys move through **pending → active → retired**
with a grace period (so RPs can refresh their JWKS cache before a new key
signs) and an overlap window (so in-flight tokens signed by the outgoing key
still verify). `POST /admin/keys/rotate` triggers a rotation and returns the
computed schedule; an **emergency** mode collapses both windows to zero, making
a compromised `kid` disappear from JWKS immediately — the §3.5.4 "nuclear
option" that invalidates every token signed by that key at once. This completes
the emergency-kill tier that `real-token-issuance` left as a manual,
process-restart-only operation.

## Behavior (as-built)

**State machine (`crypto.RotationManager`)** — a **stateless, pure** computation
layer over key metadata and an injectable clock. It never performs I/O itself;
it decides *when* transitions are eligible and delegates the actual state
change to a `SigningKeyStateUpdater`. Core surface:

- `ShouldPromote(key)` — `now >= createdAt + GracePeriod` for a pending key.
- `ShouldRetire(key)` — `now >= promotedAt + OverlapWindow` for an active key.
- `ComputeSchedule(...)` → `RotationSchedule` (new kid, promote-at, old kid,
  retire-old-at, emergency flag).
- `Promote(...)` / `Retire(force)` — apply the transition via the updater;
  `force` skips the overlap check for emergency retirement.

Timing comes from `RotationConfig`: `DefaultRotationConfig()` is a 60 s grace
period + 15 min overlap; `EmergencyRotationConfig()` is `0/0`. Because the
manager is pure and clock-injectable, the whole lifecycle is unit-testable
without a database (§1.7).

**Key states (`crypto.KeyState`)** — `pending` / `active` / `retired`, with
`IsLive()` = pending ∨ active. Only live keys appear in JWKS; a retired `kid`
is removed, so tokens carrying it fail verification.

**Schema (`0008_signing_keys`)** — a `signing_keys` table storing `kid`, `state`,
DER-encoded `public_key_bytes`, envelope-wrapped `private_key_wrapped`,
`region`, and lifecycle timestamps. Two CHECK constraints make illegal states
unrepresentable at the DB level:

- `signing_keys_state_valid` — state ∈ {pending, active, retired}.
- `signing_keys_state_timestamps` — pending has no promoted/retired; active has
  promoted only; retired has both.

A **partial unique index** `idx_signing_keys_one_active ... WHERE state =
'active'` enforces **exactly one active key** at any time — the invariant that
there is a single signer. A second partial index serves the JWKS "all live
keys" query, and a region index supports multi-region deployments.

**Handler (`POST /admin/keys/rotate`)** — `Server.PostAdminKeysRotate` returns
`501 Not Implemented` when no rotator is wired, otherwise calls
`rotator.Rotate(RotateOptions{Emergency})` and maps the domain `RotateResult`
onto the generated `openapi.SigningKeyRotateResponse` (`new_kid`, `promoted_at`,
optional `old_kid`/`retired_at`, `is_emergency`). The `emergency` flag is
resolved by `parseEmergency`: the `?emergency=true` query parameter takes
precedence, falling back to an optional JSON body (capped at 4 KB via
`MaxBytesReader`; an empty body is valid and means scheduled rotation). Admin
authentication is enforced by middleware in front of the handler.

## Interfaces / Endpoints

- `POST /admin/keys/rotate` → `200` `SigningKeyRotateResponse`; `501` when
  rotation is not configured; `400` on a malformed body; `401` without admin
  auth; `500` on rotation failure.
- Exported Go surface:
  - `crypto.KeyState` (+ `IsValid`, `String`), `crypto.SigningKeyMetadata` (+ `IsLive`).
  - `crypto.RotationConfig`, `DefaultRotationConfig()`, `EmergencyRotationConfig()`.
  - `crypto.RotationManager` (`ShouldPromote`, `ShouldRetire`, `ComputeSchedule`,
    `Promote`, `Retire`, `WithClock`), `RotationSchedule`.
  - `crypto.MultiKeySigner` (`ActiveSigner`, `AllLiveJWKs`, `RotateTo`).
  - `crypto.SigningKeyStateUpdater` / `SigningKeyRecord` bridge interfaces + `ToMetadata`.
- Contract: `api/openapi/harbor.yaml` defines the `/admin/keys/rotate`
  operation and `SigningKeyRotate{Request,Response}` schemas.

## Code map

| Path | Role |
|---|---|
| `internal/crypto/rotation.go` | Pure rotation state machine: `KeyState`, `SigningKeyMetadata`, `RotationConfig`, `RotationManager`, `MultiKeySigner`. |
| `db/migrations/0008_signing_keys.{up,down}.sql` | `signing_keys` table; one-active partial unique index; state/timestamp CHECKs. |
| `db/queries/signing_keys.sql` | sqlc queries for the key lifecycle. |
| `internal/clients/signingkeys.go` | DB-backed signing-key store implementing the updater/record bridge. |
| `internal/oidcapi/admin_keys.go` | `POST /admin/keys/rotate` handler, `parseEmergency`, response mapping. |
| `api/openapi/harbor.yaml` | `/admin/keys/rotate` + `SigningKeyRotate{Request,Response}` schemas. |

## Security & privacy invariants

- **Exactly one active signing key** — enforced at the DB level by the
  `idx_signing_keys_one_active` partial unique index; the application cannot
  race two keys into the active state.
- **Illegal key states are unrepresentable** — the `state`/timestamp CHECK
  constraints reject any row that doesn't match a valid lifecycle stage.
- **Private key never leaves the boundary (§3.3, §7.3)** — only
  envelope-wrapped private key bytes are stored (`private_key_wrapped`, sealed
  by the regional KEK); `public_key_bytes` alone feeds JWKS.
- **Data sovereignty (§4.4)** — every signing key carries a `region`; keys
  belong to their jurisdiction.
- **Emergency rotation is deliberate (§3.5.4)** — zero grace + zero overlap
  drops the old `kid` immediately; documented as the last-resort nuclear option
  because it briefly breaks verification for still-valid tokens signed by the
  old key.
- **Bounded admin input (§6.5)** — the rotate body is capped at 4 KB so a
  flooded admin endpoint can't exhaust memory.

## Tests

- `internal/crypto/` — pending→active→retired transitions; grace-period and
  overlap-window boundary conditions via the injectable clock; emergency config
  (`0/0`) promotes/retires immediately; `ComputeSchedule` timestamps; `IsLive`;
  `ShouldPromote`/`ShouldRetire` guards for wrong-state keys.
- `internal/clients/signingkeys_test.go` — lifecycle persistence; `promoted_at`
  preserved when retiring; one-active constraint; concurrent access.
- `internal/oidcapi/` — `POST /admin/keys/rotate` success (scheduled and
  emergency), `501` when unconfigured, `400` on malformed body, query-param vs
  body precedence for the emergency flag, response field mapping.

## Known gaps / TODOs

- **Automated scheduling** — promotion/retirement transitions are computed by
  `RotationManager` but must be driven by a caller (scheduler/worker); a
  periodic reconcile loop that promotes/retires due keys across replicas is the
  production target (the plan proposes Redis pub/sub; a short DB poll is the
  Phase-1 fallback).
- **Multi-replica active-signer convergence** — all hot-path replicas must pick
  up a newly promoted active signer within the grace period; the pub/sub push
  is not yet wired.
- **HSM-backed generation** — key generation currently uses the in-process
  `crypto.LocalSigner` (DEV-ONLY); the HSM-delegated generation path (§7.3)
  remains a seam.

## As-built note

Signing-key metadata landed as migration `0008_signing_keys`. Merged to `main`
in PR #31.
