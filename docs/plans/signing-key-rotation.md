---
title: Signing key rotation (JWKS kid lifecycle — §7.3)
status: approved
design_refs: [§7.3, §3.5.4, §3.3]
targets: [internal/crypto/, cmd/harbor-hot/, cmd/harbor-mgmt/, api/openapi/harbor.yaml]
promoted_to: null
openspec: changes/signing-key-rotation
created: 2026-07-14
---

# Signing key rotation (plan)

> **Dependency order:** depends on **`real-token-issuance`** (signing keys only
> exist once `JWTIssuer` and `crypto.Signer` are in place). No other
> prerequisites — can land immediately after `real-token-issuance`. This is
> Phase 1 work (the "nuclear option" revocation tier described in §3.5.4
> requires rotating `kid` on key compromise; without rotation the emergency
> kill tier is incomplete).

## Problem

`real-token-issuance` introduces a `crypto.Signer` with a single in-process
or HSM-backed ECDSA key. That key has **no rotation lifecycle**. Two failure
modes are completely unmitigated today:

1. **Scheduled rotation** — cryptographic hygiene dictates rotating signing
   keys on a regular cadence (e.g. 90 days). Without a rotation mechanism,
   the same private key persists indefinitely.
2. **Emergency rotation** (§3.5.4, "nuclear option") — if the signing private
   key is compromised, the only way to immediately invalidate *all* tokens
   signed by that key is to rotate the `kid` in JWKS: any token carrying the
   old `kid` will fail signature verification at every RP instantly. Without a
   rotation path, a compromised key has no fast remediation — the attacker
   retains valid tokens until they expire.

There is currently no management API to trigger rotation, no `kid` overlap
window, and no mechanism to retire old public keys from JWKS.

## Proposed approach

### Key lifecycle model

```
active ──rotate──► pending (new key, published in JWKS but not yet signing)
                      │
                 grace period (RPs refresh JWKS cache)
                      │
                   active (new key signs all new tokens)
                      │
              overlap window (old key still in JWKS for in-flight tokens)
                      │
                   retired (old key removed from JWKS; old tokens with old kid rejected)
```

### Implementation

1. **`KeyProvider` multi-key support** — extend `internal/crypto/` to hold
   multiple `(kid, publicKey)` pairs in JWKS and exactly one `(kid, signer)`
   for signing new tokens. The JWKS response already serves an array — make
   the array truly multi-key rather than always length-1.

2. **Key generation / import** — a management command (or management API
   endpoint `POST /admin/keys/rotate`) triggers:
   - Generate (or import from HSM) a new ECDSA P-256 key, assign a new `kid`
     (UUID or timestamp-based, e.g. `k_<unix_ms>`).
   - Add the new public key to the JWKS immediately (pending state).
   - After a configurable grace period (default: 60 s, enough for RP JWKS
     cache refreshes), promote the new key to the active signer.
   - Keep the old public key in JWKS for an overlap window (default: JWT
     `exp` max-age, e.g. 15 min). Remove it once the window elapses.

3. **`/jwks.json` multi-key response** — already returns a `keys` array;
   confirm that `KeyProvider.PublicKeys()` returns all non-retired keys.

4. **State persistence** — in dev mode, key metadata is in-memory (reset on
   restart). In prod, key metadata (kid, creation time, state, public key
   bytes) is persisted in the DB (`signing_keys` table — new migration) so
   the overlap window survives replica restarts.

5. **Management endpoint** — `POST /admin/keys/rotate` (management API, not
   hot path) triggers the rotation. Returns the new `kid` and the scheduled
   promotion and retirement timestamps. Protected by admin auth.

6. **Audit** — every rotation event is emitted to `audit_events` with
   `event_type = "signing_key_rotated"`, `old_kid`, `new_kid`, and operator
   identity. Required for compliance and incident response.

### Emergency rotation (§3.5.4)

Emergency rotation is the same flow with `grace_period = 0s` and
`overlap_window = 0s`. This makes the old key disappear from JWKS
immediately — all in-flight tokens with the old `kid` are rejected by every
RP on their next verify call. The management endpoint accepts
`?emergency=true` to trigger this path. Document clearly that emergency
rotation is the last-resort nuclear option (causes a brief auth outage for
tokens signed with the old key).

## DESIGN alignment

Directly realizes §7.3 (signing key rotation with overlap, HSM seam) and
§3.5.4 (emergency `kid` rotation as the highest-tier revocation lever). Keeps
the JWKS endpoint contract from `real-token-issuance` stable (multi-key was
always the intended shape). No DESIGN changes needed.

## Target code paths

- `internal/crypto/key_provider.go` — multi-key `KeyProvider`, `PublicKeys()` returning all live keys
- `internal/crypto/rotation.go` — rotation state machine + overlap window logic
- `db/migrations/NNNN_signing_keys.up.sql` — `signing_keys` table (kid, state, public_key_bytes, created_at, promoted_at, retired_at)
- `db/queries/signing_keys.sql` — sqlc queries
- `internal/gen/db/` — regenerated sqlc output
- `cmd/harbor-mgmt/main.go` — register `POST /admin/keys/rotate`
- `internal/oidcapi/jwks.go` — serve multi-key JWKS (may already work)
- `api/openapi/harbor.yaml` — add `POST /admin/keys/rotate` + `SigningKeyRotateResponse`

## Implementation checklist

- [ ] `@openspec new signing-key-rotation` — draft the OpenAPI change
- [ ] Extend `KeyProvider` to hold multiple keys; `PublicKeys()` returns slice
- [ ] Add `signing_keys` migration + sqlc queries; regenerate
- [ ] Implement `internal/crypto/rotation.go` — promote/retire state machine
- [ ] `POST /admin/keys/rotate` handler; wire into mgmt server
- [ ] Audit event emission on every rotation
- [ ] Tests: scheduled rotation (promote after grace); emergency rotation (zero grace + zero overlap); JWKS serves both old and new key during overlap; old key absent after retirement; tokens signed by retired key rejected by RP verify
- [ ] Author & verify paired OpenSpec change: `openspec validate signing-key-rotation --strict`
- [ ] Reconcile & promote: `@plan promote signing-key-rotation`

## Risks & open questions

- **HSM key generation** — `real-token-issuance` documents the HSM seam; key
  rotation must work with both in-proc key generation (dev) and HSM-delegated
  generation (prod). The rotation API must accept both paths without leaking
  private key material in the dev case.
- **Multi-replica coordination** — all hot-path replicas must pick up the new
  active signer simultaneously (or within the grace period). Options: (a) pull
  from DB on every request (adds latency), (b) listen for a rotation event via
  Redis pub/sub (preferred), (c) poll DB on a short interval. Choose (c) for
  Phase 1 simplicity (poll every 10 s); (b) is the production target.
- **`kid` naming** — stable, collision-free `kid`s are essential. Use a
  cryptographic hash of the public key bytes (e.g. base64url of SHA-256
  truncated to 8 bytes). This is self-describing and survives key re-imports.

## Definition of done

`go build/vet/test ./...` green; `KeyProvider` returns all live public keys;
`POST /admin/keys/rotate` triggers promotion + retirement lifecycle; JWKS
serves both keys during overlap; tokens with a retired `kid` are rejected;
emergency rotation removes old key immediately; audit events emitted; migration
applied cleanly; `make agent-check` clean.
