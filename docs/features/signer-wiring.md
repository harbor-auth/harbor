---
title: Hot-Path Signer Wiring (KeyRotator + JWTIssuer in harbor-hot)
status: draft
design_refs: [§3.3, §3.5, §4.1, §7.3]
targets:
  - cmd/harbor-hot/main.go
  - internal/oidcapi/server.go
  - internal/oidcapi/jwks.go
  - internal/crypto/signingkeyprovider.go
  - internal/clients/signingkeys.go
promoted_to: null
openspec: null
created: 2026-07-22
depends_on: [signing-key-rotation, envelope-encryption-kms]
---

# Hot-Path Signer Wiring (plan)

## Problem

The `KeyRotator`, `MultiKeyProvider`, `JWTIssuer`, and `DBSigningKeyStore` are
all fully implemented and tested in isolation, but **none of them are wired into
`cmd/harbor-hot/main.go`**. As a result:

- `/token` issues placeholder scaffold tokens (`NewPlaceholderIssuer`), not
  real ES256-signed JWTs.
- `/jwks.json` serves an empty key set (no `cfg.Signers` supplied to
  `oidcapi.New`), so any RP attempting to verify tokens gets a 200 with
  `{"keys": []}`.
- `POST /admin/keys/rotate` returns `501 Not Implemented` because
  `oidcapi.Config.Rotator` is always nil.

This is the last scaffold wall between the existing crypto infrastructure and a
production-grade OIDC deployment.

## Proposed approach

Three phases, each independently shippable:

### Phase 1 — Static startup wiring (minimum viable)

Wire real JWT issuance and JWKS at process startup. No background goroutine;
rotation is manual via `POST /admin/keys/rotate` (already implemented).

**Startup sequence in `harbor-hot/main.go` when `DATABASE_URL` is set:**

1. **Build `KeyProvider`** — same `localKeyProvider` pattern used by
   `harbor-mgmt` for enrollment, keyed by `KEK_SECRET`. Fail-closed: refuse to
   start if `DATABASE_URL` is set but `KEK_SECRET` is missing (mirrors the
   `harbor-mgmt` guard for `HARBOR_KMS_SECRET`).

2. **Load live keys from DB** — call `clients.DBSigningKeyStore.ListLive()`
   to get all `pending` + `active` keys. If the result is empty, **auto-seed**:
   generate a `LocalSigner`, call `KeyRotator.Rotate()` to persist it directly
   to active state (emergency config = zero grace + zero overlap means it is
   promoted inline). Log a warning that auto-seeding occurred.

3. **Unwrap private keys** — for each live key, call
   `KeyProvider.UnwrapDEK(ctx, region, row.PrivateKeyWrapped)` (repurposing the
   DEK wrapping primitive for EC private key bytes — same AES-256-GCM envelope).
   Reconstruct the `*ecdsa.PrivateKey` via `x509.ParseECPrivateKey` (PKCS#8
   DER), then `crypto.NewSignerFromKey`.

4. **Build `MultiKeyProvider`** — pass the active signer + any pending/live
   signers as `pending ...Signer`.

5. **Wire `JWTIssuer`** — `oidc.NewJWTIssuer(JWTIssuerConfig{Signer:
   provider.ActiveSigner()})`. Pass to `oidc.ServiceConfig.Tokens`.

6. **Wire `oidcapi`** — populate `cfg.Signers = provider.AllSigners()` and
   `cfg.Rotator = keyRotator`.

**Dev / no-DB fallback** — when `DATABASE_URL` is absent, keep the current
`NewPlaceholderIssuer()` with a prominent startup warning. Do NOT silently
generate a LocalSigner against the live issuer URL.

### Phase 2 — Dynamic JWKS (live rotation without restart)

After Phase 1, `oidcapi.Server` caches `jwksBytes` at construction time from
`cfg.Signers`. A rotation (Promote / Retire) changes the live set but the
cached JWKS is stale until restart.

Fix: accept a `SigningKeyProvider` (the `MultiKeyProvider`) in `oidcapi.Config`
instead of (or in addition to) `[]crypto.Signer`. The `/jwks.json` handler
calls `provider.AllSigners()` on every request and rebuilds the JWKS inline
(the list is tiny — typically 1–2 keys; JSON marshal cost is negligible).
The `oidcapi.Server.PostAdminKeysRotate` already holds the rotator; after a
successful `Rotate/Promote/Retire` the provider is automatically updated
(the rotator calls `provider.SetActive/Add/Remove` inline).

No cache invalidation plumbing needed; the provider's RW-mutex ensures
consistent reads.

### Phase 3 — Background rotation scheduler

The rotator computes promotion and retirement times at `Rotate()` call time, but
nothing drives the follow-up `Promote(kid)` and `Retire(kid)` calls on schedule.
Add a lightweight `RotationScheduler` goroutine in `harbor-hot`:

```
for {
    sleep(pollInterval)          // default: 10s
    keys := store.ListLive()
    for _, key := range keys {
        if mgr.ShouldPromote(key.ToMetadata()) { rotator.Promote(ctx, key.Kid) }
        if mgr.ShouldRetire(key.ToMetadata())  { rotator.Retire(ctx, key.Kid) }
    }
}
```

Multi-replica safety: `Promote` and `Retire` update DB state; the
`idx_signing_keys_one_active` partial unique index makes the DB the arbiter —
whichever replica wins the race, the second gets a harmless unique-constraint
error (or no-op on an already-active key). The in-memory `MultiKeyProvider` on
each replica converges on the next poll.

For now **Redis pub/sub push is explicitly out of scope** (§7.3 notes it as a
future optimisation). The poll approach is sufficient for the single-replica
production deployment.

## DESIGN alignment

- **§3.3** — signing keys sourced from the regional store; private key bytes
  never exit the envelope-encryption boundary.
- **§3.5 / §3.5.4** — `KeyRotator` implements the pending→active→retired
  lifecycle; emergency rotation drops the old `kid` from JWKS immediately.
- **§4.1** — harbor-hot is the hot path; the only per-request cost is reading
  `provider.ActiveSigner()` under a RW lock (nanoseconds) and calling
  `signer.Sign()` (in-process EC; negligible).
- **§7.3** — private key material lives in the DB only in wrapped form
  (`private_key_wrapped`). In memory only transiently during the startup
  unwrap; the signer holds the `*ecdsa.PrivateKey` thereafter. The HSM path
  (Phase 1 uses LocalSigner; the `hsmSigner` scaffold replaces it in a future
  plan) keeps the key out of process memory entirely.

This plan does NOT change the DESIGN; it closes the wiring gap the design
already calls for.

## Target code paths

| File | Change |
|---|---|
| `cmd/harbor-hot/main.go` | Wire `KeyProvider`, `DBSigningKeyStore`, `MultiKeyProvider`, `JWTIssuer`, `KeyRotator`; auto-seed first key; fail-closed on missing `KEK_SECRET` |
| `internal/oidcapi/server.go` | Add `SigningKeyProvider` field to `Config`; make JWKS handler read from provider dynamically (Phase 2) |
| `internal/oidcapi/jwks.go` | Dynamic JWKS rebuild from `provider.AllSigners()` (Phase 2) |
| `internal/clients/signingkeys.go` | Implement `crypto.RotationStore` adapter so `KeyRotator` can use `DBSigningKeyStore` |
| `internal/crypto/signingkeyprovider.go` | No change needed — `MultiKeyProvider` is already complete |
| `internal/oidcapi/worker.go` (new) | `RotationScheduler` goroutine for Phase 3 |

## Implementation checklist

### Phase 1 — Static startup wiring

- [ ] Add `KEK_SECRET` env-var guard to `harbor-hot/main.go` (fatal when DB is
      set but secret is absent)
- [ ] Implement `clients.DBRotationStore` — adapter from `DBSigningKeyStore` to
      `crypto.RotationStore` (the `Create/ActiveKid/Promote/Retire` seam)
- [ ] Add `loadOrSeedSigners(ctx, store, kp, region)` helper: `ListLive()` →
      unwrap private keys → `NewSignerFromKey` → `NewMultiKeyProvider`; if
      empty, generate + seed via emergency `Rotate()`
- [ ] Wire `JWTIssuer`, `Signers`, `Rotator` in `harbor-hot/main.go` when pool
      is non-nil
- [ ] Integration test: start server against test DB, hit `/token`, verify JWT
      header/sig, fetch `/jwks.json`, verify kid matches

### Phase 2 — Dynamic JWKS

- [ ] Add `SigningKeyProvider SigningKeyProvider` to `oidcapi.Config`
- [ ] `oidcapi.New`: if `cfg.SigningKeyProvider != nil`, wire dynamic JWKS
      handler (call `provider.AllSigners()` per request); else keep current
      static-byte approach for zero-DB / test paths
- [ ] Test: rotate via `PostAdminKeysRotate`, verify `/jwks.json` reflects new
      kid without restart

### Phase 3 — Background scheduler

- [ ] `RotationScheduler` struct in `internal/oidcapi/worker.go` with
      `Start(ctx) error` (launches goroutine, returns on ctx cancel)
- [ ] Wire in `harbor-hot/main.go` when pool is non-nil; log each
      promote/retire event
- [ ] Test: use injected clock + fake store; verify ShouldPromote/Retire polling
      drives correct transitions

### Cross-cutting

- [ ] Tests: `go test ./cmd/harbor-hot/... ./internal/oidcapi/...` green
- [ ] Reconcile feature docs: update `signing-key-rotation.md` "Known gaps" as
      each phase lands; promote this plan on Phase 3 completion

## Risks & open questions

1. **Private-key serialisation format** — `signing_keys.private_key_wrapped`
   stores EC key bytes after envelope-encryption. We must fix the encoding
   (PKCS#8 DER via `x509.MarshalPKCS8PrivateKey`) at key-generation time
   (Phase 1) and use `x509.ParsePKCS8PrivateKey` at load time. The format must
   be documented in a comment alongside `DBSigningKeyStore.Create` so future
   implementers do not assume raw key bytes.

2. **KEK_SECRET sharing policy** *(resolved)* — `harbor-hot` reuses the same
   `KEK_SECRET` already plumbed in `harbor-hot-secrets`. It does NOT call
   `WrapDEK`/`UnwrapDEK` directly (those are typed to the 32-byte `DEK` struct
   and use info string `"harbor-dek-wrap-v1:"`). Instead, `KeyProvider` is
   extended with `WrapKey(ctx, region, purpose, []byte)` /
   `UnwrapKey(ctx, region, purpose, []byte)` that use
   `"harbor-" + purpose + "-wrap-v1:" + region` as the HKDF info string.
   Signing keys use `purpose = "signing-key"`, giving info string
   `"harbor-signing-key-wrap-v1:EU"` — cryptographically independent from the
   DEK path even though both derive from the same master secret (RFC 5869 §3.2
   domain separation). This is equivalent to a separate secret from a
   cryptographic standpoint, with no extra operational burden. The Helm chart
   already plumbs `KEK_SECRET` in `harbor-hot`; no new env var is needed.

3. **Auto-seed race** — two replicas starting simultaneously against an empty DB
   could both attempt to seed the first key. The `idx_signing_keys_one_active`
   partial unique index will serialise them; the loser gets a conflict error and
   should retry `ListLive()` (not fail). The auto-seed helper needs explicit
   conflict-retry logic.

4. **LocalSigner in prod** — Phase 1 still uses `LocalSigner` (in-process
   private key in memory). This is acceptable for v1 but MUST be flagged loudly
   at startup. The `hsmSigner` upgrade is a separate plan; this plan does not
   attempt to close that gap.

## Definition of done

- Phase 1: `harbor-hot` starts against the prod DB, `/token` returns a
  verifiable ES256 JWT (kid in header matches a key in `/jwks.json`),
  `POST /admin/keys/rotate` returns `200` with schedule (not `501`), all tests
  green on CI.
- Phase 2: `/jwks.json` dynamically reflects key set after a rotation without
  restart; verified by integration test.
- Phase 3: Scheduled rotations apply automatically; scheduler goroutine exits
  cleanly on context cancellation; `signing-key-rotation.md` "Known gaps"
  section updated to reflect closed items.
