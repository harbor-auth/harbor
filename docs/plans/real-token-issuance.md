---
title: Real token issuance (crypto.Signer + JWKS)
status: in-progress
design_refs: [§3.3, §3.4, §7.3]
targets: [internal/crypto/, internal/oidc/, internal/oidcapi/, api/openapi/harbor.yaml]
promoted_to: null
openspec: changes/real-token-issuance
created: 2026-07-10
---

# Real token issuance (plan)

> **Dependency order:** *Foundational — no prerequisites.* One of the two roots
> of the build graph (alongside `envelope-encryption-kms`). `session-ppid-seam`
> and `refresh-token-rotation` both depend on this. Build early.

## Problem

`internal/oidc/issuer.go` ships a `placeholderIssuer` that returns
**obviously-fake, unsigned** tokens (`UNSIGNED_PLACEHOLDER_ACCESS_TOKEN.<sub>`).
The whole performance thesis (§3.3, §6) — *RPs verify tokens offline against a
cached JWKS, no DB hit* — is impossible until we mint real asymmetric-signed
JWTs and publish the matching public keys at `/jwks.json`. There is no signing
key, no `internal/crypto` Signer, and no JWKS endpoint. This is the seam every
real login ultimately produces a token through.

## Proposed approach

1. **`crypto.Signer` + `crypto.KeyProvider` (signing side)** — an ES256
   (P-256 / ECDSA) signer whose private key is held by a `KeyProvider`:
   - dev: an in-process generated/loaded ECDSA key (self-identifying `kid`).
   - prod (later): the regional HSM — the private key never leaves the boundary
     (§7.3). Same interface, swapped implementation.
   ES256/EdDSA chosen over RS256 for smaller tokens + faster verify (§3.3).
2. **`JWTIssuer implements oidc.TokenIssuer`** — builds the ID token (minimal
   claims: `iss`, `sub`=PPID, `aud`=client_id, `exp`, `iat`, `nonce`) and the
   access token, signs both with the `Signer`, stamps the `kid` header. Drops
   straight into the existing `TokenIssuer` seam — the `/token` flow logic in
   `service.go` is untouched.
3. **`GET /jwks.json`** — a new hot-path endpoint (added to the OpenAPI
   contract first, §1.2) serving the region's public keys as a JWKS document,
   cache-friendly (static-ish, edge-cacheable per §4.1). Key rotation publishes
   a new `kid` while keeping old public keys until old tokens expire (§7.3).

## DESIGN alignment

Realizes §3.3 (asymmetric JWT hot path), §3.4 (per-region issuer + JWKS
discovery), §7.3 (signing keys in regional HSM, rotation-with-overlap). Keeps
token claims minimal per §3.3's privacy note. Does **not** change `DESIGN.md`.

## Target code paths

- `internal/crypto/signer.go` — `Signer` (ES256) + signing `KeyProvider`
- `internal/oidc/jwt_issuer.go` — `JWTIssuer implements TokenIssuer`
- `internal/oidc/jwks.go` — build the JWKS document from public keys
- `internal/oidcapi/jwks.go` — `GET /jwks.json` handler
- `api/openapi/harbor.yaml` — add the `/jwks.json` operation + JWKS schema (regen `internal/gen/openapi`)
- `internal/crypto/testdata/jwt_vectors.json` — frozen signing/verify vectors

## Implementation checklist

- [ ] `crypto.Signer` (ES256) + signing `KeyProvider` (dev in-proc key; HSM seam documented).
- [ ] `JWTIssuer` implements `TokenIssuer`; minimal claims; `kid` in header; short TTLs (§3.5).
- [ ] JWKS document builder from public key(s); stable `kid`.
- [ ] Add `GET /jwks.json` to `api/openapi/harbor.yaml`; regenerate; implement handler in `internal/oidcapi`.
- [ ] Update `/.well-known/openid-configuration` to set `"jwks_uri": "<issuer>/jwks.json"` so RPs using auto-discovery find the JWKS endpoint (§3.4).
- [ ] Wire `JWTIssuer` into `cmd/harbor-hot/main.go` (replace `NewPlaceholderIssuer`).
- [ ] Tests: sign→verify round-trip; issued JWT verifies against the served JWKS; `kid` matches; expired/tampered tokens rejected; no PII in claims (only consented + PPID `sub`).
- [ ] Frozen golden vectors for a fixed key (byte-equality; never regenerated).
- [ ] Author & verify paired OpenSpec change: `openspec validate real-token-issuance --strict`
- [ ] Reconcile & promote: `@plan promote real-token-issuance`

## Risks & open questions

- **Access-token format** is per-RP (`jwt` default | `opaque`, §3.3) — v1 ships JWT-default; opaque+introspection is a later opt-in, leave the seam.
- ES256 signatures are non-deterministic (random `k`), so JWT golden vectors must pin verification of a *fixed* token, not re-signing — freeze a known-good signed token + its verifying key.
- `/jwks.json` cache headers must balance edge-cacheability against rotation latency — pick a conservative `max-age` and document the rotation overlap.

## Definition of done

`go build/vet/test ./...` green; real ES256 JWTs minted through the existing
`TokenIssuer` seam; `GET /jwks.json` in the spec + served; issued tokens verify
offline against the JWKS; claims carry no PII beyond PPID `sub` + consented
scopes; frozen vectors byte-match; `make agent-check` clean. Ready to
`@plan promote`.
