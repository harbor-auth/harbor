# Proposal: Real token issuance (crypto.Signer + JWKS)

## Problem

`internal/oidc/issuer.go` ships `placeholderIssuer`, returning obviously-fake
unsigned tokens. The performance thesis (DESIGN §3.3, §6) — RPs verify tokens
offline against a cached JWKS with no DB hit — is impossible until we mint real
asymmetric-signed JWTs and publish the matching public keys at `/jwks.json`.
There is no signer, no signing key, and no JWKS endpoint.

## Proposed Solution

- Add a `crypto.Signer` (ES256 / P-256 ECDSA) backed by a signing `KeyProvider`
  (dev in-process key; regional HSM in prod, §7.3).
- Implement `JWTIssuer` satisfying the existing `oidc.TokenIssuer` seam: builds
  minimal-claim ID + access tokens (`iss`, `sub`=PPID, `aud`, `exp`, `iat`,
  `nonce`), signs with the `Signer`, stamps `kid`.
- Add `GET /jwks.json` to the OpenAPI contract and serve the region's public
  keys as a cache-friendly JWKS document (§3.4).

## Non-Goals

- Opaque access tokens + introspection (per-RP opt-in; §3.3 — later).
- HSM integration (dev in-proc key now; HSM seam documented).
- Refresh tokens (owned by `refresh-token-rotation`).

## Success Criteria

- [ ] Issued tokens are real ES256 JWTs minted through `TokenIssuer` (placeholder removed from the hot path).
- [ ] `GET /jwks.json` is in the spec and served; issued tokens verify offline against it.
- [ ] `kid` in the token header matches a JWKS key; expired/tampered tokens are rejected.
- [ ] Claims carry no PII beyond PPID `sub` + consented scopes.
- [ ] Frozen signing/verify vectors byte-match; `make agent-check` clean.
