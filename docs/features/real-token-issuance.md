---
title: Real Token Issuance (ES256 JWTs + JWKS)
status: implemented
design_refs: [§3.3, §3.4, §7.3, §3.5]
code:  [internal/crypto/, internal/oidc/, internal/oidcapi/, cmd/harbor-hot/]
spec:  [api/openapi/harbor.yaml]
tests: [internal/crypto/, internal/oidc/, internal/oidcapi/]
depends_on: [oidc-authorization-code]
plan: real-token-issuance
last_reconciled: 2026-07-16
---

# Real Token Issuance (ES256 JWTs + JWKS)

## Summary

Harbor mints **real asymmetric-signed JWTs** through the existing
`oidc.TokenIssuer` seam and publishes the matching public keys at
`GET /jwks.json`, so relying parties verify tokens **offline** against a cached
JWKS with no per-request DB hit — the performance thesis of docs/DESIGN.md §3.3
/ §3.4. This replaces the unsigned `placeholderIssuer` scaffold
([oidc-authorization-code](oidc-authorization-code.md) Known gaps) with
`oidc.JWTIssuer`, backed by a `crypto.Signer` (ES256 / P-256). The signing key
is held behind the `crypto.Signer` interface — in dev an in-process
`crypto.LocalSigner`, in prod the regional HSM (§7.3) — so the `/token`
exchange logic never touches key material. The `kid` is the RFC 7638 JWK
thumbprint, letting the same signer feed both the issuer and the JWKS endpoint
with a self-consistent key id.

## Behavior (as-built)

**Signing (`crypto`)** — `crypto.Signer` is the narrow signing seam: `Sign`
(hashes with SHA-256 internally, returns the raw ES256 `R‖S` signature,
each coordinate left-padded to 32 bytes per RFC 7518 §3.4), `KeyID` (the RFC
7638 JWK thumbprint), and `PublicJWK` (the public key as a `crypto.JWK`).
`crypto.LocalSigner` is a **DEV-ONLY scaffold** — it generates a P-256 key
in-process, logs a prominent DEV-ONLY warning at construction, and stringifies
as `localSigner(DEV-ONLY)`; tokens do not survive a restart. The production
signer wraps the regional HSM behind the same interface (§7.3). `JWK.ToPublicKey`
reconstructs and validates the `*ecdsa.PublicKey`, rejecting coordinates that
are over-length or not on P-256 (via `ecdh.P256().NewPublicKey`, avoiding the
deprecated `elliptic` APIs).

**Issuance (`oidc.JWTIssuer`)** — `Issue` mints two compact JWTs, both `ES256`
with the signer's `kid` stamped in the JOSE header:

- **ID token** (`typ: JWT`): `iss`, `sub` (**always the PPID**, §3.2), `aud` =
  `client_id`, `azp` = `client_id` (OIDC Core §2, single-valued `aud`), `exp`,
  `iat`, `auth_time`, and — when present — `acr`, `amr`, `nonce`; plus a random
  256-bit `jti`. TTL is 10 minutes (§3.5).
- **Access token** (`typ: at+JWT`, RFC 9068 profile): `iss`, `sub`, `aud`,
  `exp`, `iat`, `scope`, `jti`. TTL is 10 minutes (§3.5).

The claim set carries **no PII beyond the PPID `sub` + consented scopes**
(enforced by invariant, see below). The header field order is fixed
(`alg`, `typ`, `kid`) for byte-stable golden vectors. The clock is injectable
(`JWTIssuerConfig.Now`) for deterministic tests.

**JWKS (`GET /jwks.json`)** — `oidc.BuildJWKS` builds the document from the
configured signer(s), returning the spec-generated `openapi.JWKSet` so the
served bytes cannot drift from the OpenAPI contract. The slice form supports
key rotation with overlap (publish a new `kid` alongside the old while old
tokens drain, §7.3). `Server.GetJwks` serves the **precomputed, cached**
document (`Content-Type: application/json`, `Cache-Control: public,
max-age=300`) — the JWKS changes only on rotation, which restarts the process
in v1.

**Discovery** — `/.well-known/openid-configuration` advertises
`"jwks_uri": "<issuer>/jwks.json"` (§3.4) so auto-discovering RPs find the
endpoint, and continues to advertise only pairwise subjects (§3.2) and
ES256/EdDSA signing (§7).

**Wiring** — `cmd/harbor-hot/main.go` constructs one `crypto.NewLocalSigner`
and passes it both to `oidc.NewJWTIssuer` (as the service's `TokenIssuer`) and
to `oidcapi.New` (as the JWKS `Signers`), so an issued token's `kid` always
matches a key in the served JWKS. The `placeholderIssuer` scaffold remains in
`internal/oidc/issuer.go` for tests but is no longer on the hot path.

## Interfaces / Endpoints

- `GET /jwks.json` → `200` `openapi.JWKSet` (EC P-256 public keys), `Cache-Control: public, max-age=300`.
- `GET /.well-known/openid-configuration` → now includes `jwks_uri`.
- Exported Go surface:
  - `crypto.Signer` (`Sign`, `KeyID`, `PublicJWK`), `crypto.JWK` (+ `ToPublicKey`).
  - `crypto.NewLocalSigner` / `crypto.NewSignerFromKey` → `*crypto.LocalSigner` (DEV-ONLY).
  - `oidc.NewJWTIssuer(oidc.JWTIssuerConfig{Signer, Now})` → `*oidc.JWTIssuer` (implements `oidc.TokenIssuer`).
  - `oidc.BuildJWKS([]crypto.Signer) openapi.JWKSet`.
- Contract: `api/openapi/harbor.yaml` defines the `/jwks.json` operation + `JWKSet`/`JWK` schemas.

## Code map

| Path | Role |
|---|---|
| `internal/crypto/signer.go` | `Signer` interface, `JWK` (+ `ToPublicKey`), DEV-ONLY `LocalSigner` (ES256, RFC 7638 `kid`). |
| `internal/oidc/issuer.go` | `TokenIssuer` seam + `IssueParams`/`IssuedTokens`; retains the unsigned `placeholderIssuer` scaffold (test-only). |
| `internal/oidc/jwt_issuer.go` | `JWTIssuer` — mints ES256 ID + access tokens; minimal claims; `kid` header; random `jti`. |
| `internal/oidc/jwks.go` | `BuildJWKS` — JWKS document from signer public keys (spec-typed, rotation-ready). |
| `internal/oidcapi/jwks.go` | `GET /jwks.json` handler — precomputed + edge-cacheable. |
| `internal/oidcapi/discovery.go` | Sets `jwks_uri` in the discovery document. |
| `cmd/harbor-hot/main.go` | Wires one `LocalSigner` into both the `JWTIssuer` and the JWKS endpoint. |
| `internal/oidc/testdata/jwt_vectors.json` | Frozen golden vectors — verify a fixed signed token against a fixed key. |

## Security & privacy invariants

- **`sub` is always the PPID (§3.2)** — `INV-JWT-SUB-IS-PPID` on `JWTIssuer.Issue`.
- **No PII in claims beyond PPID `sub` + consented scopes (§3.2, §6.5)** — `INV-JWT-NO-PII` on `JWTIssuer.Issue`.
- **Asymmetric signing only; private key never leaves the boundary (§3.3, §7.3)** — `Sign` lives behind `crypto.Signer`; the prod HSM implementation keeps the key inside the HSM. `LocalSigner` is DEV-ONLY and loudly self-identifies.
- **`kid` self-consistency** — the RFC 7638 thumbprint ties every issued token's header `kid` to exactly one published JWK, so offline verifiers select the right key.
- **Served JWKS cannot drift from the contract** — `BuildJWKS` returns the spec-generated `openapi.JWKSet`; the JWKS endpoint serializes that type.
- **Short token TTLs (§3.5)** — 10-minute ID and access tokens.
- **Rotation with overlap (§7.3)** — the `[]Signer` JWKS form publishes new + old `kid`s during a rotation window; `Cache-Control: max-age=300` bounds RP staleness.

## Tests

- `internal/crypto/` — sign→verify round-trip; `PublicJWK`/`ToPublicKey` reconstruction; `kid` = RFC 7638 thumbprint; malformed / off-curve coordinate rejection.
- `internal/oidc/` — `JWTIssuer` claim shape (ID + access), `sub` = PPID, `kid` in header, header/claims decode; issued JWT verifies against `BuildJWKS`; expired / tampered tokens rejected; the `INV-JWT-SUB-IS-PPID` and `INV-JWT-NO-PII` invariant tests; **frozen golden vectors** (`jwt_vectors.json`) verifying a fixed signed token byte-for-byte against a fixed key (ES256 signatures are non-deterministic, so the vectors pin *verification*, never re-signing).
- `internal/oidcapi/` — `GET /jwks.json` shape + cache headers; discovery advertises `jwks_uri`.

## Known gaps / TODOs

- **`LocalSigner` is a SCAFFOLD** — the in-process ECDSA key is DEV-ONLY and not
  HSM-backed; tokens do not survive a restart. Swap for the regional HSM-backed
  `crypto.Signer` (§7.3) before any real deployment.
- **Login/consent still stubbed** — the `sub` is a real PPID, but the subject is
  resolved via the fixed dev auth source in `cmd/harbor-hot`; real passkey login
  ([webauthn-passkeys](webauthn-passkeys.md)) + consent are not yet on the hot
  path.
- **Signing-key rotation is manual** — v1 rotation restarts the process; the
  automated overlap-rotation flow is tracked in
  [signing-key-rotation](../plans/signing-key-rotation.md).
- **No `/introspect`** — opaque access tokens + token introspection remain an
  opt-in seam ([token-introspection](../plans/token-introspection.md)); v1 ships
  JWT access tokens only.
