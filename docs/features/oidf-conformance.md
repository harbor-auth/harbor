---
title: OIDF OP Conformance (green certification suite)
status: implemented
design_refs: [§1.8, §11.7, §3.1]
code:  [internal/oidc/, internal/oidcapi/, api/openapi/harbor.yaml, conformance/]
spec:  [api/openapi/harbor.yaml]
tests: [internal/oidc/, internal/oidcapi/, conformance/]
depends_on: [real-token-issuance, user-enrollment, session-ppid-seam, userinfo-endpoint]
plan: oidf-conformance
last_reconciled: 2026-07-20
---

# OIDF OP Conformance (green certification suite)

## Summary

`harbor-hot` passes the OpenID Foundation **OIDC Basic OP certification** plan,
and the conformance run is wired into CI as a release-blocking gate (§1.8
Stage 7). Getting there required completing the `id_token` claim set
(`auth_time`, `nonce`, `jti`, `azp`, `acr`, `amr`), threading `auth_time`
through the flow, shipping `/userinfo`, and filling in the discovery metadata
(`subject_types_supported`, `claims_supported`, `userinfo_endpoint`, …). The
§11.7 negative checks (alg:none, HS256, redirect_uri mismatch, PKCE `plain`
rejection) continue to pass. `conformance/assert-pass.sh` is fail-closed: any
required module that is absent or non-passing blocks the release.

## Behavior (as-built)

**id_token completeness** — `internal/oidc/jwt_issuer.go` emits the full OIDC
Core §2 claim set on the `id_token`: `iss`, `sub` (pairwise PPID), `aud`,
`azp` (= `client_id` when `aud` is single-valued), `exp`, `iat`, `auth_time`,
`nonce` (omitempty), `acr`, `amr`, and a per-token `jti` (256-bit URL-safe,
`newJTI()`). Access tokens also carry a `jti`. `auth_time` is threaded from the
session creation timestamp through authorize → token issuance.

**Discovery metadata** — `internal/oidcapi/discovery.go` advertises the fields
the suite checks: `userinfo_endpoint`, `subject_types_supported`
(`["pairwise"]`), and a `claims_supported` list covering the emitted claims,
alongside the existing signing-alg / PKCE-method / response-type fields.

**/userinfo** — the Bearer-authenticated UserInfo endpoint (see
[userinfo-endpoint](userinfo-endpoint.md)) satisfies the suite's
`oidcc-userinfo-get` module.

**Release gate** — `conformance/assert-pass.sh` consumes the normalized
`results.json` and exits non-zero on anything short of a clean pass. It enforces
a `REQUIRED_MODULES` allowlist (`oidcc-server`, `oidcc-userinfo-get`,
`oidcc-idtoken-signature`, `oidcc-scope-profile`) so a silently-skipped plan
cannot report a hollow "0 failures"; `WARNING` is advisory-acceptable, every
other non-`PASSED` status fails the gate.

## Interfaces / Endpoints

- No new public endpoint beyond `/userinfo` (documented separately); this
  feature is the *claim/metadata completeness* + *CI gate* layer.
- `id_token` / access-token claims: `iss`, `sub`, `aud`, `azp`, `exp`, `iat`,
  `auth_time`, `nonce`, `acr`, `amr`, `jti`.
- Discovery: `subject_types_supported`, `claims_supported`,
  `userinfo_endpoint`, `id_token_signing_alg_values_supported`,
  `code_challenge_methods_supported`.

## Code map

| Path | Role |
|---|---|
| `internal/oidc/jwt_issuer.go` | Emits the full id_token claim set (`azp`, `auth_time`, `nonce`, `acr`, `amr`, `jti`); `newJTI()`. |
| `internal/oidc/service.go` | Threads `auth_time` (and nonce/PKCE params) through authorize → token issuance. |
| `internal/oidcapi/discovery.go` | `subject_types_supported`, `claims_supported`, `userinfo_endpoint`. |
| `internal/oidcapi/userinfo.go` | `/userinfo` handler (satisfies `oidcc-userinfo-get`). |
| `api/openapi/harbor.yaml` | `/userinfo` + discovery metadata contract. |
| `conformance/assert-pass.sh` | Fail-closed release gate with a `REQUIRED_MODULES` allowlist. |

## Security & privacy invariants

- **Asymmetric signing only (§11.7)** — id_tokens are ES256-signed; alg:none and
  HS256 are rejected (negative conformance modules pass).
- **Pairwise subjects (§3.1/§3.2)** — `subject_types_supported: ["pairwise"]`;
  the `sub` is the per-RP PPID.
- **Per-token `jti`** — every id_token / access token carries a unique 256-bit
  `jti`, enabling targeted revocation (bloom-filter path).
- **Fail-closed gate (§1.8)** — missing/empty/invalid `results.json`, a non-zero
  runner exit, or any required module not `PASSED`/`WARNING` blocks the release.

## Tests

- `internal/oidc/jwt_issuer_test.go` — asserts the exact id_token claim set
  (allowed-claims allowlist incl. `azp`/`auth_time`/`acr`/`amr`/`nonce`/`jti`)
  and per-token `jti` presence on both id and access tokens.
- `internal/oidcapi/discovery_test.go` — required discovery fields present.
- `internal/oidcapi/userinfo_test.go` — `/userinfo` sub round-trip + auth errors.
- `conformance/` — the OIDF suite runs in the CI `e2e` job; `assert-pass.sh`
  gates on the required modules.

## Known gaps / TODOs

- **`auth-code-persistence`** — the conformance suite passes today against the
  in-memory authorization-code store (single-replica CI). Durable, multi-replica
  code persistence remains a follow-up hardening (does not affect the cert).
- **UserInfo email** — `/userinfo` returns `sub` today; grant-backed
  `email`/`email_verified` resolution is a follow-up (see
  [userinfo-endpoint](userinfo-endpoint.md)).
- **`acr`/`amr` values** — emitted with baseline values; richer
  authentication-context reporting (e.g. step-up) is future work (§11.4).
