---
title: OIDF OP conformance (green conformance suite on every PR)
status: draft
design_refs: [§1.8, §11.7, §3.1]
targets: [internal/oidcapi/, internal/oidc/, api/openapi/harbor.yaml, conformance/]
promoted_to: null
openspec: changes/oidf-conformance
created: 2026-07-14
---

# OIDF OP conformance (plan)

> **Dependency order:** depends on **`real-token-issuance`** (the suite requires
> real signed JWTs), **`auth-code-persistence`** (multi-replica-safe codes),
> and **`user-enrollment`** (real user identities for the full login ceremony).
> This is the **last plan** in the dependency graph — the conformance suite is
> the integration gate that confirms everything composes correctly end-to-end.

## Problem

The OIDF OP test suite (`conformance/`) is intentionally wired into CI (the
`e2e` job, Foundation F8) but is known to fail today. The `conformance/README.md`
documents which tests are expected to pass vs. fail and why. The current state:

- **`/authorize` + `/token` (authorization_code)** — partially pass. The basic
  happy path works; failures are due to missing `jti`, `iss` validation in
  responses, and absent `id_token` claims like `auth_time` and `nonce`.
- **`/token` (refresh_token)** — fails: `harbor-hot` serves no real JWT; the
  `id_token` in the refresh response is a scaffold placeholder.
- **PKCE S256** — passes (the PKCE implementation is real and passes invariant
  checks). PKCE `plain` is correctly rejected (§11.7 negative).
- **`/userinfo`** — not implemented (endpoint absent from OpenAPI spec).
- **Pairwise subjects** — fails: PPID derivation is implemented but not yet
  wired into the login flow (`session-ppid-seam` is a prerequisite).
- **Discovery** (`/.well-known/openid-configuration`) — passes structurally but
  is missing several required fields once real signing is in place
  (`jwks_uri`, `token_endpoint_auth_methods_supported`, `claims_supported`).
- **§11.7 negatives** — alg:none, HS256, redirect_uri mismatch — all pass.

The goal of this plan is to move the conformance suite from its current
"intentionally red" status to **green on every PR**, which becomes the §1.8
Stage-7 production readiness gate.

## Proposed approach

### Phase 1 — id_token completeness (depends on `real-token-issuance`)

The `id_token` must include the claims required by OIDC Core §2:

| Claim | Status | Fix |
|---|---|---|
| `iss` | present (stub URL) | wire real issuer from config |
| `sub` | present (random UUID) | wire real PPID after `session-ppid-seam` |
| `aud` | present | confirm it matches client_id |
| `exp` | present | confirm it's `iat + 300` (5 min default) |
| `iat` | present | ✅ |
| `auth_time` | **missing** | record login timestamp in session; emit here |
| `nonce` | **missing** | pass nonce through `/authorize` → code → id_token |
| `jti` | **missing** | issue UUID per token; required for bloom filter plan |
| `azp` | missing (optional but checked by suite) | emit when aud is single value |

### Phase 2 — `/userinfo` endpoint

The OIDF suite calls `GET /userinfo` with an access token and expects at least:
```json
{ "sub": "<pairwise_sub>", "email": "...", "email_verified": true }
```

Implementation:
1. Add `GET /userinfo` to `api/openapi/harbor.yaml` (regenerate `harbor.gen.go`).
2. Route to a new `internal/oidcapi/userinfo.go` handler.
3. Handler validates the access token (bearer auth), looks up the session, and
   returns the claims granted in that session's scope.
4. `email` and `email_verified` come from `internal/users` (requires
   `user-enrollment` to exist).

### Phase 3 — Discovery completeness

`GET /.well-known/openid-configuration` must include several fields the suite
checks. Gaps to fill:

| Field | Fix |
|---|---|
| `jwks_uri` | already present; confirm it matches the live JWKS endpoint |
| `userinfo_endpoint` | add once Phase 2 ships |
| `token_endpoint_auth_methods_supported` | add `["none"]` (public clients only for now) |
| `claims_supported` | add `["sub","iss","aud","exp","iat","auth_time","nonce","jti","email"]` |
| `response_types_supported` | confirm `["code"]` |
| `subject_types_supported` | add `["pairwise"]` |
| `id_token_signing_alg_values_supported` | add `["ES256"]` (after real-token-issuance) |
| `code_challenge_methods_supported` | add `["S256"]` |
| `scopes_supported` | add `["openid","email","offline_access"]` |

### Phase 4 — Nonce passthrough

The OIDF suite sends a `nonce` on `/authorize` and expects it back in the
`id_token`. Currently Harbor ignores nonce:

1. Extend `AuthCode` (and the auth code store) to carry `Nonce string`.
2. In `authorize.go`, extract `nonce` from the request and store it in the code.
3. In `Token()`, propagate `nonce` from the code into `tokens.Issue(...)`.
4. `tokens.Issue` emits it as a claim only when non-empty (optional parameter,
   not present for refresh responses).

### Phase 5 — auth_time

The OIDF suite checks `auth_time` (the timestamp of the most recent user
authentication). Carry it through:

1. `RefreshSession` gains `AuthTime time.Time`.
2. Set at session creation time in `Authorize()`.
3. `Token()` and `Refresh()` emit `auth_time` in the `id_token` (as a Unix
   timestamp integer, per OIDC Core §2).

### Phase 6 — Conformance suite triage and assert-pass.sh

Update `conformance/assert-pass.sh` as each phase ships to gate on the tests
that are now expected to pass. The CI `e2e` job already runs `make conformance`
and fails on a non-zero exit — the shell script is the only thing that needs
updating as coverage grows.

## DESIGN alignment

Realizes §1.8 (Stage-7 OIDF gate) and §11.7 (conformance negative tests).
Phase 1–5 each realize specific OIDC Core §2 / §3.1 requirements. Phase 2
realizes §11.4 (userinfo endpoint). No DESIGN changes needed — this is
realization of existing design.

## Target code paths

- `api/openapi/harbor.yaml` — add `/userinfo`; update discovery fields
- `internal/gen/openapi/harbor.gen.go` — regenerated via `@openspec`
- `internal/oidcapi/userinfo.go` — new `/userinfo` handler
- `internal/oidcapi/discovery.go` — extend `openid-configuration` fields
- `internal/oidc/authorize.go` — capture `nonce` and `auth_time`
- `internal/oidc/token.go` — emit `nonce`, `auth_time`, `jti` in `id_token`
- `internal/oidc/store.go` — extend `AuthCode` with `Nonce`; `RefreshSession` with `AuthTime`
- `conformance/assert-pass.sh` — update pass-list incrementally per phase

## Implementation checklist

### Phase 1 (id_token completeness)
- [ ] Add `auth_time`, `nonce`, `jti`, `azp` to `tokens.Issue` signature
- [ ] Capture `nonce` in `authorize.go` → store in `AuthCode`
- [ ] Thread `nonce` through `Token()` → `tokens.Issue`
- [ ] Add `auth_time` to `RefreshSession`; set at session creation
- [ ] Issue UUID `jti` per id_token
- [ ] Tests: `TestTokenIssue_IDTokenClaims`

### Phase 2 (userinfo)
- [ ] Add `GET /userinfo` to OpenAPI spec; regenerate
- [ ] Implement `internal/oidcapi/userinfo.go`
- [ ] Tests: `TestUserinfo_*`

### Phase 3 (discovery)
- [ ] Fill all missing fields in `discoveryHandler`
- [ ] Tests: `TestDiscovery_RequiredFields`

### Phase 4 (nonce passthrough)
- [ ] Already covered in Phase 1 above

### Phase 5 (auth_time)
- [ ] Already covered in Phase 1 above

### Phase 6 (assert-pass.sh)
- [ ] Update `conformance/assert-pass.sh` as each phase ships
- [ ] CI `e2e` job goes green
- [ ] `@validate` passes
