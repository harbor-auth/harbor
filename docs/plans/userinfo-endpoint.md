---
title: UserInfo endpoint (OIDC Core §5.3 — GET /userinfo)
status: draft
design_refs: [§3.3, §11.4, §3.1]
targets: [internal/oidcapi/, api/openapi/harbor.yaml, internal/gen/openapi/]
promoted_to: null
openspec: changes/userinfo-endpoint
created: 2026-07-14
---

# UserInfo endpoint (plan)

> **Dependency order:** depends on **`real-token-issuance`** (the endpoint
> validates a bearer access token, which must be a real signed JWT with a
> verifiable `sub` and scope set) and **`user-enrollment`** (the response
> includes `email` + `email_verified` sourced from the enrolled user record).
> Does **not** depend on `session-ppid-seam` — the `sub` in the access token
> is already the PPID when issued, so the endpoint only needs to look it up
> (no derivation at userinfo time). Can land in Phase 2, parallel to
> `session-ppid-seam`.

## Problem

`GET /userinfo` is absent from the OpenAPI contract and the `harbor-hot`
router. The OIDF OP conformance suite sends a bearer access token to
`/userinfo` and expects at minimum:

```json
{ "sub": "<pairwise_sub>", "email": "...", "email_verified": true }
```

Without the endpoint the suite fails every test that calls it, and the
`oidf-conformance` plan cannot go green. It is also a hard OIDC Core §5.3
requirement for any compliant OP.

Additionally, `bloom-filter-revocation` specifies introspection as the
false-positive confirmation path — a `/userinfo` request with an invalid
token is a lightweight proxy for that until real introspection lands.

## Proposed approach

1. **OpenAPI first** (`@openspec new userinfo-endpoint`) — add
   `GET /userinfo` to `api/openapi/harbor.yaml` with:
   - Bearer token auth (`securityScheme: BearerAuth`)
   - `200 OK` response body: `UserInfoResponse` schema (`sub`, `email`,
     `email_verified`, `name` — all optional except `sub`)
   - `401 Unauthorized` on missing/invalid token
   - `403 Forbidden` on insufficient scope (requires `openid`)
   Regenerate `internal/gen/openapi/harbor.gen.go` via `@openspec`.

2. **Handler** — new `internal/oidcapi/userinfo.go`:
   - Parse `Authorization: Bearer <token>` header.
   - Validate the access token against the live JWKS (reuses the same
     verification path as any RP — no special DB lookup).
   - Confirm `openid` scope is present in the token's `scope` claim.
   - Look up the enrolled user by `sub` (PPID) — returns `email` +
     `email_verified` from the `users` table.
   - Return the `UserInfoResponse` JSON.
   - On invalid/expired token: `401` with `WWW-Authenticate: Bearer error="invalid_token"`.

3. **Route** — register `GET /userinfo` in `internal/oidcapi/router.go`
   (or wherever hot-path routes are registered).

4. **Scope gate** — userinfo must only respond to tokens with `openid` in
   scope. Access tokens currently carry scope as a claim; add a scope
   presence check in the handler.

## DESIGN alignment

Realizes OIDC Core §5.3 (UserInfo endpoint) and §11.4 in the design
(`harbor` serves user profile claims from the enrolled user record).
The pairwise `sub` in the response is the PPID, consistent with §3.2
(privacy-preserving identity). No DESIGN changes needed.

## Target code paths

- `api/openapi/harbor.yaml` — add `GET /userinfo` + `UserInfoResponse` schema
- `internal/gen/openapi/harbor.gen.go` — regenerated
- `internal/oidcapi/userinfo.go` — new handler
- `internal/oidcapi/router.go` (or equivalent) — register route

## Implementation checklist

- [ ] `@openspec new userinfo-endpoint` — draft the OpenAPI change
- [ ] Add `GET /userinfo` to `api/openapi/harbor.yaml`; regenerate via `@openspec`
- [ ] Implement `internal/oidcapi/userinfo.go` — token validation, scope check, user lookup
- [ ] Register route; verify `go build ./...` clean
- [ ] Tests: valid token → `200` with `sub` + `email`; no token → `401`; wrong scope → `403`; expired token → `401`
- [ ] Update `conformance/assert-pass.sh` to gate on userinfo tests now expected to pass
- [ ] Author & verify paired OpenSpec change: `openspec validate userinfo-endpoint --strict`
- [ ] Reconcile & promote: `@plan promote userinfo-endpoint`

## Risks & open questions

- **Token validation strategy**: the handler can either (a) verify the JWT
  locally against the cached JWKS (stateless — preferred) or (b) look up
  the access token in the session store (adds a DB hit). Option (a) is
  correct per §3.3's stateless hot path; choose it.
- **Opaque access tokens** (future §3.3 opt-in): if a client negotiates
  `token_endpoint_auth_method=opaque`, userinfo will need an introspection
  lookup instead. This plan targets JWT-format access tokens only; opaque
  support follows the `token-introspection` plan.
- **Claims filter**: scope controls which claims are returned
  (`email` only with `email` scope, etc.). v1 returns all available claims;
  scope-filtered response follows the `client-grant-persistence` plan.

## Definition of done

`go build/vet/test ./...` green; `GET /userinfo` in the OpenAPI spec and
served by `harbor-hot`; valid access token returns `sub` + `email` +
`email_verified`; invalid/expired tokens return proper `401`; OIDF suite
userinfo tests pass; `conformance/assert-pass.sh` updated.
