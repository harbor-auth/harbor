# Tasks: Token revocation endpoint (RFC 7009 — POST /revoke)

## Prerequisites

- [ ] **Hard dependency — build order `token-introspection` → `rate-limiting` →
  `token-revocation-endpoint`.** `/revoke` shares the `internal/oidcapi/`
  hot-path router/middleware surface that `token-introspection` extends and
  reuses its client-auth seam, and it is an abuse-sensitive surface that MUST
  sit **behind the rate limiter**. Do NOT start until both `token-introspection`
  and `rate-limiting` are on `main`.

## Implementation

- [ ] Add `POST /revoke` to `api/openapi/harbor.yaml` (Basic auth; form body
  `token` + optional `token_type_hint`; `200` empty success); run `make codegen`
  to regenerate `internal/gen/openapi/`.
- [ ] Enforce client Basic-auth (reuse the `token-introspection` client-auth
  seam); anonymous → `401`.
- [ ] `internal/oidcapi/revoke.go`: resolve `token` (honouring `token_type_hint`
  as advisory) → grant/JTI.
- [ ] Refresh tokens: mark the session/grant revoked (`revoked_at`) and
  invalidate the whole grant family via the `grant-id-fk` seam.
- [ ] Access tokens: record the JTI via the `revocation-outbox` → `revoked_jtis`
  path so the bloom filter + `/introspect` report the token inactive.
- [ ] Cross-client isolation: a token not owned by the authenticated `client_id`
  returns `200` and performs no revocation (no `403`, no leak).
- [ ] Uniform response: `200` empty body for all well-formed authenticated
  requests (unknown/expired/already-revoked included); `400 invalid_request`
  only for malformed requests.
- [ ] Register `/revoke` on the hot-path router **behind the rate-limiter
  middleware**.
- [ ] Add a thin `Revoke(token)` service method in `internal/oidc/` if one does
  not already exist (reusing the revocation seam).

## Tests

- [ ] Valid refresh token → session `revoked_at` set; grant family invalidated.
- [ ] Valid access token → JTI recorded; subsequent `/introspect` returns `active:false`.
- [ ] Unknown token → `200`, no error, no state change.
- [ ] Cross-client token → `200`, no revocation performed.
- [ ] Anonymous caller → `401`; malformed body → `400 invalid_request`.
- [ ] Security: the uniform-`200` response/timing does not distinguish existing
  vs non-existing tokens (no enumeration oracle).
- [ ] Wrong `token_type_hint` still revokes (advisory hint, fallback to the
  other store).

## Validation

- [ ] `go build ./... && go vet ./... && go test ./...`
- [ ] `make agent-check`
- [ ] `openspec validate token-revocation-endpoint --strict`
