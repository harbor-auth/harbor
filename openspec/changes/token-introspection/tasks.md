# Tasks: Token introspection (RFC 7662 — POST /introspect)

## Prerequisites

- [ ] Confirm `real-token-issuance` has landed (access tokens are real ES256
      JWTs with `jti`, `aud`, `exp` claims — introspection is meaningless
      without them)
- [ ] Confirm the `/introspect` stubs in `api/` (paths + response schema)
      match the RFC 7662 contract; reconcile the `IntrospectionResponse`
      schema if drifted (`active` required; `sub`, `scope`, `client_id`,
      `exp`, `iat`, `jti`, `token_type` optional)
- [ ] Regenerate `internal/gen/openapi/` and verify the generated server
      interface exposes the introspect operation

## Implementation

- [ ] Add `IntrospectionResult` type to `internal/oidc` (`Active bool` +
      RFC 7662 claim fields)
- [ ] Implement `func (s *Service) Introspect(ctx context.Context, token,
      clientID string) (IntrospectionResult, error)` in `internal/oidc`:
  - [ ] JWT path: verify signature against signers, check `exp`/`iat`
        (reuse the `jwt_verifier.go` pipeline rather than re-implementing)
  - [ ] Revocation path: consult `RevocationFilter`; on filter hit, confirm
        via `RevokedJTIChecker` (`GetRevokedJTI`); revoked → inactive
  - [ ] Refresh-token path: look up in the session store; derive active from
        `revoked_at` / `expires_at`
  - [ ] Cross-client isolation: non-admin caller with token `aud` ≠
        `clientID` → `Active: false` (no error, no claims)
  - [ ] Honor `token_type_hint` as ordering optimization only (wrong hint
        must still resolve correctly)
- [ ] Implement `internal/oidcapi/introspect.go` —
      `func (s *Server) PostIntrospect(w http.ResponseWriter, r *http.Request)`:
  - [ ] Parse `Authorization`: Basic client credential (validate against the
        client store) or admin Bearer token; anonymous / invalid → `401`
        with `WWW-Authenticate`
  - [ ] Parse `application/x-www-form-urlencoded` body; missing `token`
        param → `400 invalid_request`
  - [ ] Delegate to `svc.Introspect`; serialize `active: true` + claims or
        `{ "active": false }`; internal errors → `500` with a PII-free body
  - [ ] Record telemetry with `telemetry.EndpointIntrospect`
- [ ] Register the route on the hot-path router (`internal/oidcapi` router /
      `cmd/harbor-hot`); confirm it is NOT mounted on harbor-mgmt
- [ ] `go build ./...` and `go vet ./...` clean

## Tests

- [ ] Valid non-revoked JWT + correct client Basic auth → `200`,
      `active: true`, claims match the minted token
- [ ] Fast path: bloom filter miss performs zero DB queries (assert via a
      counting fake `RevokedJTIChecker`)
- [ ] Expired JWT → `200 { "active": false }`
- [ ] Tampered signature → `200 { "active": false }`
- [ ] Revoked JTI (in filter and DB) → `200 { "active": false }`
- [ ] Bloom false positive (in filter, NOT in DB) → `active: true` (DB
      confirmation rescues the token)
- [ ] Refresh token: live session → `active: true`; revoked session →
      `active: false`; expired session → `active: false`
- [ ] Wrong `token_type_hint` still resolves the token correctly
- [ ] Cross-client: client B introspecting client A's token → `200
      { "active": false }` — response byte-identical to an unknown token
- [ ] Admin Bearer introspecting any client's token → `active: true`
- [ ] Anonymous caller → `401`; bad client secret → `401`
- [ ] Missing `token` parameter → `400`

## Validation

- [ ] `go test ./...` green
- [ ] `openspec validate token-introspection --strict` passes
- [ ] `make agent-check` clean
- [ ] Manual smoke: mint a token via `/token`, introspect it (active), revoke
      via `/admin/revoke-jwt`, introspect again (inactive) — on harbor-hot
- [ ] Update `docs/plans/token-introspection.md` checklist; promote via
      `@plan promote token-introspection`
