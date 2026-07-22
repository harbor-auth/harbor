# Tasks: End-session / RP-Initiated Logout

Estimated: ~6 hours. Weft-parallelisable to ~3 hours.

## T1 — OpenAPI contract (1 h)
- [ ] T1.1 Add `GET /end_session` to `api/openapi/harbor.yaml`:
      params: `id_token_hint` (required string), `post_logout_redirect_uri` (optional string), `state` (optional string);
      responses: 302 Found, 400 invalid_request
- [ ] T1.2 Add `POST /end_session` (form-post variant; same params in body)
- [ ] T1.3 Run `make codegen` to regenerate `internal/gen/openapi/`

## T2 — Discovery update (15 min)
- [ ] T2.1 Add `EndSessionEndpoint: strPtr(base + "/end_session")` to `metadata()` in `internal/oidcapi/discovery.go`
- [ ] T2.2 Update `internal/oidcapi/discovery_test.go` to assert `end_session_endpoint` present

## T3 — `internal/oidcapi/end_session.go` handler (2 h)
- [ ] T3.1 Define `SessionRevoker` interface (wraps `RevokeSessionsByUserClient`)
- [ ] T3.2 Define `LogoutClientLookup` interface (wraps `registry.Get` → `LogoutURIs`)
- [ ] T3.3 Implement `GetEndSession`:
      - Parse `id_token_hint` via `s.verifier.Verify(ctx, hint)` — 400 if missing/invalid
      - Extract `sub` + `azp` from claims
      - Validate `post_logout_redirect_uri` against `LogoutClientLookup.GetLogoutURIs(ctx, azp)`
      - Call `s.sessionRevoker.RevokeSessionsByUserClient(ctx, sub, azp)`
      - Redirect to validated `post_logout_redirect_uri?state=<state>` or `{issuer}/logged-out`
- [ ] T3.4 Implement `PostEndSession` (parse form body, delegate to same logic)

## T4 — Server wiring (30 min)
- [ ] T4.1 Add `SessionRevoker` + `LogoutClientLookup` fields to `oidcapi.Config` + `Server`
- [ ] T4.2 Wire `DBSessionStore` as `SessionRevoker` in `cmd/harbor-hot/main.go`
- [ ] T4.3 Wire `DBClientRegistry` as `LogoutClientLookup` in `cmd/harbor-hot/main.go`
- [ ] T4.4 Add `JWTVerifier` to `Server` config for `id_token_hint` verification

## T5 — Tests: `internal/oidcapi/end_session_test.go` (2 h)
- [ ] T5.1 Valid `id_token_hint` + registered `post_logout_redirect_uri` → 302, `RevokeSessionsByUserClient` called
- [ ] T5.2 Missing `id_token_hint` → 400 `invalid_request`
- [ ] T5.3 Invalid/expired `id_token_hint` → 400 `invalid_request`
- [ ] T5.4 Unregistered `post_logout_redirect_uri` → 400 (open-redirect prevention)
- [ ] T5.5 Missing `post_logout_redirect_uri` → 302 to `{issuer}/logged-out`
- [ ] T5.6 `state` param passed through to redirect URI
- [ ] T5.7 `POST /end_session` form-post variant works identically

## T6 — Validation
- [ ] `go build ./... && go vet ./... && go test ./...`
- [ ] `make agent-check`
- [ ] Verify discovery doc includes `end_session_endpoint`
