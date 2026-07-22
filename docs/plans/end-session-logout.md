---
title: End-session / RP-Initiated Logout (§3.3, OIDC Session Management)
status: planned
design_refs: [§3.3, §3.5, §9]
targets: [internal/oidcapi/, api/openapi/harbor.yaml, internal/gen/openapi/, internal/bff/, internal/oidcapi/discovery.go]
depends_on: [bff-flow-wiring, client-secret-auth]
wave: 6
priority: P1
created: 2026-07-22
---

# End-session / RP-Initiated Logout (plan)

> **Priority:** Wave 6 P1 — leaf feature, no dependents. Depends on
> `bff-flow-wiring` (BFF session store wired) and `client-secret-auth`
> (client auth seam for `id_token_hint` validation).

## Problem

Harbor has **no RP-Initiated Logout endpoint** and **no session termination
surface**. The OpenID Connect Session Management / RP-Initiated Logout 1.0
spec requires an `end_session_endpoint` that relying parties call to terminate
a user session. Today:

- RPs have no way to end a Harbor session on behalf of a user.
- The discovery document (`GetOpenIDConfiguration`) does not advertise
  `end_session_endpoint`, so compliant RP libraries cannot discover it.
- `BFFSessionStore.Delete()` exists but is never called on logout.
- `SessionStore.RevokeSessionsByUserClient()` exists but is only called
  from the theft-signal path, never from user-initiated logout.
- There is no front-channel logout notification to sibling RPs.

## Proposed approach

### Endpoint contract (OIDC RP-Initiated Logout 1.0)

```
GET /end_session
  ?id_token_hint=<previously-issued-id-token>
  &post_logout_redirect_uri=<uri-registered-with-client>
  &state=<opaque-value-passed-through-to-redirect>
```

### Implementation pipeline

1. **OpenAPI first** — add `GET /end_session` (and `POST /end_session` for
   form-post clients) to `api/openapi/harbor.yaml`. Regenerate
   `internal/gen/openapi/`.

2. **`id_token_hint` validation** — parse and verify the ID token signature
   (reuse `oidc.JWTVerifier`); extract `sub` + `azp` (authorized party =
   `client_id`). An absent or invalid `id_token_hint` is allowed by spec but
   we SHOULD prompt for user confirmation rather than silently logging out
   (security: prevents CSRF-logout). In the initial implementation: require
   `id_token_hint` (fail with `400 invalid_request` if absent).

3. **`post_logout_redirect_uri` validation** — if provided, verify it is in
   the client's registered `logout_uris` list. Reject with `400` if it is
   not registered. Never redirect to an unregistered URI.

4. **Session termination**
   - Clear the BFF session: `BFFSessionStore.Delete(requestID)` where
     `requestID` is derived from the `sid` claim in the ID token (if present)
     or from a cookie.
   - Revoke the session's grants: call
     `SessionStore.RevokeSessionsByUserClient(ctx, userID, clientID)` to
     invalidate all refresh tokens for this user+client pair. This feeds the
     revocation outbox so existing refresh tokens become unusable.
   - Emit a `session.end` audit event (when user-audit-trail is wired).

5. **Discovery advertisement** — add `end_session_endpoint` to the
   `metadata()` function in `internal/oidcapi/discovery.go`.

6. **Front-Channel logout (Phase 2)** — embed `<img src="{logout_uri}">` tags
   for each RP with a registered `frontchannel_logout_uri` in the HTML
   logout confirmation page. Phase 1 omits this; it is noted as a follow-on.

7. **Redirect** — after termination, redirect to `post_logout_redirect_uri`
   (if registered and provided) with `state` appended, or to a default
   `{issuer}/logged-out` page.

### Cross-binary note

`end_session_endpoint` lives on `harbor-hot` (it appears in the discovery doc
which is served by `harbor-hot`). But the BFF session store lives in
`harbor-mgmt`. The cleanest approach: `harbor-hot` handles the OIDC surface
(validates `id_token_hint`, validates `post_logout_redirect_uri`, revokes the
grant via `RevokeSessionsByUserClient` which reaches the DB directly), then
redirects to the `post_logout_redirect_uri`. The BFF session cookie is
`harbor-mgmt`-scoped and is cleaned up naturally at expiry or by a
`harbor-mgmt` logout page that `post_logout_redirect_uri` points at.

## DESIGN alignment

Realises §3.3 (session termination) and §3.5 (revocation outbox for grant
invalidation). The `end_session_endpoint` is a required OIDC conformance
item. No DESIGN.md changes needed — this is wiring of existing seams.

## Target code paths

- `api/openapi/harbor.yaml` — add `GET /end_session` + `POST /end_session`
- `internal/gen/openapi/` — regenerated
- `internal/oidcapi/end_session.go` — new handler
- `internal/oidcapi/discovery.go` — add `end_session_endpoint` to `metadata()`
- `internal/oidcapi/server.go` — register handler + add `sessionStore` field
- `cmd/harbor-hot/main.go` — wire `SessionStore` into `oidcapi.Config`

## Implementation checklist

- [ ] T1: Add `GET /end_session` + `POST /end_session` to `api/openapi/harbor.yaml`; run `make codegen`
- [ ] T2: Add `end_session_endpoint` to `metadata()` in `internal/oidcapi/discovery.go`
- [ ] T3: Add `SessionRevoker` interface to `internal/oidcapi/end_session.go` (narrow interface over `SessionStore.RevokeSessionsByUserClient`)
- [ ] T4: Implement `GetEndSession` / `PostEndSession` handler:
      - Parse + validate `id_token_hint` (require it; use `oidc.JWTVerifier`)
      - Validate `post_logout_redirect_uri` against client's registered `logout_uris`
      - Call `SessionRevoker.RevokeSessionsByUserClient(ctx, userID, clientID)`
      - Redirect to `post_logout_redirect_uri?state=<state>` or default logout page
- [ ] T5: Add `SessionRevoker` field to `oidcapi.Config` + `oidcapi.Server`
- [ ] T6: Wire `DBSessionStore` (as `SessionRevoker`) in `cmd/harbor-hot/main.go`
- [ ] T7: `internal/oidcapi/end_session_test.go`:
      - Valid `id_token_hint` + registered redirect → 302 to redirect URI
      - Missing `id_token_hint` → 400
      - Unregistered `post_logout_redirect_uri` → 400
      - Valid logout → `RevokeSessionsByUserClient` called with correct (userID, clientID)
      - Missing `post_logout_redirect_uri` → redirect to default logged-out page
- [ ] T8: Update discovery test to assert `end_session_endpoint` is present
- [ ] Tests: `go build ./... && go vet ./... && go test ./...` green
- [ ] Follow-on (Phase 2): Front-Channel logout via `<img>` tags

## Risks

- **CSRF-logout** — without `id_token_hint`, any page can embed
  `<img src="/end_session">` and silently log out the user. The `id_token_hint`
  requirement in Phase 1 mitigates this; add CSRF token in Phase 2.
- **Cross-binary session scope** — BFF sessions are `harbor-mgmt`-scoped.
  Phase 1 only clears the grant (hot-path); BFF session cookie expires
  naturally or via the mgmt logout page.
- **`post_logout_redirect_uri` injection** — MUST validate against the
  registered client list; never redirect to an arbitrary provided URI.

## Definition of done

`go build/vet/test ./...` green; `GET /end_session` served on `harbor-hot`;
discovery doc advertises `end_session_endpoint`; valid logout revokes the
grant family; `post_logout_redirect_uri` is validated against registered
`logout_uris`; missing/invalid `id_token_hint` returns 400; redirect works
correctly; `make agent-check` clean.
