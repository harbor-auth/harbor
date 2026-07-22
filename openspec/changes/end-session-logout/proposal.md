# Proposal: End-session / RP-Initiated Logout

## Problem

Harbor has no `end_session_endpoint`. RPs cannot terminate a Harbor session on
behalf of a user. The discovery document does not advertise the endpoint, so
compliant OIDC libraries cannot discover logout. `BFFSessionStore.Delete()` and
`RevokeSessionsByUserClient()` exist but are never called on user-initiated logout.

## Proposed Solution

Add `GET /end_session` (and `POST /end_session`) on `harbor-hot`, OpenAPI-first:

1. **Contract** — `GET /end_session?id_token_hint=<token>&post_logout_redirect_uri=<uri>&state=<state>`
2. **`id_token_hint` required** (Phase 1) — validates the ID token signature;
   extracts `sub` + `azp` to identify user + client.
3. **`post_logout_redirect_uri` validation** — must be in the client's
   registered `logout_uris`; reject with 400 otherwise.
4. **Grant revocation** — `SessionStore.RevokeSessionsByUserClient(ctx, userID, clientID)` feeds the revocation outbox.
5. **Discovery** — add `end_session_endpoint` to `GetOpenIDConfiguration`.
6. **Redirect** — to `post_logout_redirect_uri?state=<state>` or default logout page.

## Non-Goals
- Front-Channel logout `<img>` tags (Phase 2)
- BFF session cookie cleanup from harbor-hot (BFF is harbor-mgmt scoped; cookie expires naturally)
- CSRF token on logout form (Phase 2, alongside front-channel)

## Success Criteria
- [ ] Discovery doc advertises `end_session_endpoint`
- [ ] Valid logout revokes grant family
- [ ] Redirect validated against registered `logout_uris`
- [ ] Missing/invalid `id_token_hint` → 400
- [ ] `go build/vet/test ./...` green
