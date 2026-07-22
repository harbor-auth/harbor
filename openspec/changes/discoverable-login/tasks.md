# Tasks: Discoverable login (replace devUserResolver with discoverable credentials)

## Prerequisites

- [ ] Confirm the pinned go-webauthn version's discoverable-login API
      signatures (`BeginDiscoverableLogin` / discoverable finish variant with
      a user-handle → user callback) and note any `Store` seam adaptation
      needed
- [ ] Audit registration creation options: verify `residentKey: required`
      (and `requireResidentKey` for WebAuthn L2 compat) so newly enrolled
      passkeys are discoverable; fix registration options if not
- [ ] Confirm the stored WebAuthn user handle is exactly what registration
      wrote as `user.id` (i.e. the assertion's `userHandle` round-trips to
      `Store.GetUser`)

## Implementation

- [ ] `internal/webauthn/service.go`:
  - [ ] `BeginDiscoverableLogin(ctx) (*protocol.CredentialAssertion, string,
        error)` — no user handle, empty `allowCredentials`; persist the
        ceremony session under a fresh key exactly like `BeginLogin`
  - [ ] `FinishDiscoverableLogin(ctx, sessionKey, body) ([]byte,
        *gowebauthn.Credential, error)` — parse the assertion, resolve the
        user from its `userHandle` via `Store.GetUser`, validate
        (challenge/signature/origin), enforce `CloneWarning` →
        `ErrClonedAuthenticator`, persist the advanced sign count via
        `Store.UpdateCredential`, return the authenticated handle
  - [ ] Missing/empty/unknown `userHandle` → generic validation error (no
        distinct "user not found" — same enumeration posture as `writeError`)
- [ ] `internal/bff/login.go`:
  - [ ] Add `ErrDiscoverable` sentinel and `DiscoverableUserResolver`
        (returns `nil, ErrDiscoverable`) with a compile-time
        `var _ UserResolver` assertion
  - [ ] Extend the `WebAuthnService` interface with
        `BeginDiscoverableLogin` / `FinishDiscoverableLogin`
  - [ ] `LoginHandler.BeginLogin`: on `errors.Is(err, ErrDiscoverable)`,
        call `BeginDiscoverableLogin` instead of erroring; cookie handling
        unchanged
  - [ ] `LoginHandler.FinishLogin` / `FinishLoginWithParsedData`: complete
        via the discoverable finish; write the authenticator-derived user ID
        to the BFF session via `SetUser`
- [ ] `cmd/harbor-mgmt/bff.go`:
  - [ ] Delete `devUserResolver`; wire `bff.DiscoverableUserResolver` into
        `NewLoginHandler`
  - [ ] Implement the discoverable methods on `bffWebAuthnAdapter`
        (base64url-encode the returned handle as the BFF user ID); remove
        the `byKey` session-key → handle map and its mutex
- [ ] Grep-verify no remaining `user_id` query-parameter reads on the login
      path
- [ ] `go build ./...` and `go vet ./...` clean

## Tests

- [ ] `BeginDiscoverableLogin` returns options with empty `allowCredentials`
      and no user handle; a ceremony session is persisted
- [ ] Full discoverable round-trip (fake store + fake engine seam): finish
      resolves the correct user from `userHandle` and the BFF session user ID
      equals the base64url handle
- [ ] Assertion with unknown `userHandle` → `401 authentication_failed`,
      byte-identical to the bad-signature response
- [ ] Assertion with missing/empty `userHandle` → same generic failure
- [ ] Sign-count regression on the discoverable path →
      `ErrClonedAuthenticator`, counter NOT persisted
- [ ] Ceremony session single-use: replaying the same `sessionKey` fails
- [ ] `LoginHandler.BeginLogin` with `DiscoverableUserResolver` ignores any
      `user_id` query parameter entirely
- [ ] `DiscoverableUserResolver` returns `ErrDiscoverable` regardless of
      request contents
- [ ] Non-discoverable resolvers (returning a handle) still drive the
      known-user path unchanged (regression)

## Validation

- [ ] `go test ./...` green
- [ ] `openspec validate discoverable-login --strict` passes
- [ ] `make agent-check` clean
- [ ] Manual smoke: enroll a passkey, open the login page, complete login via
      passkey autofill (conditional UI) with no identifier entered; verify
      the BFF session carries the correct user and `/authorize/complete`
      redirect fires
- [ ] Confirm no new rows in `db/queries/` and no migration files in the diff
- [ ] Update `docs/plans/discoverable-login.md` checklist; promote via
      `@plan promote discoverable-login`
