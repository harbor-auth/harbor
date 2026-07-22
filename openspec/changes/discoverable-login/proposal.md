# Proposal: Discoverable login (replace devUserResolver with discoverable credentials)

## Problem

The BFF login flow identifies the user via `devUserResolver`
(`cmd/harbor-mgmt/bff.go`), a DEV scaffold that decodes a base64url `user_id`
query parameter and feeds it to `BeginLogin`. The passkey assertion still must
be proven, so this is not an impersonation hole — but it cannot ship: real
users have no way to know a Harbor-internal user handle, and the conventional
replacement (an email → user lookup) is impossible by design, because Harbor's
users table deliberately stores no email (`user_id`, `region`, `dek_wrapped`,
`pairwise_secret`, `recovery_required`, `status` only). Any identifier-first
login would both violate the privacy model and open a user-enumeration
surface. Meanwhile the current `BeginLogin` path must call
`store.GetUser(userID)` *before* any authentication, forcing enumeration-
masking workarounds ("collapse to generic error").

## Proposed Solution

Use **WebAuthn discoverable credentials** (passkey autofill / conditional UI).
The user never enters an identifier: the frontend calls

```js
navigator.credentials.get({ mediation: 'conditional', publicKey: options })
```

and the browser presents stored passkeys. The WebAuthn `userHandle` is
returned **by the authenticator** in the assertion response — so the RP learns
who the user is only *after* they have cryptographically proven it.

Server-side changes:

1. **`internal/webauthn.Service`** — add a discoverable ceremony pair:

   ```go
   // BeginDiscoverableLogin starts an assertion with NO user handle and an
   // empty allowCredentials list — the authenticator chooses the credential.
   func (s *Service) BeginDiscoverableLogin(ctx context.Context) (*protocol.CredentialAssertion, string, error)

   // FinishDiscoverableLogin resolves the user from the assertion's
   // userHandle, then validates signature, challenge, and clone-detection
   // exactly as the known-user path does. Returns the authenticated handle.
   func (s *Service) FinishDiscoverableLogin(ctx context.Context, sessionKey string, body io.Reader) ([]byte, *gowebauthn.Credential, error)
   ```

   These wrap go-webauthn's discoverable-login APIs, with the user-handle →
   user lookup delegated to the existing `Store.GetUser`.

2. **`internal/bff/login.go`** — add a sentinel and resolver:

   ```go
   // ErrDiscoverable signals that no user is pre-identified: begin a
   // discoverable ceremony and take the user handle from the assertion.
   var ErrDiscoverable = errors.New("bff: discoverable login")

   type DiscoverableUserResolver struct{}

   func (DiscoverableUserResolver) ResolveUser(context.Context, *http.Request, BFFSessionRecord) ([]byte, error) {
       return nil, ErrDiscoverable
   }
   ```

   `LoginHandler.BeginLogin` treats `ErrDiscoverable` as "begin discoverable
   mode" (not an error) and calls the user-less begin. `FinishLogin` derives
   the authenticated user ID from the assertion's `userHandle` instead of a
   pre-resolved value. The `bff.WebAuthnService` interface grows the two
   discoverable methods.

3. **`cmd/harbor-mgmt/bff.go`** — delete `devUserResolver`, wire
   `DiscoverableUserResolver`, and simplify `bffWebAuthnAdapter`: its
   in-memory session-key → user-handle map exists only because the known-user
   flow needed the handle up front; in the discoverable flow the handle comes
   back from the authenticator.

No DB queries, no migrations, no `db/queries/` changes — identification is
delegated entirely to the authenticator.

## Non-Goals

- Login UI implementation (conditional-mediation feature detection, autofill
  wiring) — the frontend plan owns `isConditionalMediationAvailable` checks
  and the modal fallback; this change is server-side only.
- Account recovery for users without a discoverable passkey — owned by the
  recovery plan (`recovery_required` flag).
- Any email/username lookup, identifier-first login, or DB-backed
  `UserResolver` — explicitly rejected by the privacy model.
- Migrating pre-existing non-resident credentials to resident — audit only;
  remediation (if any is needed) is a follow-up.

## Success Criteria

- [ ] `devUserResolver` and the `user_id` query parameter are removed from
      the login path
- [ ] `BeginLogin` for a discoverable ceremony sends no user handle and an
      empty `allowCredentials` list
- [ ] A user with a registered discoverable passkey completes login with no
      identifier entry; the BFF session's user ID matches the authenticator-
      returned `userHandle`
- [ ] An assertion with an unknown or missing `userHandle` fails closed with
      a generic `authentication_failed` — indistinguishable from a bad
      signature
- [ ] Clone detection (sign-count regression → `ErrClonedAuthenticator`)
      still enforced on the discoverable path
- [ ] No new DB queries or migrations introduced
- [ ] `go build ./... && go vet ./... && go test ./...` green;
      `openspec validate discoverable-login --strict` passes
