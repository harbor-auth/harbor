# Spec: Discoverable Login

**Change ID:** discoverable-login-0ad35f86
**Sections:** ADDED Requirements

---

## REQ-DL-001 — User-less assertion begin

**SHALL** provide a `BeginDiscoverableLogin` path in `internal/webauthn.Service`
that calls the go-webauthn `BeginDiscoverableLogin` API with no user and no
`allowCredentials`, returning a challenge suitable for passkey autofill.

**Scenario:**
```
Given a configured WebAuthn Service
When BeginDiscoverableLogin is called
Then the returned CredentialAssertion has an empty allowCredentials list
And no userHandle is embedded in the assertion options
And a session key is returned for use in FinishDiscoverableLogin
```

---

## REQ-DL-002 — User resolution from authenticator userHandle

**SHALL** provide a `FinishDiscoverableLogin` path that resolves the user
exclusively from the `userHandle` field returned by the authenticator in the
assertion response, by calling `store.GetUser(ctx, userHandle)`.

**NEVER** SHALL the server accept or use any client-supplied user identifier
during the login path after this change lands.

**Scenario:**
```
Given a valid discoverable session key stored by BeginDiscoverableLogin
And a WebAuthn assertion response containing a valid userHandle
When FinishDiscoverableLogin is called
Then the user is resolved from the store using the userHandle
And the credential signature is verified
And the session counter is updated (clone detection preserved)
And the base64url-encoded userHandle is returned as userID
```

---

## REQ-DL-003 — Unknown userHandle fails closed

**SHALL** return a generic error (indistinguishable from other ceremony
failures) when the `userHandle` in the assertion response does not correspond
to any known user.

**NEVER** SHALL the error message distinguish between "user not found" and
"bad signature" or any other ceremony failure (§6.5 — no enumeration).

**Scenario:**
```
Given a discoverable assertion response with an unknown userHandle
When FinishDiscoverableLogin is called
Then the call returns an error
And the error does not reveal whether the userHandle was valid
```

---

## REQ-DL-004 — Clone detection preserved

**SHALL** check `cred.Authenticator.CloneWarning` and fail closed with
`ErrClonedAuthenticator` when a sign-count regression is detected, identical
to the existing `FinishLogin` path.

**Scenario:**
```
Given a discoverable assertion where the authenticator's sign count has regressed
When FinishDiscoverableLogin completes signature verification
Then ErrClonedAuthenticator is returned
And store.UpdateCredential is NOT called
```

---

## REQ-DL-005 — BFF DiscoverableUserResolver sentinel

**SHALL** provide `DiscoverableUserResolver` in `internal/bff` that implements
`UserResolver` and returns `ErrDiscoverable` from `ResolveUser`.

**SHALL** cause `LoginHandler.BeginLogin` to call `BeginDiscoverableLogin`
(not `BeginLogin(userID)`) when `ResolveUser` returns `ErrDiscoverable`.

**Scenario:**
```
Given LoginHandler is wired with DiscoverableUserResolver
When BeginLogin is called
Then BeginDiscoverableLogin is called on the WebAuthnService
And no user_id is read from the request query parameters
```

---

## REQ-DL-006 — devUserResolver removed

**SHALL** remove `devUserResolver` from `cmd/harbor-mgmt/bff.go` entirely.
The `?user_id` query parameter MUST NOT influence the login path.

**Scenario:**
```
Given the production login handler wired with DiscoverableUserResolver
When a request arrives with ?user_id=<anything>
Then the query parameter is ignored
And the discoverable ceremony proceeds normally
```

---

## REQ-DL-007 — Resident key required for new registrations

**SHALL** pass `WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired)`
to `BeginRegistration` so newly enrolled passkeys are client-side discoverable.

**Scenario:**
```
Given BeginRegistration is called
Then the returned CredentialCreation options include residentKey: "required"
And requireResidentKey is true
```
