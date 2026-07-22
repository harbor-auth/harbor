# Design: Discoverable login (replace devUserResolver with discoverable credentials)

## Key Decisions

### Decision 1: Discoverable credentials instead of an identifier-first lookup

**Chosen:** The production login flow is a WebAuthn discoverable-credential
ceremony: no identifier field, `mediation: 'conditional'` on the frontend,
user handle returned by the authenticator in the assertion.

**Rationale:** Harbor stores no email or username — there is literally nothing
to look a user up by, and adding such a column would break the privacy model
and create an enumeration index. Discoverable credentials make the problem
disappear: the authenticator *is* the user directory, and Harbor learns the
user's identity only alongside cryptographic proof of it. This also removes
the enumeration side-channel inherent in identifier-first flows (BeginLogin
can no longer reveal whether a user exists, because it takes no user).

**Alternatives considered:** Email → user_id lookup table (rejected: PII in
the DB, enumeration surface, contradicts the schema's deliberate design);
opaque username chosen at enrollment (rejected: still an enumeration surface,
poor UX, and users forget non-email identifiers); keeping the `user_id` query
param behind auth (rejected: circular — you need to be logged in to log in).

### Decision 2: ResolveUser signals discoverable mode via a sentinel error

**Chosen:** Keep the `bff.UserResolver` interface unchanged. Add
`ErrDiscoverable`; `DiscoverableUserResolver.ResolveUser` returns
`(nil, ErrDiscoverable)`, and `LoginHandler.BeginLogin` branches on
`errors.Is(err, ErrDiscoverable)` into the user-less begin path.

**Rationale:** The interface is already deployed and other resolvers
(enrollment sessions, future step-up flows) may still pre-identify a user, so
the seam must express both "here is the user" and "no user — go
discoverable." A sentinel error does that without an interface change,
follows the package's existing pattern (`ErrUserNotIdentified`), and keeps
`nil`-handle ambiguity out of the happy path (a `nil, nil` return would be an
easy-to-miss contract).

**Alternatives considered:** Returning `(nil, nil)` to mean discoverable
(rejected: silent contract, easy to misimplement); a second interface method
`Mode()` (rejected: breaks existing implementors for no gain); deleting
`UserResolver` entirely (rejected: known-user assertion remains useful for
re-auth/step-up where the session already knows the user).

### Decision 3: User resolution happens in FinishLogin, from the assertion's userHandle

**Chosen:** `FinishDiscoverableLogin` extracts `userHandle` from the parsed
assertion response, loads the user via `Store.GetUser(userHandle)`, and only
then validates the assertion (challenge, signature, sign-count). BeginLogin
performs no user lookup at all.

**Rationale:** This is the WebAuthn-specified discoverable flow: the RP
cannot know the user before the authenticator answers. Deferring `GetUser`
until after the assertion arrives means a user lookup is only ever performed
on data signed by an authenticator, and a failed lookup collapses into the
same generic `authentication_failed` as a bad signature — no oracle.

**Alternatives considered:** Calling `ResolveUser` after FinishLogin
(rejected: the resolver has nothing request-side to resolve from; the handle
is inside the assertion, which the webauthn service already parses — routing
it back out through the resolver adds a lap for nothing).

### Decision 4: New Service methods rather than overloading BeginLogin(nil)

**Chosen:** Add explicit `BeginDiscoverableLogin` / `FinishDiscoverableLogin`
to `internal/webauthn.Service` (and mirror them on `bff.WebAuthnService`),
instead of making `BeginLogin(ctx, nil)` mean "discoverable."

**Rationale:** `BeginLogin(nil)` would make a nil slice semantically load-
bearing and would push a mode-switch into every existing caller and test.
Separate methods make the two ceremonies (known-user vs discoverable)
independently testable, let the discoverable finish return the resolved user
handle (a signature the known-user finish doesn't need), and map cleanly onto
go-webauthn's own split API for discoverable logins.

**Alternatives considered:** `BeginLogin(ctx, nil)` sentinel (rejected: nil
as API contract); a separate `DiscoverableService` type (rejected: shares
every dependency with `Service`; a type split doubles wiring for no
isolation benefit).

### Decision 5: bffWebAuthnAdapter drops its session-key → handle map

**Chosen:** In `cmd/harbor-mgmt/bff.go`, the adapter's `byKey` map (which
memorized the user handle between begin and finish) is removed for the
discoverable path; `FinishDiscoverableLogin` returns the handle from the
assertion, and the adapter base64url-encodes it as the BFF session user ID.

**Rationale:** The map existed only because `webauthn.Service.FinishLogin`
demanded the user handle up front. It was also a correctness liability: an
in-process map breaks under multi-replica deployment and leaks entries on
abandoned ceremonies. The discoverable flow eliminates the need — the
authenticator supplies the handle — making the adapter stateless.

**Alternatives considered:** Keeping the map for a retained known-user path
(deferred: if re-auth flows later need it, the handle belongs in the
persisted ceremony `SessionData`, not an in-memory map).

### Decision 6: No DB changes; registration must produce resident credentials

**Chosen:** Zero migrations and zero new queries. As part of this change,
audit registration options to ensure `residentKey: required` (and
`requireResidentKey` for L2 compat) so newly enrolled passkeys are
discoverable; existing platform passkeys are resident by default on all major
platforms.

**Rationale:** The whole design premise is that no server-side lookup is
needed pre-authentication; adding DB surface would reintroduce the seam this
change removes. The residency requirement is the one registration-side
precondition for the flow to work, so it is verified here rather than assumed.

**Alternatives considered:** A `resident` flag column on credentials for
auditability (rejected: authenticator-reported residency is not reliably
observable at registration time across all authenticators; the flag would be
best-effort metadata driving no behavior).
