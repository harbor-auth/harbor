---
title: Discoverable login (replace devUserResolver with discoverable credentials)
status: draft
design_refs: [§3.1, §6.5, §9, §11.1]
targets: [internal/bff/, internal/webauthn/, cmd/harbor-mgmt/]
promoted_to: null
openspec: changes/discoverable-login
created: 2026-07-22
---

# Discoverable login (plan)

> **Dependency order:** depends on the landed BFF login flow
> (`bff-session-middleware`) and the WebAuthn ceremony service. No DB or
> migration dependencies — this plan deliberately adds **no** user lookup.
> Can land in parallel with `token-introspection`; blocks nothing but should
> land before any public-facing login UI ships, because the current
> `devUserResolver` accepts a client-supplied `user_id` query parameter.

## Problem

The BFF login flow currently identifies the user via `devUserResolver` in
`cmd/harbor-mgmt/bff.go`: a DEV scaffold that reads a base64url `user_id`
query parameter and hands it to `BeginLogin`. The passkey assertion still has
to be proven, so it is not an impersonation hole — but it is unshippable:

1. **It requires the client to know a Harbor-internal user handle.** Real
   users have no way to obtain or supply one.
2. **The obvious "fix" — an email → user_id lookup — is impossible by
   design.** Harbor's users table stores no email (only `user_id`, `region`,
   `dek_wrapped`, `pairwise_secret`, `recovery_required`, `status`). Adding an
   email lookup would break the privacy model and create a user-enumeration
   surface.
3. **Pre-identifying the user before the ceremony is unnecessary.** WebAuthn
   discoverable credentials (passkeys) return the user handle FROM the
   authenticator in the assertion response — the RP never needs to ask "who
   are you?" before asking "prove it."

## Proposed approach

Adopt **WebAuthn discoverable credentials** (passkey autofill / conditional
UI) as the production login flow:

1. **Frontend** uses `navigator.credentials.get({ mediation: 'conditional' })`
   — the browser surfaces stored passkeys in the autofill UI; the user picks
   one; no identifier field exists at all.

2. **BeginLogin goes user-less.** For a discoverable ceremony the RP does NOT
   pre-specify the user: `internal/webauthn.Service` gains a
   `BeginDiscoverableLogin(ctx)` path that calls the go-webauthn engine's
   discoverable variant (no user, empty `allowCredentials`). The challenge
   session is stored exactly as today.

3. **The user handle arrives in the assertion.** In `FinishLogin`, the
   authenticator's response carries `userHandle`. The service resolves the
   user + credential from that handle (discoverable finish variant), then
   runs the same validation: signature, challenge, sign-count/clone check.

4. **UserResolver signals discoverable mode.** Introduce
   `DiscoverableUserResolver` in `internal/bff` whose `ResolveUser` returns a
   sentinel `ErrDiscoverable` (alternatively a `nil` handle). `LoginHandler.
   BeginLogin` treats that sentinel as "begin a discoverable ceremony" instead
   of an error, calling the user-less begin path. `FinishLogin` then derives
   the authenticated user ID from the assertion's user handle rather than the
   pre-resolved one.

5. **Swap the wiring.** `cmd/harbor-mgmt/bff.go` replaces `devUserResolver`
   with `DiscoverableUserResolver`; the `bffWebAuthnAdapter`'s
   session-key → user-handle map is no longer needed for the discoverable
   path (the handle comes back from the authenticator, not from memory).

**No DB work.** No `db/queries/` changes, no migrations, no user lookup of any
kind — the entire point is that identification is delegated to the
authenticator.

## DESIGN alignment

- §3.1 (passkey-first authentication) — discoverable credentials are the
  intended end-state of passkey login; this completes it.
- §9 / §11.1 (no client-supplied user identity seams) — removes the last
  client-supplied `user_id` parameter from the login path, closing the same
  class of seam `internal/webauthn/handlers.go` already refuses with 501.
- §6.5 (no enumeration) — a user-less BeginLogin cannot leak whether a user
  exists, eliminating the "generic error on unknown user" workaround in the
  current BeginLogin path.
- Privacy model — preserves "no email in users table"; no new PII, no new
  lookup index.

## Target code paths

- `internal/webauthn/service.go` — `BeginDiscoverableLogin` /
  `FinishDiscoverableLogin` (wrapping go-webauthn's discoverable APIs);
  user-handle-keyed credential lookup on finish
- `internal/webauthn/store.go` — credential lookup by user handle (existing
  `GetUser` suffices if the assertion's `userHandle` IS the stored handle)
- `internal/bff/login.go` — `ErrDiscoverable` sentinel;
  `DiscoverableUserResolver`; discoverable branch in `BeginLogin`; derive
  user ID from assertion `userHandle` in `FinishLogin`
- `internal/bff/` — extend `WebAuthnService` interface with the discoverable
  begin/finish methods
- `cmd/harbor-mgmt/bff.go` — replace `devUserResolver` with
  `DiscoverableUserResolver`; simplify `bffWebAuthnAdapter` (drop the
  in-memory session-key → handle map for the discoverable path)

## Implementation checklist

- [ ] `@openspec new discoverable-login` — draft the paired OpenSpec change
- [ ] Add `BeginDiscoverableLogin` / `FinishDiscoverableLogin` to
      `internal/webauthn.Service` using go-webauthn's discoverable-credential
      APIs
- [ ] Add `ErrDiscoverable` + `DiscoverableUserResolver` to `internal/bff`
- [ ] Extend `bff.WebAuthnService` interface; add discoverable branch to
      `LoginHandler.BeginLogin`; resolve user from assertion `userHandle` in
      `FinishLogin`
- [ ] Rewire `cmd/harbor-mgmt/bff.go`: delete `devUserResolver`, wire
      `DiscoverableUserResolver`, adapt `bffWebAuthnAdapter`
- [ ] Verify registration marks credentials resident/discoverable
      (`residentKey: required` in creation options) so newly enrolled
      passkeys are usable in this flow
- [ ] Tests: discoverable begin has no `allowCredentials` and no user handle;
      finish resolves the right user from `userHandle`; unknown handle fails
      closed with a generic error; clone detection still enforced; `user_id`
      query param is ignored
- [ ] `go build/vet/test ./...` green; `openspec validate discoverable-login
      --strict`
- [ ] Reconcile & promote: `@plan promote discoverable-login`

## Risks & open questions

- **Pre-resident-key credentials.** Passkeys registered before
  `residentKey: required` was enforced may be non-discoverable; those users
  cannot log in via conditional UI. Mitigation: registration already creates
  passkeys (client-side discoverable by default on all major platforms);
  audit the registration options and, if needed, keep the non-discoverable
  code path callable behind a feature flag during transition (dev-only).
- **go-webauthn API surface.** The discoverable flow uses
  `BeginDiscoverableLogin` / `FinishPasskeyLogin`-style APIs with a
  user-handle → user callback; confirm the pinned library version's exact
  signatures before implementation and adapt the `Store` seam accordingly.
- **BFF adapter statefulness.** `bffWebAuthnAdapter` currently memorizes the
  user handle between begin and finish; the discoverable path removes the
  need but the map must remain for any retained non-discoverable path —
  decide whether to delete it outright (preferred: delete, single flow).
- **Frontend conditional-UI support.** `mediation: 'conditional'` requires a
  browser support check (`PublicKeyCredential.isConditionalMediationAvailable`);
  the fallback is modal (non-conditional) discoverable login — same server
  flow, different mediation. No server-side change needed, but document it
  for the UI plan.

## Definition of done

`go build/vet/test ./...` green; `devUserResolver` and the `user_id` query
parameter are gone from the login path; a user with a discoverable passkey
completes login with no identifier entry; unknown/invalid user handles fail
closed with generic errors; clone detection preserved; no new DB queries or
migrations; `make agent-check` clean.
