# Spec: Public passkey-first signup and sign-in

Defines the public `/signup` and `/signin` surface at `auth.harborauth.com`,
composed entirely from shipped enrollment, WebAuthn, BFF session-binding,
recovery-required, and discoverable-login primitives. Cross-links to
`docs/design/flows/overview.md` §11.1 and `docs/design/product/trust-model.md`.

## ADDED Requirements

### Requirement: REQ-001 Public signup entry point states the privacy promise and region choice

The system SHALL serve `GET /signup` as a public, unauthenticated HTML page
presenting a truthful privacy promise and a region choice before any account
is created.

The page MUST NOT claim anonymity, third-party certification, a specific
jurisdiction's legal guarantee, or a specific data-deletion timeline unless
that claim is directly supported by shipped code or published policy. The
region choice MUST enumerate only regions `region.Parse` accepts (`eu`, `us`,
`apac`). Submitting the form MUST call the existing `POST /enroll` unmodified
(region-validated, abuse-gated) — no new enrollment code path.

#### Scenario: Signup page renders the privacy promise and region choices

**Given** an anonymous visitor with no session cookies
**When** they request `GET /signup`
**Then** the response is `200` HTML listing exactly the regions `region.Parse` accepts, with no anonymity/certification/deletion-timing claim absent from `docs/design/product/`

#### Scenario: Submitting an unsupported region is rejected before account creation

**Given** the signup form is submitted with a region string `region.Parse` rejects
**When** the client-side call reaches `POST /enroll`
**Then** the existing `400 invalid_region` response is surfaced to the user with no user row created

### Requirement: REQ-002 First passkey uses the existing enrollment-session-bound ceremony, never a client-supplied identifier

`GET /signup/passkey` SHALL drive passkey creation exclusively through the
`harbor_enrollment_session` cookie set by `POST /enroll`, using the existing
`/webauthn/register/begin` and `/webauthn/register/finish` endpoints. No new
request parameter that names the target user (e.g. `user_id`, email) SHALL be
introduced anywhere in this page or its supporting handlers.

#### Scenario: Passkey ceremony is refused without a valid enrollment session

**Given** a request to `/signup/passkey` with no `harbor_enrollment_session` cookie
**When** the page's script calls `POST /webauthn/register/begin`
**Then** the existing 501 fail-closed response is returned, unchanged from today's behavior

#### Scenario: A supplied user_id parameter is ignored on every signup route

**Given** any signup route request carrying a `user_id` query parameter or body field
**When** the request is processed
**Then** the parameter has no effect on which user's credential is created or asserted

### Requirement: REQ-003 Recovery setup is mandatory before any full-scope surface

The system SHALL require recovery setup to complete before a newly-signed-up
user can reach any route protected by `bff.RequireFullScope`, using the
existing `recovery_required` / `SessionScopeEnrollmentOnly` gate — not a new
flag.

Upon a successful first `/webauthn/register/finish`, the system MUST establish
an enrollment-only-scoped BFF session for the new user via the existing
`mgmtapi.ScopedSessionIssuer.IssueEnrollmentSession` seam (the same seam the
lost-device recovery ceremony already uses), then serve `GET /signup/recovery`
under that session. The recovery step MUST use the existing
`POST /recovery/codes` endpoint and MUST NOT clear `recovery_required` through
any path other than the one `internal/identity` and `internal/mgmtapi/recovery.go`
already implement.

```go
// Existing seam, reused (not reinvented) for the post-registration handoff:
type ScopedSessionIssuer interface {
    IssueEnrollmentSession(ctx context.Context, userID, returnTo string) (string, error)
}
```

#### Scenario: A user who skips recovery setup cannot reach the dashboard

**Given** a user who has completed `/signup/passkey` but not `/signup/recovery`
**When** they request a route protected by `RequireFullScope` (e.g. `/dashboard`)
**Then** the response is `403` with a generic "complete account setup first" message, unchanged from the existing `RequireFullScope` behavior

#### Scenario: Completing recovery setup clears recovery_required exactly once

**Given** a user in an enrollment-only-scoped session who completes the recovery-setup step correctly
**When** the step's server-side completion path runs
**Then** `users.recovery_required` becomes `false` in the database and a later `RequireFullScope` route succeeds for that user

### Requirement: REQ-004 return_to is allowlisted and never blindly reflected

The system SHALL validate any `return_to` value against a configured host
allowlist before it can appear in a redirect `Location` header, at every step
of `/signup` and `/signin`.

An unrecognized or missing `return_to` MUST fall back to a fixed same-origin
default. The validated value MUST be carried as opaque server-side session
state (not re-parsed from a client-controlled query string at each hop).

```go
// internal/bff/returnto.go
func ValidateReturnTo(raw string, allowlist []string) (string, bool)
```

#### Scenario: An unrecognized return_to host never appears in a redirect

**Given** a signup flow started with `return_to=https://evil.example/phish`
**When** the flow completes and redirects the user
**Then** the redirect target is the fixed same-origin default, never `evil.example`

#### Scenario: An allowlisted return_to is honored at signup completion

**Given** a signup flow started with `return_to` set to a host in the configured allowlist
**When** `/signup/success` completes
**Then** the success page links to that exact allowlisted URL

### Requirement: REQ-005 Pre-session state-changing routes enforce Origin/CSRF, rate limiting, and bounded bodies

Every new state-changing route introduced by this change, and `POST /enroll`,
SHALL reject cross-origin form/script submissions via an Origin /
`Sec-Fetch-Site` check, SHALL be covered by the existing distributed
rate-limit / abuse-gate pattern (`newMgmtLimiter` /
`WithProductionAbuseProtection`), and SHALL cap request body size.

This closes the existing gap where `/webauthn/register/begin|finish` and
`/webauthn/login/begin|finish` have no abuse-gate coverage.

#### Scenario: Cross-origin POST to a pre-session signup route is refused

**Given** a POST to a new signup route with an `Origin` header that does not match the serving origin
**When** the request is processed
**Then** the response is a 4xx refusal and no state-changing effect occurs

#### Scenario: WebAuthn ceremony begin endpoints are rate-limited

**Given** requests to `POST /webauthn/register/begin` exceeding the configured limiter budget from one abuse-gate key
**When** the budget is exhausted
**Then** subsequent requests receive `429` exactly as `/enroll` already does

### Requirement: REQ-006 Sign-in uses discoverable credentials with no identifier field

`GET /signin` SHALL present a passkey picker using conditional UI
(`navigator.credentials.get({ mediation: 'conditional' })`) backed by the
existing discoverable-login endpoints, with a non-conditional modal fallback
when the browser does not support conditional mediation. No email/username
input field SHALL exist on the page.

#### Scenario: Sign-in completes with no identifier entry

**Given** a user with a previously-registered discoverable passkey
**When** they complete `/signin` via the browser's passkey picker
**Then** the existing `DiscoverableUserResolver` / `FinishDiscoverableLogin` path authenticates them with no identifier ever submitted

### Requirement: REQ-007 Stable public URL contract is published

The system SHALL document a stable, versioned URL contract for `/signup` and
`/signin` (including the `return_to` and optional `region` query parameters)
that the Harbor Cloud marketing site and demo can link to without coordinating
further changes.

#### Scenario: Documented URLs resolve as specified

**Given** the published URL contract lists `GET /signup`, `GET /signup?return_to=<allowlisted-url>`, and `GET /signin?return_to=<allowlisted-url>`
**When** each is requested against a running `harbor-mgmt`
**Then** each returns `200` HTML matching the documented behavior, with no undocumented required parameter
