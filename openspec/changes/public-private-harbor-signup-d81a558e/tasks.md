# Tasks: Public passkey-first signup and sign-in

> Change: `public-private-harbor-signup-d81a558e`

## Prerequisites

- [ ] `internal/mgmtapi/enroll.go` — `POST /enroll` exists, region-validated, abuse-gated
- [ ] `internal/webauthn/handlers.go` — `/webauthn/register|login/begin|finish` exist, enrollment-session-cookie bound
- [ ] `internal/mgmtapi/recovery.go` + `internal/identity/recovery.go` — recovery codes, `recovery_required` gate exist
- [ ] `internal/bff/middleware.go` — `RequireFullScope`, `RequireEnrollmentAllowed`, `SessionScopeEnrollmentOnly` exist
- [ ] `internal/bff/login.go` — `DiscoverableUserResolver`, `BeginDiscoverableLogin`/`FinishDiscoverableLogin` exist
- [ ] `internal/bff/dashboard.go` + `web/templates/` — the `html/template` HTML-serving pattern to follow
- [ ] `cmd/harbor-mgmt/caller.go` — `recoverySessionIssuer` / `ScopedSessionIssuer` exist

## No DB migrations

This change adds no table and no column — it composes existing enrollment,
WebAuthn, recovery, and session state. If implementation discovers a genuine
need for new persisted state, stop and re-plan rather than smuggling in a
migration.

## Implementation

### 1. Harden the public surface: Origin/CSRF, rate limiting, return_to allowlist

- [ ] `internal/bff/csrf.go`: factor `DashboardCSRF`'s Origin/`Sec-Fetch-Site` check into a reusable pre-session variant; apply it to `POST /enroll` and every new signup POST route
- [ ] `internal/bff/returnto.go` (new): `ValidateReturnTo(raw string, allowlist []string) (string, bool)`; carries the validated value as opaque server-side session state, never re-parsed from the client at each hop
- [ ] `cmd/harbor-mgmt/main.go`: extend `newMgmtLimiter` / `WithProductionAbuseProtection` coverage to `/webauthn/register/begin`, `/webauthn/register/finish`, `/webauthn/login/begin`, `/webauthn/login/finish` (currently uncovered)
- [ ] Bound every new route's request body (mirror `maxEnrollBody` in `internal/mgmtapi/enroll.go`)
- [ ] Tests: cross-origin POST refused; rate limit exhausted on WebAuthn begin endpoints returns 429; unrecognized `return_to` never appears in a `Location` header; allowlisted `return_to` is honored

### 2. `/signup` — privacy promise, region choice, first passkey

- [ ] `web/templates/signup.html`, `web/templates/signup_passkey.html` (new, `html/template`, matching `dashboard.html`'s structure/escaping)
- [ ] New handler (e.g. `internal/bff/signup.go`, mirroring `DashboardHandler`'s shape): `GET /signup`, `GET /signup/passkey`
- [ ] Copy fact-checked against `docs/design/product/trust-model.md` + `privacy-positioning.md` — no anonymity/certification/geography/deletion-timing claims not already supported
- [ ] Region choice restricted to what `region.Parse` accepts; form submission calls existing `POST /enroll` unmodified
- [ ] `/signup/passkey` JS calls existing `/webauthn/register/begin|finish` using the `harbor_enrollment_session` cookie; `navigator.credentials.create()`, `residentKey: required` already enforced server-side
- [ ] Semantic HTML, labelled form fields, visible focus states, keyboard-operable passkey button (accessibility)
- [ ] Wire routes in `cmd/harbor-mgmt/main.go`
- [ ] Tests: region rendering matches `region.Parse`; `/webauthn/register/begin` without enrollment cookie still 501s (unchanged); no `user_id` parameter accepted anywhere on these routes

### 3. Post-registration handoff + mandatory recovery setup

- [ ] `cmd/harbor-mgmt/caller.go` / `internal/mgmtapi`: invoke the existing `ScopedSessionIssuer.IssueEnrollmentSession` right after a user's first successful `/webauthn/register/finish` (today only fires from `PostRecoveryBegin`/`PostRecoveryComplete`) — reuse the seam, do not add a second session type
- [ ] Confirm (read `internal/identity/recovery.go` + its tests, `internal/webauthn/service.go`'s `FinishRecoveryRegistration`) the **exact existing mechanism** that clears `recovery_required`, and wire `/signup/recovery` to that mechanism only — do not invent a new one
- [ ] `web/templates/signup_recovery.html` (new): generate + display recovery codes once via existing `POST /recovery/codes`; require explicit user confirmation before proceeding
- [ ] `GET /signup/recovery` served under `RequireEnrollmentAllowed`; anything beyond it requires `RequireFullScope`
- [ ] Tests: a user who has registered a passkey but not completed recovery setup is refused by `RequireFullScope` routes (403, generic message); completing recovery setup clears `recovery_required` in the DB and unlocks `RequireFullScope`; recovery codes are never logged, never shown twice

### 4. `/signup/success` — completion and safe return-to

- [ ] `web/templates/signup_success.html` (new)
- [ ] Handler requires a full-scope session (post-recovery); renders the `return_to` link produced by task 1's allowlist validator, or the same-origin default
- [ ] Emit signup-lifecycle audit events (`signup.enrolled`, `signup.passkey_registered`, `signup.recovery_completed`) via the existing `identity.AuditRecorder`, matching the audit-trail conventions already used elsewhere
- [ ] Tests: success page is unreachable without a full-scope session; audit events appear in the user's own audit trail with no PII beyond what existing audit events already carry

### 5. `/signin` — discoverable-credential sign-in entry point

- [ ] `web/templates/signin.html` (new): conditional-UI passkey picker (`navigator.credentials.get({ mediation: 'conditional' })`) with a modal fallback when unsupported; no identifier field
- [ ] Handler: `GET /signin`, wired to the existing `GET /login` / `POST /login/complete` (`DiscoverableUserResolver`) unmodified
- [ ] Wire route in `cmd/harbor-mgmt/main.go`; apply task 1's `return_to` allowlist on completion
- [ ] Tests: sign-in completes with no identifier submitted anywhere; unknown/invalid credential fails closed with the existing generic error (no enumeration)

### 6. Publish the stable CTA URL contract

- [ ] New doc (e.g. `docs/design/product/signup-cta-contract.md` or an addition to `docs/README.md`'s index): documents `GET /signup`, `GET /signup?return_to=&region=`, `GET /signin?return_to=` as the stable, versioned contract for the Harbor Cloud marketing site and demo
- [ ] Cross-link from the doc to this OpenSpec change and to `deploy/README.md`'s single-host topology note

## Tests (cross-cutting)

- [ ] `e2e/signup_test.go` (new, `//go:build e2e`, following `enrollment_test.go`'s docker-compose + cookiejar pattern):
  - Happy path: `/signup` → `/signup/passkey` → `/signup/recovery` → `/signup/success`, full-scope session reachable, correct `return_to`
  - Cancellation: abandoning mid-flow (e.g. after `/enroll` but before passkey registration) leaves no usable full-scope account and no security-relevant leftover state
  - Expiry: enrollment-session cookie / ceremony session expired mid-flow fails closed with a generic error, no partial state usable
  - Replay: a captured `/webauthn/register/finish` response cannot be replayed to create a second credential from the same challenge
  - Wrong origin/RP: a ceremony attempted from an origin outside `WEBAUTHN_RP_ORIGINS` fails (existing go-webauthn validation), exercised end-to-end for the new pages
  - Recovery gating: `RequireFullScope` routes refuse a user who has not completed `/signup/recovery`
  - Concurrent sessions: two simultaneous signup attempts (or a signup racing a lost-device recovery) do not corrupt or cross-bind each other's session state

## Validation

- [ ] `gofmt -l ./internal/... ./cmd/...` — clean
- [ ] `go build ./...`
- [ ] `go vet ./...`
- [ ] `go test ./...`
- [ ] `go test -tags e2e ./e2e/...` (against `e2e/docker-compose.yml`)
- [ ] `make agent-check`
- [ ] `helm lint` / `make helm-lint` if any Helm values change (routing/ingress for the new paths)
- [ ] `openspec validate public-private-harbor-signup-d81a558e --strict`
