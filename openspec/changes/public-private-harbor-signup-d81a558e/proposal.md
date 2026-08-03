# Proposal: Public passkey-first signup for individual Private Harbor users

## Problem

Harbor's enrollment, WebAuthn, BFF session-binding, consent, recovery-required,
and discoverable-login primitives are all implemented and shipped
(`user-enrollment`, `webauthn-db-wiring`, `webauthn-session-store-ae13c126`,
`fix-bff-session-binding-baf9dff1`, `fix-bff-browser-nonce-gate-9b24a54f`,
`discoverable-login`, `user-account-recovery`, `consent-ledger`) — but there is
**no public-facing entry point** that assembles them into a usable signup
journey. `web/templates/` contains only post-login dashboard pages
(`dashboard*.html`); `POST /enroll`, `/webauthn/register/*`, `/login*`,
`/recovery/*` are JSON-only endpoints with no HTML surface, no region picker,
no CSRF/origin hardening tailored to an anonymous pre-session route, and no
documented, stable URL contract an external site can link to. An individual
user visiting `auth.harborauth.com` today has no way to create an account.

## Proposed Solution

Add server-rendered (`html/template`, matching the existing dashboard
pattern) `/signup` and `/signin` pages on `harbor-mgmt`, composed **entirely**
from existing primitives, on the single public host / path-routed topology
already established by `fix-bff-session-binding`:

1. **`/signup`** — privacy promise + region choice → `POST /enroll` (existing,
   region-validated, abuse-gated).
2. **`/signup/passkey`** — first passkey via the existing
   enrollment-session-cookie-bound `/webauthn/register/begin|finish` ceremony
   (no client-supplied `user_id`, as today).
3. **`/signup/recovery`** — mandatory recovery setup, gated by the already-shipped
   fail-closed `recovery_required` / `SessionScopeEnrollmentOnly` machinery.
   Extends `ScopedSessionIssuer.IssueEnrollmentSession` (today only invoked from
   the lost-device recovery ceremony) to also fire right after first-passkey
   registration, so a new signup lands in the *same* enrollment-only session
   type recovery already uses — one gate, not two.
4. **`/signup/success`** — concise success state + a validated `return_to`
   redirect back to the initiating site.
5. **`/signin`** — reuses the already-shipped discoverable/usernameless login
   (`bff.DiscoverableUserResolver`) behind a conditional-UI passkey picker.

Harden the newly-public surface: an Origin/`Sec-Fetch-Site` check generalized
from `internal/bff/csrf.go`'s dashboard-only pattern to pre-session routes;
distributed rate limiting / abuse-gate coverage extended to the two WebAuthn
ceremony endpoints (`/webauthn/register/begin|finish`, `/webauthn/login/begin|finish`
— currently uncovered by `WithProductionAbuseProtection`); bounded request
bodies; and a `return_to` allowlist validator that never redirects to an
unrecognized host. Publish the resulting stable URL contract for the Harbor
Cloud marketing site and demo.

No new identity system, no revived `user_id` query parameter, and no change to
region host-map routing, PPID derivation, the consent-ledger, or the shipped
C3/M2 browser-nonce gates — this is exclusively a new front door onto shipped
machinery.

## Non-Goals

- Email/SMS/social recovery (Phase 1 recovery is codes + fallback authenticator
  only, per `user-account-recovery`).
- A CAPTCHA / third-party bot-challenge vendor integration — no such dependency
  exists in the repo today; abuse defense here is distributed rate limiting +
  the existing abuse gate, extended to the newly-public routes.
- Changing region host→region routing, PPID derivation, or the OIDC
  authorize/consent flow.
- A JS framework or build pipeline — pages follow the existing `html/template`
  + vanilla JS pattern used by `web/templates/dashboard*.html`.
- Any DNS mutation or use of production credentials.

## Success Criteria

- [ ] A user with no prior Harbor account completes signup end-to-end at
      `/signup` with a passkey, is required to complete recovery setup before
      reaching any `RequireFullScope` surface, and lands on a success screen
      with a validated return-to link.
- [ ] `/signin` completes a discoverable-credential login with no identifier
      field and no `user_id` parameter anywhere in the request.
- [ ] Every new state-changing route enforces Origin/CSRF, distributed rate
      limiting, and a bounded request body; unrecognized `return_to` values are
      rejected and never redirected to (no open redirect).
- [ ] No enumeration signal (uniform errors/timing) is introduced by any new
      route.
- [ ] Privacy/consent copy makes only claims the code and
      `docs/design/product/{trust-model,privacy-positioning}.md` already
      support — no promises of anonymity, certifications, geography, or
      deletion timing.
- [ ] `go build/vet/test ./...`, `make agent-check`, and the new e2e suite
      (happy path, cancellation, expiry, replay, wrong-origin/RP, recovery
      gating, concurrent sessions) are green.
- [ ] `openspec validate public-private-harbor-signup-d81a558e --strict` passes.
