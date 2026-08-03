# Design: Public passkey-first signup

## Key Decisions

### Decision 1: Pure composition over shipped primitives — zero new identity/session machinery
**Chosen:** The signup/signin journey is a UI + wiring layer over the
already-shipped `POST /enroll`, `/webauthn/register|login/begin|finish`,
`/recovery/*`, and discoverable-login primitives. No new user table, session
type, or credential model.
**Rationale:** The feature brief explicitly forbids a parallel identity system
or reviving a client-supplied `user_id`. Every piece of the underlying ceremony
(enrollment-session cookie hand-off, `recovery_required` fail-closed gate,
`SessionScopeEnrollmentOnly`/`SessionScopeFull`, PPID derivation, browser-nonce
binding) is production-hardened already; reinventing any of it would both
duplicate work and risk regressing a fixed vulnerability class (C3 session
fixation, the WebAuthn `user_id` IDOR closed by `user-enrollment`, the
`devUserResolver` param closed by `discoverable-login`).
**Alternatives considered:** A separate "signup service" with its own session
cookie — rejected outright, this is exactly the parallel identity system the
brief prohibits.

### Decision 2: Server-rendered `html/template` pages on `harbor-mgmt`, not a new binary or SPA
**Chosen:** New pages live alongside `web/templates/dashboard*.html` and are
served by `harbor-mgmt`, following `bff.DashboardHandler`'s pattern
(`internal/bff/dashboard.go`): thin handler, `*html/template.Template`,
XSS-safe contextual escaping, no client framework.
**Rationale:** Matches the one existing HTML-serving precedent in the repo,
keeps the single-public-host / path-routed ingress topology intact (the
`fix-bff-session-binding` Decision 4 constraint: `__Host-` cookies cannot span
two hosts), and avoids a new frontend build pipeline this repo does not have.
**Alternatives considered:** A statically-hosted SPA calling Harbor as a pure
API — rejected: it would need to run on a second origin, breaking the
`__Host-` cookie model that both the enrollment-session and BFF-session cookies
depend on.

### Decision 3: Route placement — new pages on the existing `harbor-mgmt` mux
**Chosen:** `GET /signup`, `GET /signup/passkey`, `GET /signup/recovery`,
`GET /signup/success`, `GET /signin` register on the same
`mux *http.ServeMux` in `cmd/harbor-mgmt/main.go` as `/enroll`, `/webauthn/*`,
`/login*` — i.e., the same host that already carries the enrollment-session and
BFF-session cookies. No new listener, no new host.
**Rationale:** Consistent with the documented single-host topology
(`deploy/README.md`, per `fix-bff-session-binding`); a second host would 404
exactly the way the pre-fix `/authorize/complete` redirect did.

### Decision 4: Extend `ScopedSessionIssuer` to fire after first-passkey registration, not just lost-device recovery
**Chosen:** `cmd/harbor-mgmt/caller.go`'s `recoverySessionIssuer` (today wired
only via `mgmtapi.Server.WithScopedSessionIssuer` and invoked from
`PostRecoveryBegin`/`PostRecoveryComplete`) is also invoked once
`/webauthn/register/finish` completes a user's **first** credential — landing
the new signup user in the same `SessionScopeEnrollmentOnly` BFF session type
the recovery ceremony already produces. `/signup/recovery` then runs under
`RequireEnrollmentAllowed`, and every later `/signup/success` /
post-signup surface runs under the existing `RequireFullScope`.
**Rationale:** `recovery_required` is set `true` on every fresh enrollment
already (`internal/identity/enroll.go`); it is one fail-closed gate, not two —
signup and lost-device recovery are just two different **entry paths** into
the same gate, so they must share the same session-scope machinery rather than
bifurcate into a signup-specific "pending" state and a recovery-specific one.
**Alternatives considered:** A bespoke `signup_pending` cookie distinct from
the BFF session — rejected as the parallel-machinery pattern this feature must
avoid; it would also need its own CSRF/origin/nonce hardening instead of
inheriting the shipped BFF gates.
**Open question for implementation:** whether `recovery_required` clears on
recovery-codes generation alone or requires the same
`FinishRecoveryRegistration`-style fresh-credential step used by the
lost-device path (`internal/webauthn/service.go`) is a real design decision
that must be resolved by reading `internal/identity/recovery.go` and
`internal/mgmtapi/recovery.go`'s existing tests, not invented ad hoc — see
`tasks.md` task 3.

### Decision 5: `return_to` is an opaque, allowlisted, server-validated redirect — never blindly reflected
**Chosen:** A new `internal/bff/returnto.go` validates a `return_to`
query/state parameter against a configured host allowlist (Harbor Cloud
marketing site + demo) *before* ever appearing in a `Location` header; an
unrecognized value falls back to a fixed same-origin default. `return_to` is
carried as opaque server-side session state (bound into the same enrollment /
BFF session records already threading `request_id` and the browser nonce
through the flow) rather than round-tripped through the URL at every step.
**Rationale:** An unvalidated `return_to` is a classic open-redirect / phishing
vector, and the brief explicitly calls for "a safe return-to flow" and
"account-enumeration-resistant" behavior throughout.
**Alternatives considered:** Reflecting `return_to` verbatim through query
params at each step (rejected: reproduces the exact query-string trust problem
`fix-bff-session-binding` closed for `request_id`, just on a new parameter).

### Decision 6: Origin/CSRF hardening generalized to pre-session routes
**Chosen:** `internal/bff/csrf.go`'s `DashboardCSRF` (Origin / `Sec-Fetch-Site`
check, today applied only to authenticated dashboard POSTs) is factored into a
reusable check applied to the new pre-session POST routes, and to `POST
/enroll` itself (which currently has no such check — only the abuse gate).
**Rationale:** These routes run *before* any session cookie exists, so a
session-bound CSRF token is unavailable; an Origin/`Sec-Fetch-Site` check is
the correct primitive at this stage, matching what `csrf.go` already does for
the same threat model post-session.
**Alternatives considered:** Skipping CSRF on `/enroll` because "there's no
session yet to fix" — rejected: a cross-site-triggered enrollment still writes
a real user row and enrollment-session cookie into the victim's browser and
consumes the abuse-gate budget; low severity is not zero severity, and the
brief requires it explicitly.

### Decision 7: Abuse-gate coverage extended to the WebAuthn ceremony endpoints
**Chosen:** The Redis-backed limiter pattern already used for
`enroll`/`register`(DCR)/`mfa`/`recovery` (`newMgmtLimiter` +
`WithProductionAbuseProtection`, `cmd/harbor-mgmt/main.go`) is extended to
`/webauthn/register/begin|finish` and `/webauthn/login/begin|finish`, which
today have **no** rate-limit coverage even though they become part of the
public signup/signin surface.
**Rationale:** These four endpoints are cheap to hammer (no email, no
CAPTCHA) and now sit directly behind a public button; leaving them uncovered
while every other pre-session endpoint is gated would be the obvious gap.
**Alternatives considered:** A CAPTCHA vendor — rejected per proposal.md
Non-Goals (no such dependency exists; adding one needs production credentials
this task cannot provision).

### Decision 8: Copy is fact-checked against `docs/design/product/`, not written fresh
**Chosen:** All privacy/consent-facing copy on `/signup` and `/signin` is
written to match exactly what `docs/design/product/trust-model.md` and
`privacy-positioning.md` already claim (PPID, per-RP unlinkability, minimal
data, no ad monetization) and explicitly avoids anything those documents
flag as **not yet proven** (operator non-correlation is "attestation-dependent"
pending reproducible builds + a transparency log, §3.2.4 note; no
certification claims exist anywhere in the repo).
**Rationale:** The brief requires truthful, non-overclaiming copy; the design
docs already contain the honest, reviewed framing — copy should cite it, not
improvise.
