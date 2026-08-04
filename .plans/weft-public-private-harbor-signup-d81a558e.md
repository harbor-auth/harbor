# Harden public signup/login surface: Origin/CSRF, WebAuthn rate limiting, return_to allowlist

1. Factor `DashboardCSRF`'s Origin/`Sec-Fetch-Site` check in `internal/bff/csrf.go` into a shared `requireSameOriginPOST` helper, exposing a new `PreSessionCSRF` middleware for POST routes that run before any session cookie exists.
2. Add `internal/bff/returnto.go` with `ValidateReturnTo(raw string, allowlist []string) (string, bool)`: accepts same-origin relative paths and allowlisted `https://` hosts, rejects everything else (foreign hosts, insecure/opaque schemes, backslash/CRLF obfuscation) back to a fixed same-origin default.
3. Apply the Origin/CSRF check directly to `POST /enroll` in `internal/mgmtapi/enroll.go`. Since `internal/bff` already imports `internal/mgmtapi` (dashboard handler), `mgmtapi` cannot import `bff` without a cycle — duplicate the small check as `checkPreSessionOrigin`, matching the existing `enrollmentCookieName` duplication precedent in `internal/webauthn`.
4. In `cmd/harbor-mgmt/main.go`, replace the unprotected `webauthnHandler.RegisterRoutes(mux)` call with four explicit route registrations for `/webauthn/register/begin|finish` and `/webauthn/login/begin|finish`, each wrapped in a new `wrapPreSessionRoute` helper composing `bff.PreSessionCSRF` + a per-route Redis-backed abuse limiter (`newMgmtLimiter`) + a bounded body (`maxWebauthnCeremonyBody`, mirroring `maxEnrollBody`).
5. Add unit tests: `internal/bff/csrf_test.go` (PreSessionCSRF), `internal/bff/returnto_test.go` (ValidateReturnTo, including a dedicated "unrecognized value never echoed" regression test), `internal/mgmtapi/enroll_test.go` (cross-site/cross-origin POST /enroll rejected with no state change, rate-limit-after-CSRF-pass), and `cmd/harbor-mgmt/webauthn_route_test.go` (wrapPreSessionRoute CSRF-before-rate-limit ordering, 429 on exhaustion, remoteAddrKey hashing) plus a source-level graph-wiring guard in `main_test.go`.
6. Run `go build ./...`, `go vet ./...`, `go test ./...`, `gofmt -l .`, and `make agent-check` (golangci-lint fails in this sandbox on a pre-existing Go-toolchain-version mismatch, confirmed identical on the unmodified branch — not introduced by this change).

## Task 2: GET /signup and GET /signup/passkey

1. Add `internal/bff/signup.go` with `SignupHandler` (mirrors `DashboardHandler`'s shape but pre-session — no auth middleware, no CSRF on its own GET-only routes since it mutates nothing). `NewSignupHandler(tmpl, logger)` requires a non-nil template. `Routes(mux)` registers `GET /signup` and `GET /signup/passkey`.
2. `GET /signup` renders `signup.html` with a region picker built from `allowedSignupRegions()` — a small candidate list (`EU`/`US`/`APAC`) filtered through `region.Parse` so a code region.Parse stops accepting silently drops off the picker instead of rendering a value the backend would reject.
3. `GET /signup/passkey` renders `signup_passkey.html`, static (no template data) — its vanilla JS drives `navigator.credentials.create()` against the existing `POST /webauthn/register/begin` / `finish`, relying solely on the `harbor_enrollment_session` cookie set by `POST /enroll`. No `user_id`/email parameter anywhere.
4. `web/templates/signup.html`: privacy promise copy sourced from `docs/design/product/trust-model.md` §2.1 (no profile-building, no persistent cross-RP correlation, PPID per-RP, user-owned audit log) — no anonymity/certification/deletion-timing claims. Region fieldset with radio inputs. Form JS POSTs JSON to `/enroll` (`credentials: 'same-origin'`), then navigates to `/signup/passkey` on success.
5. `web/templates/signup_passkey.html`: base64url encode/decode helpers + WebAuthn ceremony JS matching `go-webauthn` v0.17.4's `protocol.CredentialCreation`/`CredentialCreationResponse` JSON shapes (`publicKey.challenge`, `publicKey.user.id`, `excludeCredentials[].id` as base64url in; `id`/`rawId`/`response.attestationObject`/`response.clientDataJSON` as base64url out). Keyboard-operable `<button>`, feature-detects `window.PublicKeyCredential`, handles `NotAllowedError` (cancel) distinctly from other failures. On success, navigates to `/signup/recovery` (task 3).
6. `web/templates.go`: doc-only update — `ParseDashboardTemplates` already globs `templates/*.html` so the new templates are picked up automatically; comment now notes it serves both dashboard and public signup views.
7. `cmd/harbor-mgmt/main.go`: construct `signupHandler := bff.NewSignupHandler(dashboardTemplates, logger)` and call `signupHandler.Routes(mux)` alongside the existing `dashboardHandler.Routes(mux)`.
8. Tests in `internal/bff/signup_test.go`: nil-template rejection, region-picker filtering (both "all accepted candidates render" and "an unaccepted candidate is dropped"), no `user_id` echoed, passkey page drives the begin/finish endpoints, both routes wired on a fresh mux.
9. Verified: `go build ./...`, `go vet ./...`, `gofmt -l .`, `go test ./...` (all green — includes untouched `internal/webauthn` 501-without-cookie tests). `make validate` stops at the pre-existing golangci-lint/Go-1.25 toolchain mismatch noted in task 1 — not introduced by this change.

# Task 5: Build GET /signin: discoverable-credential sign-in with no identifier field

1. Add `internal/bff/signin.go` (`SigninHandler`/`NewSigninHandler`/`ServeSignin`): a public `GET /signin?return_to=` entry point that mirrors what `internal/oidcapi/authorize.go`'s `authorizeWithBFFSession` does for the OIDC flow — mint a `BFFSessionRecord` (no `ClientID`/`RedirectURI`, this isn't an OIDC ceremony), set the browser-nonce hash + cookie, validate `return_to` once via task 1's `ValidateReturnTo`, and render `signin.html` with the resulting `request_id` and safe `return_to` embedded. `GET /login` and `POST /login/complete` (`bff.DiscoverableUserResolver`) stay completely unmodified — the page's script drives them purely via `fetch()`.
2. Add `web/templates/signin.html`: no email/username field anywhere. Feature-detects `PublicKeyCredential.isConditionalMediationAvailable`; when true, immediately calls `navigator.credentials.get({ mediation: 'conditional', ... })` in the background. A single always-visible, keyboard-operable "Sign in with a passkey" button is both the accessible entry point and the non-conditional modal fallback — necessary because with no identifier field there is no anchor element for the browser to attach a conditional-UI dropdown to. Uses `AbortController` so a button click cleanly supersedes an in-flight conditional attempt. `POST /login/complete` is called with `redirect: "manual"`; since the handler only ever 302s on success and returns plain JSON on failure, an opaque-redirect response is the success signal, and the script navigates to the pre-validated `return_to` itself rather than following the handler's (OIDC-only) `Location` target.
3. Wire `GET /signin` into `cmd/harbor-mgmt/main.go` next to the existing `/login` routes, reusing `bffStore`, `dashboardTemplates` (the embedded-FS glob already covers `signin.html`), and `bffSessionTTL`; add the `RETURN_TO_ALLOWLIST` env var (optional, comma-separated hosts) via the existing `splitAndTrim` helper.
4. Tests (`internal/bff/signin_test.go`): constructor validation; `ServeSignin` happy path (no identifier field/autocomplete in the rendered body, nonce cookie set, session created with a matching `BrowserNonceHash` and no OIDC fields); `return_to` allowlist behavior (same-origin path, allowlisted absolute host, unrecognized host silently falls back and is never echoed — accounting for `html/template`'s JS-string `/` escaping); a full discoverable sign-in completing end-to-end through the unmodified `LoginHandler` with no identifier submitted anywhere; an unknown/invalid credential failing closed with the existing generic `authentication_failed` error.
5. Run `go build ./...`, `go vet ./...`, `go test ./...`, `gofmt -l .`, and `make agent-check` (same pre-existing golangci-lint toolchain-version failure as task 1, unrelated to this change).

## Task 3: post-registration handoff + mandatory recovery-required gating

Investigation first: `internal/webauthn/service.go`'s `FinishRecoveryRegistration` is the ONLY caller of `Store.SetRecoveryComplete` — the sole code path that ever flips `users.recovery_required` to false. It is not wired to any HTTP route today (`internal/webauthn/handlers.go`'s `FinishRegistration` handler always calls `svc.FinishRegistration`, never `FinishRecoveryRegistration`) and touching that wiring is out of scope for this task's file list — a candidate follow-on task, not fixed here. Also established from `TestRecoverySessionIssuerBindsBFFAndEnrollmentRecords` (cmd/harbor-mgmt/caller_test.go) and `store_db_test.go`'s `uidBytes`: the "userID" string threaded through `bff.BFFSessionRecord.UserID` / `mgmtapi.CallerSource` / `clients.parseUUID` is always the canonical UUID text form, while the WebAuthn "user handle" bytes (`mgmtapi.EnrollmentSessionStore`) are always the raw 16-byte binary form — the two representations round-trip via `uuid.UUID(handle).String()` / `uuid.Parse(text)[:]`.

1. `cmd/harbor-mgmt/caller.go`: add `wirePostRegistrationHandoff` — wraps the *entire* existing `wrapPreSessionRoute(webauthnHandler.FinishRegistration, ...)` chain (preserving the literal substring `main_test.go`'s `TestProductionGraphWiresWebauthnCeremonyProtections` greps for) with a `postRegistrationHandoffWriter` that intercepts `WriteHeader`: on a 200 from the wrapped chain, it resolves the enrollment-session cookie's WebAuthn handle back to a canonical UUID string and calls `recoverySessionIssuer.IssueEnrollmentSession` (the exact seam `PostRecoveryComplete` already uses) before any header is flushed, setting the same `__Host-harbor-bff` + `harbor_enrollment_session` cookie pair `PostRecoveryComplete` sets. A handoff failure never turns a successful ceremony into an error response — the credential is already durably persisted by then, so the ceremony still reports success; the user just needs a fresh sign-in if the handoff itself failed. Also adds `recoveryRequirementClearer` (adapts `webauthn.DBStore.SetRecoveryComplete` via a narrow duck-typed interface — no new import), `bffSessionScopeRefresher` (adapts `bff.BFFSessionStore.SetUserWithRecoveryStatus`, previously unused by any caller), and `bffEnrollmentCallerAdapter` (resolves `bff.UserIDFromContext` WITHOUT `bffCallerAdapter`'s enrollment-only block — wired only to the two recovery-setup endpoints below, every other endpoint keeps the existing block untouched).
2. `internal/mgmtapi/recovery.go` / `server.go`: add `RecoveryRequirementClearer` and `RecoverySessionRefresher` interfaces + `enrollmentCallerSource` field/`WithEnrollmentCallerSource`. Add `recoverySessionCaller` helper (tries `callerSource` then falls back to `enrollmentCallerSource`) and switch `PostRecoveryCodes`'s userID resolution to it — additive only: `callerSource` alone still gates every other endpoint, so `TestSpoofing_HeaderPresent_NoSession`'s full `userScopedEndpoints` table is unaffected. Add `POST /recovery/acknowledge` (`PostRecoveryAcknowledge`): resolves caller the same way, calls `recoveryRequirementClearer.ClearRecoveryRequired` (DB write) then `recoverySessionRefresher.RefreshSessionScope` (live BFF session scope, so the SAME cookie now passes `RequireFullScope` with no fresh login), audit-logs `auth.recovery_succeeded`.
3. `cmd/harbor-mgmt/main.go`: wire the four new `With...` calls, share one `recoverySessionIssuer` instance between `WithScopedSessionIssuer` and `wirePostRegistrationHandoff`, and wrap the finish-registration route registration.
4. `internal/bff/signup.go`: add `GET /signup/recovery` behind `RequireEnrollmentAllowed`, rendering the new static `web/templates/signup_recovery.html`.
5. `web/templates/signup_recovery.html`: on load, POSTs `/recovery/codes` once and renders the plaintext codes (never re-fetched on the same load); a confirmation checkbox gates a "Continue" button that POSTs `/recovery/acknowledge` then navigates to `/signup/success`. Codes are never logged; nothing in the JS persists them beyond the DOM.
6. Tests: `internal/mgmtapi/recovery_test.go` (acknowledge success/unauthorized/unavailable/clearer-error/refresher-error, codes-now-succeeds-under-enrollment-only-scope), `internal/mgmtapi/caller_test.go` (`/recovery/acknowledge` added to the spoofing table), `internal/bff/signup_test.go` (route wired, renders codes-fetch + acknowledge + no user_id), `cmd/harbor-mgmt/caller_test.go` (handoff writer fires only on 200, enrollment adapter ignores scope).
7. Follow-on suggested (out of scope, filed via `weft-agent tasks suggest`): `internal/webauthn/handlers.go`'s `FinishRegistration` handler never calls `FinishRecoveryRegistration`, so the lost-device recovery ceremony's own re-enrolled passkey never actually clears `recovery_required` through that path today; and `parseUUIDToBytes`/`recoveryUserHandle`'s raw-16-byte WebAuthn handle convention is inconsistent with `store_db.go`'s `parseWebAuthnUserID` (`uuid.ParseBytes`, text-only) — worth a dedicated fix + regression test.
8. Verify: `go build ./...`, `go vet ./...`, `gofmt -l .`, `go test ./...`.

# Task 4: Build GET /signup/success: full-scope completion, audit events, and the validated return-to link

Investigation first: confirmed by repo-wide grep that `return_to` plumbing is currently a single-hop-only pattern — `internal/bff/signin.go`'s `ServeSignin` is the *only* call site of `ValidateReturnTo` today, and it validates once and renders the value straight into that same page's inline JS (`web/templates/signin.html`), because `/signin`'s whole ceremony is one page/one request with no further server round trip. `GET /signup` (task 2) never reads or validates a `return_to` query parameter at all; `POST /enroll`'s `EnrollmentSessionStore` only ever stores the raw WebAuthn user-handle bytes (no session struct, no room for a `ReturnTo` field); `BFFSessionRecord` (`internal/bff/session.go`) has no `ReturnTo` field; `ScopedSessionIssuer.IssueEnrollmentSession(ctx, userID)` and `RecoverySessionRefresher.RefreshSessionScope` have no return_to parameter; and `web/templates/signup_recovery.html`'s `window.location.assign("/signup/success")` carries nothing. So the openspec design's Decision 5 / REQ-004 intent ("carried as opaque server-side session state... bound into the same enrollment/BFF session records") is NOT wired end-to-end by tasks 1-3/5 as they stand — there is no session-state carrier available today for a `return_to` captured at `/signup` to survive the multi-page navigation all the way to `/signup/success`. Building that full carrier (a `ReturnTo` field threaded through `EnrollmentSessionStore`, `ScopedSessionIssuer`, and `BFFSessionRecord`) touches `internal/mgmtapi/session.go`, `enroll.go`, `recovery.go`, `internal/bff/session.go`, and `cmd/harbor-mgmt/caller.go` — all outside this task's file list (`web/templates/signup_success.html`, `internal/bff/signup.go`, `internal/bff/signup_test.go`, `cmd/harbor-mgmt/main.go`). Filing that as a follow-on rather than expanding scope.

Within this task's scope, `GET /signup/success` validates its own `return_to` query parameter directly against the configured allowlist — the same "validate exactly once, at the point read from the client" contract `returnto.go` documents, just applied at this page's own entry instead of an earlier hop, and matching the one existing precedent (`signin.go`) as closely as the multi-hop journey allows.

1. `internal/identity/audit.go`: add three new closed-set `EventType` consts — `EventSignupEnrolled` (`signup.enrolled`), `EventSignupPasskeyRegistered` (`signup.passkey_registered`), `EventSignupRecoveryCompleted` (`signup.recovery_completed`) — alongside the existing `auth.*`/`token.*`/`consent.*`/`compliance.*` groups.
2. `internal/bff/signup.go`: add `SignupAuditRecorder` interface (`RecordAsync(ctx, userID, identity.EventType, *string, any)`, satisfied directly by `*identity.AuditRecorder`, mirroring `mgmtapi.ConsentAuditRecorder` / `oidcapi.TokenAuditRecorder`). Extend `SignupHandler` with `audit SignupAuditRecorder` and `returnToAllowlist []string` fields; extend `NewSignupHandler`'s signature to `(tmpl *template.Template, audit SignupAuditRecorder, returnToAllowlist []string, logger *slog.Logger)` — `audit` and `returnToAllowlist` are optional (nil-tolerant, best-effort), only `tmpl` stays required. Add `GetSignupSuccess`: resolves `userID := UserIDFromContext(r.Context())` (401 if empty, same as every `DashboardHandler` read route — defence in depth alongside the route-level `RequireFullScope` gate below, since `SessionScopeFromContext` defaults to Full when no scope is in context at all); validates `return_to` via `ValidateReturnTo(r.URL.Query().Get("return_to"), h.returnToAllowlist)`; when `h.audit != nil`, fires all three `RecordAsync` calls (`clientID=nil` — no RP context at signup) exactly like `authorize.go`'s best-effort `auth.login` emission; renders `signup_success.html` with the validated `ReturnTo`. Wire `GET /signup/success` in `Routes` behind `RequireFullScope`, matching `DashboardHandler`'s `read()` composition.
3. `web/templates/signup_success.html`: static success card (matches `signup.html`/`signup_recovery.html`'s visual style) with a single link to `{{.ReturnTo}}` — no other destination is ever rendered.
4. `cmd/harbor-mgmt/main.go`: pass the already-constructed `auditRecorder` and `splitAndTrim(os.Getenv("RETURN_TO_ALLOWLIST"))` (same env var `signinHandler` already reads) into `bff.NewSignupHandler`.
5. Tests (`internal/bff/signup_test.go`): update `newTestSignupHandler`/`TestNewSignupHandler_RejectsNilTemplate` for the new constructor signature; `TestSignupHandler_SuccessRoute_RequiresFullScope` (403 for `SessionScopeEnrollmentOnly` through the mux, mirroring `TestRequireFullScope_DeniesEnrollmentOnlyScope`); `TestGetSignupSuccess_NoSessionUnauthorized` (empty context, no scope at all defaults full but no `UserID` → 401); `TestGetSignupSuccess_ReturnToAllowlisted`/`_UnrecognizedFallsBackToDefault`/`_MissingFallsBackToDefault` (link rendered exactly matches, never the rejected value); `TestGetSignupSuccess_EmitsAuditEvents` (fake `SignupAuditRecorder` capturing calls, asserts all three event types recorded for the caller's own `userID`, no PII in `detail`); `TestGetSignupSuccess_NilAuditRecorderIsGraceful` (nil audit never panics/blocks the render).
6. Follow-on suggested (out of scope, filed via `weft-agent tasks suggest`): thread `return_to` as real server-side session state end-to-end — `GET /signup?return_to=` (task 2, already "completed" but never implemented this) needs to validate-and-store it, and `EnrollmentSessionStore`, `ScopedSessionIssuer.IssueEnrollmentSession`, and `BFFSessionRecord` all need a carrier field so the value survives the `/signup` → `/signup/passkey` → webauthn ceremony → handoff → `/signup/recovery` → `/signup/success` multi-page journey without falling back to the default on every real request — today `/signup/success` can only honor a `return_to` supplied directly on its own URL, not one that started the journey at `/signup`. This is REQ-004 / design.md Decision 5's literal requirement and isn't satisfied by a single-file task.
7. Verify: `go build ./...`, `go vet ./...`, `gofmt -l .`, `go test ./...`.

## Task 6: Publish the stable CTA URL contract

Investigation confirmed `GetSignup` (`internal/bff/signup.go`) never reads its
own query string — `return_to` and `region` on `GET /signup` are accepted
(still `200`) but currently inert (region comes from the in-page form's POST
to `/enroll`; `return_to` isn't carried anywhere from this entry point, per
task 4's follow-on). The doc documents that honestly rather than asserting
the query parameters do anything today. Also found, via `deploy/contract`'s
`assertPublicLoginRoute`, that the example ingress manifests
(`deploy/k8s/ingress.yaml`, `deploy/helm/templates/ingress.yaml`) route only
`/login` to harbor-mgmt — `/signup*`, `/signin`, `/enroll`, `/webauthn/*`,
`/recovery/*` would all 404 through them today. Fixing those manifests (and
their contract test) touches files outside this task's list and has its own
test to update, so it's filed as a follow-on (`ftask_165be36d`) rather than
done here; `deploy/README.md` documents it as a known gap instead.

1. Added `docs/design/product/signup-cta-contract.md`: the versioned URL
   contract for `GET /signup`, `GET /signup?return_to=&region=`, and
   `GET /signin?return_to=` — auth, response shape, `return_to` allowlist
   semantics (`bff.ValidateReturnTo`), region-picker semantics, the
   single-host path-routed topology prerequisite, and the known
   return_to/region-on-`/signup`-is-inert gap.
2. Added `internal/bff/signup_cta_contract_test.go`: builds the real
   `SignupHandler`/`SigninHandler` on a mux the same way
   `cmd/harbor-mgmt/main.go` wires them and asserts all three published URLs
   return `200 text/html`; a second test locks in the "query params are
   inert" claim (identical body with/without them, `return_to` never echoed)
   as a regression guard for that section of the doc.
3. `docs/README.md`: added a Features-table row cross-linking the new doc,
   with a short note on why it lives under `design/product/` instead of
   `features/`.
4. `deploy/README.md`: expanded the BFF Topology ASCII diagram to list every
   harbor-mgmt-served prefix (not just `/login*`), cross-linked the new
   contract doc, and called out the ingress-manifest gap explicitly as a
   known limitation rather than leaving it undocumented.
5. Verify: `go build ./...`, `go vet ./...`, `gofmt -l .`, `go test ./...`
   (all green, including the new tests and the untouched `deploy/contract`
   suite).

# Task 12: Fix lost-device recovery register/finish (recovery_required never cleared)

Two bugs found in `internal/webauthn`/`internal/mgmtapi`/`cmd/harbor-mgmt`, both test-first (failing test added and confirmed red before the fix):

1. **`Handler.FinishRegistration` never routed to `svc.FinishRecoveryRegistration`.** The enrollment-session handoff (`EnrollmentSessionStore`) only ever carried the WebAuthn user handle, with no way to tell a lost-device recovery session (`POST /recovery/begin` → `/recovery/complete` → `register/finish`) apart from first-time enrollment (`POST /enroll` → `register/finish`) — so `register/finish` always called `svc.FinishRegistration`, and `svc.FinishRecoveryRegistration` (which clears `recovery_required`) was dead code, exercised only directly by `service_test.go`.
   - Threaded a `recovery bool` through the enrollment-session handoff end to end: `mgmtapi.EnrollmentSessionStore.Save`/`UserHandle` gained a `recovery` param/return, `RedisEnrollmentSessionStore` now stores a small JSON envelope (`{h, r}`) instead of a bare base64 string, and `webauthn.EnrollmentSessionStore.UserHandle` returns `(userID, recovery, err)`. `mgmtapi.enroll.go`'s `PostEnroll` saves `recovery=false`; `cmd/harbor-mgmt/caller.go`'s `recoverySessionIssuer.IssueEnrollmentSession` (used by `PostRecoveryComplete`) saves `recovery=true`.
   - `webauthn.Handler.FinishRegistration` now picks `svc.FinishRegistration` vs `svc.FinishRecoveryRegistration` based on that flag.
   - Regression test: `TestHandler_FinishRegistration_RecoverySession_ClearsRecoveryRequired` in `internal/webauthn/handlers_test.go` drives a full ceremony through the real go-webauthn verification path (forged ES256 "none"-attestation response via a new `forgeAttestationBody` helper in `internal/webauthn/attestation_forge_test.go`, ported from `e2e/enrollment_test.go`'s `makeAttestation`) and asserts the `InMemoryStore` observed `SetRecoveryComplete`, not just a 200 status (both the buggy and fixed paths return 200). Confirmed it failed for the right reason before the fix (temporarily hard-disabled the new branch, reran, saw the assertion fail; restored the fix).
   - Updated every `EnrollmentSessionStore` implementer for the new signatures: `mgmtapi.RedisEnrollmentSessionStore`, `mgmtapi`'s and `testsupport/mgmtapi`'s in-memory test fixtures, and `webauthn`'s `fakeEnrollmentSessionStore`; added `TestEnrollmentSession_RecoveryFlagRoundTrips` (in-memory) and `TestRedisEnrollmentSessionStore_RecoveryFlagRoundTrips` (miniredis-backed) to `internal/mgmtapi/session_test.go`.

2. **`store_db.go`'s `parseWebAuthnUserID` parsed the wrong handle representation.** `mgmtapi.parseUUIDToBytes` (POST /enroll) and `cmd/harbor-mgmt`'s `recoveryUserHandle` (POST /recovery/complete) both produce the **raw 16-byte** binary form of the user's UUID (`uuid.Parse(s); id[:]`) — confirmed as the real, pinned contract by `cmd/harbor-mgmt/caller_test.go`'s `TestRecoverySessionIssuerBindsBFFAndEnrollmentRecords`. But `store_db.go`'s `parseWebAuthnUserID` called `uuid.ParseBytes`, which only accepts the 36/32/38-character **text** form — so it silently failed (`invalidLengthError{16}` → mapped to `ErrUserNotFound`) on every real, DB-backed WebAuthn ceremony. This was masked because `store_db_test.go`'s `uidBytes` and `store_db_activate_test.go`'s `handleBytes` fixtures both (incorrectly) built text-form handles.
   - Reproduced deterministically (no live Postgres needed — same `fakeStoreQuerier`/`dbStoreQuerier` interface technique the rest of `store_db_test.go` already uses) with `TestDBStore_GetUser_ProductionHandleFormat`: confirmed it failed against the old `uuid.ParseBytes` before the fix.
   - Fixed `parseWebAuthnUserID` to `uuid.FromBytes` (raw 16-byte parse) and updated its doc comment.
   - Fixed `uidBytes`/`handleBytes` test fixtures to build raw-byte handles (matching production reality), and updated the handful of tests that inlined `[]byte(uuid.String())` directly (`TestDBStore_GetUser_NotFound`, `TestDBStore_AddCredential_UnknownUser`, `TestDBStore_UpdateCredential_CrossUserBlocked`, `TestDBStore_SetRecoveryComplete_UnknownUser`) to match.

Rebased onto Task 3's landed `wirePostRegistrationHandoff`/`recoveryRequirementClearer` work (`cmd/harbor-mgmt/caller.go`), which independently confirmed the same raw-16-byte-vs-canonical-text handle split documented above; updated its `sessions.UserHandle(...)` call site and three `Save(...)` test seeds in `caller_test.go` for the new 3-arg/3-return `EnrollmentSessionStore` signatures (all `false` — first-time-registration handoffs, not recovery sessions).

Verified: `go build ./...`, `go vet ./...`, `go test ./...` (all green, whole repo), `go test -race ./internal/webauthn/... ./internal/mgmtapi/... ./cmd/harbor-mgmt/...`, `gofmt -l` on every changed file (clean), `go mod tidy` (no drift — no new dependencies; `github.com/fxamacker/cbor/v2` used by the new test helper was already a direct `go.mod` dependency). `golangci-lint` still fails with the same pre-existing Go-1.25-vs-golangci-lint-built-with-1.24 toolchain mismatch noted in tasks 1 and 5 — unrelated to this change.

# Task 8: Add browser E2E tests: happy path, cancellation, expiry, replay, wrong origin/RP, recovery gating, concurrent sessions

Investigation first: read every signup/signin/recovery handler and its wiring line-by-line (`internal/bff/signup.go`, `signin.go`, `login.go`, `middleware.go`, `returnto.go`, `cookie.go`; `internal/mgmtapi/recovery.go`, `enroll.go`, `session.go`; `internal/webauthn/handlers.go`, `service.go`, `store_redis.go`; `cmd/harbor-mgmt/caller.go`/`main.go`) rather than trusting task-prompt paraphrase, and cross-checked against the closest existing in-process analog, `cmd/harbor-mgmt/caller_test.go`'s `TestPostRegistrationHandoffAndRecoveryGating_EndToEnd`. Two corrections to the task prompt's assumptions surfaced:

- `e2e/recovery_test.go`'s `recoveryScopedSessionCookie = "harbor_recovery_session"` constant does not match any cookie the server actually sets — the real scoped/handoff cookie is `__Host-harbor-bff` (`mgmtapi.RecoveryScopedSessionCookieName` == `bff.CookieName`). Declared a correctly-valued local constant in the new files instead of reusing the existing wrong one (left `recovery_test.go` untouched — out of this task's file scope; filed as a follow-on).
- Every cookie this system sets is `Secure: true` unconditionally (`internal/bff/cookie.go`, `internal/webauthn/handlers.go`, `internal/mgmtapi/session.go`), but `e2e/docker-compose.yml` serves harbor-mgmt over plain HTTP with no TLS. Confirmed empirically (throwaway `httptest.Server` + stdlib `cookiejar.Jar`) that Go's stdlib cookiejar's `shouldSend` rule (`https || !e.Secure`) silently drops every Secure cookie on the second hop of any `http://` request — meaning the existing `jarClient(t)` helper cannot carry a session cookie across steps on this stack, so a literal reuse of it for a multi-hop journey would make every chained assertion pass by skipping rather than by actually exercising the chain. This has never been caught because `enrollment_test.go`/`recovery_test.go`'s DB-dependent tests already skip via `openDB(t)` before reaching any multi-hop cookie chain in the `make e2e` CI profile (`HARBOR_E2E_DATABASE_URL` is unset there). Added `laxSecureCookieJar` (`e2e/signup_helpers_test.go`) — a ~30-line `http.CookieJar` that behaves like the stdlib jar but ignores the `Secure` attribute — and re-verified the fix empirically against the same throwaway harness before relying on it.

1. `e2e/signup_test.go`: package/build-tag doc comment (env vars, `laxSecureCookieJar` rationale), the shared path/cookie-name constants, and scenarios 1 (`TestSignupHappyPath_FullJourneyToSuccessWithReturnTo`: `/signup` → `/signup/passkey` → `/enroll` → first passkey → 403 pre-recovery → `/signup/recovery` → `/recovery/codes` → `/recovery/acknowledge` → 200 `/signup/success` honoring `return_to`, `recovery_required` cleared, and polling `audit_events` for the three `signup.*` event types since `RecordAsync` fires from a detached goroutine) and 2 (`TestSignupCancellation_AbandonedEnrollmentGrantsNoFullScopeAccess`: enroll, never register a passkey, assert no `__Host-harbor-bff` cookie was ever minted, `/signup/success` and `/recovery/acknowledge` both 401, DB shows `pending`/0 credentials).
2. `e2e/signup_helpers_test.go`: `laxSecureCookieJar`/`signupJarClient`/`cookieValue`/`rawRequest`; goroutine-safe plain-error counterparts of `enroll`/`generateRecoveryCodes`/`beginRecovery`/`completeRecovery` (`httpEnroll`, `httpGenerateRecoveryCodes`, `httpAcknowledgeRecovery`, `httpBeginRecovery`, `httpCompleteRecovery`) plus `driveFullSignup`, needed because `testing.T`'s `Fatal*`/`Skip*` family may only be called from the goroutine running the test — the concurrent-session tests need real overlapping requests, so their legs use these instead; `makeAttestationWithOrigin` (a parameterized-origin variant of `enrollment_test.go`'s `makeAttestation`, needed to build a wrong-origin registration response); `parseBeginRegistrationResponse`; `pollAuditEventTypes`/`hasAllEventTypes`; `credentialCount`/`userStatus`.
3. `e2e/signup_expiry_replay_test.go`: scenario 3 (`TestSignupExpiry_EnrollmentSessionFailsClosed`: forged `harbor_enrollment_session` value on `register/begin` fails closed with a generic JSON error code; `TestSignupExpiry_WebAuthnCeremonySessionFailsClosed`: valid enrollment cookie + forged `harbor_webauthn_session` on `register/finish` fails closed, DB shows `pending`/0 credentials — both simulate TTL expiry via a store-miss, since a real 10-minute/5-minute wait isn't practical in a test) and scenario 4 (`TestSignupReplay_RegisterFinishCannotMintSecondCredential`: capture the exact cookies+body of a successful `register/finish`, replay verbatim — `internal/webauthn/store_redis.go`'s `Take` is atomic GET+DEL, so the replay must fail and credential count must stay 1).
4. `e2e/signup_origin_gating_test.go`: scenario 5 (`TestSignupWrongOrigin_FailsWebAuthnValidation`: `makeAttestationWithOrigin` asserting `https://evil.example` against the real `register/begin` challenge fails go-webauthn's origin check, no partial DB state — isolates the origin check specifically, unlike `enrollment_test.go`'s existing garbage-attestation rollback test) and scenario 6 (`TestSignupRecoveryGating_FullScopeRouteRefusesUntilRecoveryComplete`: the SAME BFF cookie is 403 on `/signup/success` before `/recovery/acknowledge` and 200 immediately after, no fresh sign-in — the e2e/HTTP+DB counterpart of `caller_test.go`'s in-process unit test).
5. `e2e/signup_concurrency_test.go`: scenario 7, two variants — `TestSignupConcurrentSessions_TwoIndependentSignupsDoNotCrossBind` (two full signups via `driveFullSignup` in goroutines, assert two distinct users, each own cookie reaches its own success page, each account has exactly 1 credential) and `TestSignupConcurrentSessions_SignupRacesLostDeviceRecoveryForDifferentUser` (pre-provision user B sequentially, then race a fresh signup for user A against B's lost-device recovery ceremony, assert neither leg's `recovery_required`/credential count was affected by the other).
6. Split across 5 files (not the single `e2e/signup_test.go` the task prompt named) to respect `tools/lint/filesize`'s 500-line budget for new `_test.go` files (§1.10) — a single-file draft hit 1,114 lines. `go run ./tools/lint/filesize` confirms zero violations for the new files (the LOC check is advisory-only in `make agent-check`, but the project's own tooling doc says the correct response to a large file is to split it, not raise the limit or leave it).
7. No live `docker compose`/Postgres/Redis available in this execution environment (confirmed: no `docker`, `pg_isready`, or `redis-cli` binary, and ports 5432/6379 closed) — every new test was verified to *compile* (`go build -tags e2e ./e2e/...`, `go vet -tags e2e ./e2e/...`) and to *skip gracefully* (`go test -tags e2e ./e2e/... -run TestSignup -v`, all 9 `SKIP` with the expected "unreachable"/"DB unavailable" reasons, matching the existing package's convention) rather than being run green end-to-end against a live stack. Correctness of the HTTP/DB contracts was cross-verified by reading the actual handler/service/store source for every status code and JSON field name asserted (documented per-test in code comments with file references), not assumed from the task prompt.
8. Verify: `gofmt -l e2e/*.go` (clean), `go vet -tags e2e ./e2e/...` (clean), `go build -tags e2e ./e2e/...` (clean), `go test -tags e2e ./e2e/... -run TestSignup -v` (9/9 skip gracefully, expected reasons), `go test ./...` (whole repo, unaffected, all green), `go run ./tools/lint/filesize` (no new violations). Pre-existing `e2e` package failures (`flow_test.go`'s `TestJWKSSignatureVerification` et al., connection-refused against harbor-hot) reproduced identically on `git stash` (file is new/untracked so stash was a no-op, confirmed via `git status`) — not introduced by this change. `golangci-lint` unusable in this sandbox (Go-1.24-built binary vs module's Go 1.25), same pre-existing condition noted in every prior task on this branch.
9. Follow-ons suggested (out of scope, filed via `weft-agent tasks suggest`): (a) `internal/bff/signin.go`'s `ServeSignin` creates a `BFFSessionRecord` with no `SessionScope` set, and `LoginHandler.FinishLogin` calls `sessions.SetUser` (not `SetUserWithRecoveryStatus`) — the resulting session's `SessionScope` stays the Go zero value `""`, which fails `RequireFullScope`'s `scope != SessionScopeFull` check, so a plain returning-user sign-in via `/signin` may never reach a full-scope-gated route without an unrelated fix; (b) `e2e/recovery_test.go`'s `recoveryScopedSessionCookie` constant is wrong (see investigation note above) — low real-world impact today since the tests that use it already skip in CI, but worth fixing for when `HARBOR_E2E_DATABASE_URL` is eventually wired into `make e2e`.

# Task 14: Broaden ingress path routing for public signup/sign-in surface

`deploy/k8s/ingress.yaml` and `deploy/helm/templates/ingress.yaml` previously
routed only `/login` to `harbor-mgmt`, predating the public signup/sign-in
journey — everything else (`/signup*`, `/signin`, `/enroll`, `/webauthn/*`,
`/recovery/*`) fell through to harbor-hot's catch-all `/` and would 404, a gap
already documented in `deploy/README.md`'s BFF Topology section and
`docs/design/product/signup-cta-contract.md`.

1. Added five `pathType: Prefix` entries (`/signup`, `/signin`, `/enroll`,
   `/webauthn`, `/recovery`), each routed to `harbor-mgmt`, ahead of the
   existing catch-all `/` → `harbor-hot` rule in both `deploy/k8s/ingress.yaml`
   and `deploy/helm/templates/ingress.yaml`. Updated the top-of-file comment
   in both to describe the broadened route set instead of "only the BFF login
   paths".
2. Updated `deploy/contract/security_contract_test.go`'s `assertPublicLoginRoute`
   `want` map (shared by both `TestRawSecurityContract` and
   `TestHelmSecurityContract`) to require all six prefixes → `harbor-mgmt`/`harbor-hot`
   mappings instead of just `/login`/`/`.
3. `deploy/README.md`: removed the "Known gap" callout under BFF Topology —
   the example manifests now match the documented required prefix list, so
   the gap is closed.
4. Verify: `go build ./...`, `go vet ./...`, `gofmt -l` (clean), `go test ./...`
   (whole repo, all green, including `deploy/contract`'s raw and
   Helm-source-fallback variants). No `helm` binary available in this sandbox
   to render `HELM_RENDERED` and exercise the CI-only rendered-manifest path;
   `assertHelmSourceSecurityContract` (source-scan fallback) covers the Helm
   template directly and passed.

# Task 15: Post-registration handoff must not re-arm recovery_required after a lost-device recovery clears it

Investigation confirmed the bug is real, not intentional: `wirePostRegistrationHandoff`
(`cmd/harbor-mgmt/caller.go`) fired `ScopedSessionIssuer.IssueEnrollmentSession`
unconditionally on every 200 from `POST /webauthn/register/finish` — first-time
signup AND lost-device recovery alike — and that issuer always mints a BRAND
NEW `SessionScopeEnrollmentOnly`/`RecoveryRequired=true` BFF session. For a
recovery ceremony's own `register/finish` (`Handler.FinishRegistration` routes
to `svc.FinishRecoveryRegistration` when the enrollment session's `recovery`
flag is set — Task 12), that DB-clearing request immediately re-armed the gate
for the very session the browser was holding, sending the just-recovered user
straight back into `/signup/recovery`. This directly contradicts the
product/design intent already on record: `openspec/.../public-private-harbor-signup-d81a558e/specs/core/spec.md`
REQ-003's scenario ("`users.recovery_required` becomes `false`... and a later
`RequireFullScope` route succeeds for that user") and
`openspec/changes/user-account-recovery/specs/core/spec.md` REQ-003 ("deny
every other authenticated surface... until `recovery_required` is cleared" —
implying access resumes once it is). The `wirePostRegistrationHandoff`
code was already discarding the `recovery` bool `sessions.UserHandle` returns
(`handle, _, err := ...`) — the exact signal needed to distinguish the two
cases was sitting right there, unused.

1. Test-first: added `TestPostRegistrationHandoff_LostDeviceRecovery_DoesNotReArmRecoveryRequired`
   (`cmd/harbor-mgmt/caller_test.go`) — seeds the same enrollment-only/
   recovery-required BFF + enrollment-session pair `POST /recovery/complete`
   leaves behind (`recovery=true`), drives a simulated successful
   `register/finish` through the real `wirePostRegistrationHandoff` wired
   behind `bff.Middleware` (mirroring `TestPostRegistrationHandoffAndRecoveryGating_EndToEnd`'s
   "wired mux" pattern), and asserts the issuer is never called, no cookie is
   overwritten, and the ORIGINAL cookie passes `bff.RequireFullScope`
   immediately. Confirmed it failed for the right reason against the
   unmodified code (issuer called, dashboard route stayed 403) before fixing.
2. `cmd/harbor-mgmt/caller.go`: `wirePostRegistrationHandoff` now takes a
   `refresher mgmtapi.RecoverySessionRefresher` param and reads the `recovery`
   flag from `sessions.UserHandle`. When `recovery == true`, it calls
   `refresher.RefreshSessionScope(ctx, bff.SessionIDFromContext(ctx), userID, false)`
   — the SAME mechanism `PostRecoveryAcknowledge` already uses — to flip the
   EXISTING session (the one `POST /recovery/complete` created) to full scope
   in place, instead of minting a competing enrollment-only session. The
   first-time-signup path (`recovery == false`) is unchanged: it still calls
   `issuer.IssueEnrollmentSession` and sets the handoff cookie pair. A missing
   BFF session id (context not populated) or a refresher error is logged and
   swallowed, matching the existing "never turn a successful ceremony into an
   error response" contract.
3. `cmd/harbor-mgmt/main.go`: hoisted a shared `recoverySessionRefresher :=
   bffSessionScopeRefresher{bffSessions: bffStore}` (previously constructed
   inline only for `WithRecoverySessionRefresher`) and passed it to both
   `WithRecoverySessionRefresher` and the `wirePostRegistrationHandoff(...)`
   call — one instance, two callers, no new session-refresh mechanism.
   Updated `bffSessionScopeRefresher`'s doc comment (now has two callers, not
   one).
4. Updated the four other `wirePostRegistrationHandoff` call sites for the new
   parameter: `TestPostRegistrationHandoffAndRecoveryGating_EndToEnd` and
   `TestWirePostRegistrationHandoff_IssuesSessionOnlyOn200`'s subtests (all
   `recovery=false` paths, so `nil`/an unused refresher is correct there).
5. `internal/mgmtapi/recovery.go`: no functional change — `RecoverySessionRefresher`
   already existed as exactly the right seam; only reused, not extended.
6. Verify: `go build ./...`, `go vet ./...`, `gofmt -l` (clean), `go test ./...`
   (whole repo, all green), `go build -tags e2e ./e2e/...` / `go vet -tags e2e ./e2e/...`
   (clean, unaffected). `go run ./tools/agentcheck` — every check passes
   except the same pre-existing `golangci-lint`-vs-Go-1.25-toolchain mismatch
   noted in every prior task on this branch (confirmed identical, not
   introduced by this change). `-race` unavailable in this sandbox (no `gcc`),
   same pre-existing constraint.

# Task 16: Fix WebAuthn user-handle format mismatch (POST /webauthn/register/begin 400s on every real signup)

Investigation confirmed `internal/webauthn/store_db.go`'s `parseWebAuthnUserID`
has exactly two callers passing two *legitimately different* byte encodings of
"userID", not one bug with one correct fix:

- Every ceremony path (`GetUser`/`AddCredential`/`AddCredentialAndActivateUser`/
  `UpdateCredential`, and `SetRecoveryComplete` when called from
  `Service.FinishRecoveryRegistration`) receives the raw 16-byte WebAuthn user
  handle, as produced by `mgmtapi.parseUUIDToBytes` (POST /enroll) and
  `cmd/harbor-mgmt`'s `recoveryUserHandle` (POST /recovery/complete) — this was
  already fixed to `uuid.FromBytes` in Task 12 (commit `1e72d73`).
- But Task 12's own doc comment on `cmd/harbor-mgmt/caller.go`'s
  `recoveryRequirementClearer.ClearRecoveryRequired` (POST
  /recovery/acknowledge) says its `userID` is "always the canonical UUID text
  form" and is passed as `[]byte(userID)` straight into the SAME
  `SetRecoveryComplete` → `parseWebAuthnUserID`. That path was never actually
  exercised against the real `DBStore` — `TestRecoveryRequirementClearer_AdaptsSetRecoveryComplete`
  (`caller_test.go`) only asserts against a hand-rolled fake that echoes bytes
  back verbatim, so it couldn't catch a `uuid.FromBytes`-only parser rejecting
  a 36-byte text string with "invalid UUID (got 36 bytes)".

Fixed by making `parseWebAuthnUserID` dispatch on `len(userID) == 16` — a raw
UUID is always exactly 16 bytes, and no valid text encoding (canonical,
hyphen-less, braced, `urn:uuid:`) is ever 16 bytes, so this is unambiguous. 16
bytes → `uuid.FromBytes` (ceremony/enrollment path); anything else →
`uuid.ParseBytes` (canonical-text `recoveryRequirementClearer` path). No
producer changed — both `mgmtapi.parseUUIDToBytes`/`recoveryUserHandle` (raw)
and `recoveryRequirementClearer.ClearRecoveryRequired` (text) keep emitting
what they already emit; only the shared parser now accepts both.

1. Test-first: added `TestDBStore_SetRecoveryComplete_CanonicalTextForm` and
   `TestDBStore_SetRecoveryComplete_BothEncodingsResolveSameUser`
   (`internal/webauthn/store_db_test.go`) — the latter drives `SetRecoveryComplete`
   with the raw 16-byte handle AND the canonical text form for the SAME
   underlying user against the real `DBStore` (only the `dbStoreQuerier` is
   faked; `parseWebAuthnUserID` itself is production code), asserting both
   resolve and clear `recovery_required`. Confirmed both failed for the
   expected reason (`webauthn: user not found`, from `uuid.FromBytes` rejecting
   a 36-byte input) by stashing the fix and rerunning before restoring it.
2. `internal/webauthn/store_db.go`: `parseWebAuthnUserID` now branches on
   `len(userID)`; expanded its doc comment to name both callers and their
   encodings explicitly instead of asserting a single "the" format.
   `GetUser`/`AddCredential`/`AddCredentialAndActivateUser`/`UpdateCredential`
   are unaffected in practice (their callers only ever pass 16-byte handles)
   but now share the same dual-format-tolerant parser as `SetRecoveryComplete`
   rather than a second bespoke one.
3. Left `cmd/harbor-mgmt/caller.go`'s `recoveryRequirementClearer` doc comment
   as-is — it already correctly describes its input as "the canonical UUID
   text form" and that `parseWebAuthnUserID` now expects exactly that for
   non-16-byte input; no producer-side change was needed or made.
4. Verify: `go build ./...`, `go vet ./...`, `gofmt -l` (clean), `go test ./...`
   (whole repo, all green, including the full `internal/webauthn` and
   `cmd/harbor-mgmt`/`internal/mgmtapi` suites). `go run ./tools/agentcheck` —
   same pre-existing `golangci-lint`-vs-Go-1.25-toolchain mismatch noted on
   every prior task on this branch, not introduced by this change.

# Task 13: Thread return_to as real server-side session state through the full signup journey

Investigation first: task 4's follow-on note pinned exactly what's missing —
`GET /signup` never reads/validates its own `return_to`; `EnrollmentSessionStore`
only stores raw WebAuthn user-handle bytes; `BFFSessionRecord` has no `ReturnTo`
field; `ScopedSessionIssuer.IssueEnrollmentSession(ctx, userID)` has no
`return_to` parameter. `POST /enroll` happens directly from the `/signup` page's
own JS (before it ever navigates to `/signup/passkey`), and `web/templates/*`
are outside this task's file list, so the validated value cannot be threaded by
having the page's JS echo it into the `/enroll` request body. Chose a
short-lived, `HttpOnly`/`Secure`/`SameSite=Strict` cookie
(`mgmtapi.SignupReturnToCookieName`) as the bridge: `GET /signup` validates
`return_to` exactly once (`ValidateReturnTo`) and sets the cookie to the
*validated* output (never the raw value); the browser carries that cookie
automatically to the same-origin `POST /enroll`, which folds it into the new
enrollment session. `PostEnroll` does NOT re-validate the cookie against the
allowlist — a forged cookie set directly on `POST /enroll` (bypassing `GET
/signup`) can only ever affect the forger's own new enrollment session, never
another browser's, since nothing here lets one cookie jar influence another's;
the actual open-redirect boundary is closed once, where `ValidateReturnTo` first
runs on GET /signup's query string.

`RecoverySessionRefresher.RefreshSessionScope` — named in the task prompt as a
candidate signature change — turned out NOT to need one: `PostRecoveryAcknowledge`
calls it only to flip `UserID`/`RecoveryRequired`/`SessionScope` on an
*already-existing* BFF session record via `SetUserWithRecoveryStatus`, whose
Redis Lua script (`setUserWithRecoveryScript`) does a decode-mutate-three-fields-reencode
round trip that already preserves every other JSON field, including the new
`ReturnTo`, untouched. Confirmed by reading `internal/bff/session_redis.go`
before changing anything — left it alone rather than adding a needless
parameter.

1. `internal/mgmtapi/session.go`: added `SignupReturnToCookieName` const; added
   a `returnTo` parameter to `EnrollmentSessionStore.Save` and a `returnTo`
   return value to `UserHandle`.
2. `internal/mgmtapi/session_redis.go`: `redisEnrollmentSession` gained an
   `rt,omitempty` JSON field; `RedisEnrollmentSessionStore.Save`/`UserHandle`
   updated to match.
3. `internal/mgmtapi/enroll.go`: `PostEnroll` reads `SignupReturnToCookieName`
   (best-effort — absent cookie yields `""`, matching pre-existing behavior)
   via new helper `signupReturnToFromCookie`, and passes it to `sessions.Save`.
4. `internal/mgmtapi/recovery.go`: `ScopedSessionIssuer.IssueEnrollmentSession`
   gained a `returnTo` parameter; `PostRecoveryComplete` (lost-device recovery,
   which never runs through `GET /signup`) passes `""`.
5. `internal/bff/session.go`: added `BFFSessionRecord.ReturnTo`.
6. `internal/bff/signup.go`: `GetSignup` validates `return_to` and sets the
   cookie unconditionally (even the default) so every downstream hop sees a
   well-defined value. `SignupHandler`/`NewSignupHandler` gained an optional
   `sessions BFFSessionStore` dependency; `GetSignupSuccess` now prefers its own
   `return_to` query parameter when accepted (preserving the original
   single-hop, direct-link contract) and otherwise falls back to
   `sessionReturnTo` — a new helper resolving `SessionIDFromContext` ->
   `sessions.Get` -> `record.ReturnTo` — so a value captured once at `GET
   /signup` and carried the whole way through now reaches the completion page
   even when never re-supplied on `/signup/success`'s own URL.
7. `cmd/harbor-mgmt/caller.go`: `recoverySessionIssuer.IssueEnrollmentSession`
   threads `returnTo` into both the fresh `EnrollmentSessionStore` entry and the
   new `BFFSessionRecord.ReturnTo`; `wirePostRegistrationHandoff` reads the
   4th `UserHandle` return value and forwards it to `IssueEnrollmentSession`.
8. `cmd/harbor-mgmt/main.go`: passes the already-constructed `bffStore` into
   `bff.NewSignupHandler`.
9. Compile-forced ripple beyond the task's stated file list (Go interfaces
   require every implementer to match a changed method signature — same
   necessity task 12 hit adding the `recovery` flag): `internal/webauthn/handlers.go`
   (its own duplicated `EnrollmentSessionStore` interface + `handlers_test.go`'s
   fake), `internal/testsupport/mgmtapi/session.go` (`InMemoryEnrollmentSessionStore`),
   and every test file constructing/calling the changed signatures
   (`internal/mgmtapi/session_test.go`'s own duplicated in-memory fixture,
   `internal/mgmtapi/recovery_test.go`'s `fakeScopedSessionIssuer`,
   `cmd/harbor-mgmt/caller_test.go`'s `recordingScopedSessionIssuer`,
   `internal/bff/signup_test.go` / `signup_cta_contract_test.go`'s
   `NewSignupHandler` call sites).
10. `docs/design/product/signup-cta-contract.md`: reconciled the "Known gaps"
    section task 6 wrote — `return_to` on `GET /signup` is no longer inert as
    session-state (it still has no visible effect on that page's own rendered
    body, so `TestSignupCTAContract_SignupQueryParamsAreInert`'s body-equality
    assertions are still correct and were left as-is, just re-scoped in its doc
    comment).
11. New tests: `internal/bff/signup_returnto_test.go` (split out of
    `signup_test.go` once it crossed the 500-line `_test.go` budget — cookie
    set/validated on `GET /signup`, session-carried fallback and its priority
    order against an explicit query value on `/signup/success`, nil-sessions
    graceful degradation); `internal/mgmtapi/enroll_test.go` (`PostEnroll` folds
    the cookie into the saved session, and behaves unchanged with no cookie);
    `internal/mgmtapi/session_test.go` / Redis-backed round-trip tests for the
    new field; `cmd/harbor-mgmt/caller_test.go` (`IssueEnrollmentSession` binds
    `ReturnTo` onto both records; the handoff wrapper copies it through from the
    seeded enrollment session); `internal/mgmtapi/recovery_test.go` (lost-device
    recovery issues with an empty `returnTo`).
12. Verify: `go build ./...`, `go vet ./...`, `gofmt -l .` (all clean),
    `go test ./...` (whole repo, all green), `go test -tags e2e ./e2e/... -run
    TestSignup -v` (9/9 skip gracefully, unchanged from task 8 — the existing
    e2e happy-path test still passes `return_to` directly on its own
    `/signup/success` URL, which continues to take priority over the new
    session-carried fallback, so no e2e test needed updating), `go mod tidy`
    (no drift), `go run ./tools/lint/filesize` (no new violations — split
    `signup_test.go`; `internal/mgmtapi/recovery_test.go` grew by ~7 lines on an
    already pre-existing, already-over-its-frozen-baseline file — advisory-only
    check, not attempting a full split of unrelated pre-existing debt here).
    `-race` and `make agent-check`/`golangci-lint` unusable in this sandbox (no
    `gcc`, no `make`/`nix` binary at all) — same pre-existing condition as every
    prior task on this branch, now additionally missing `make` itself.

# Task 17: Fix /signin discoverable sign-in — decodeAssertionOptions didn't unwrap {publicKey:...}

`internal/bff/login.go`'s `BeginLogin` writes `options` (a
`*protocol.CredentialAssertion`) straight to the JSON response body.
go-webauthn's `protocol.CredentialAssertion` embeds its options under a
`Response` field tagged `json:"publicKey"`, so the wire response is
`{"publicKey": {"challenge": ..., "allowCredentials": ...}, "mediation": ...}`
— but `web/templates/signin.html`'s `beginLogin()` passed the raw parsed body
straight into `decodeAssertionOptions`, which reads `options.challenge` /
`options.allowCredentials` off the top level. `options.challenge` was always
`undefined`, so `base64urlToBuffer(undefined)` threw a `TypeError` inside the
promise chain before `navigator.credentials.get()` was ever called; the
generic `.catch()` in `attemptSignin()` swallowed it into "We couldn't sign
you in with that passkey." This broke both the conditional-mediation autofill
attempt (fires on page load) and the explicit modal button — there was no way
to complete discoverable sign-in at all. The sibling `signup_passkey.html`
already unwraps `beginData.publicKey` before decoding; `signin.html` was
missing the equivalent unwrap.

1. Test-first: added `TestSigninHandler_BeginLoginScript_UnwrapsPublicKeyWrapper`
   (`internal/bff/signin_beginlogin_script_test.go`) — renders the real
   `/signin` page via `ServeSignin`, extracts its inline `<script>` verbatim,
   and runs it under Node (`os/exec`) against a `fetch` mock shaped exactly
   like `BeginLogin`'s real wire response (`{"publicKey": {...}}`), a
   `navigator.credentials.get` mock that records its call args, and minimal
   `document`/`window`/`PublicKeyCredential` stubs. Fires the button's click
   handler and asserts `navigator.credentials.get()` was actually reached with
   a correctly base64url-decoded `ArrayBuffer` challenge and
   `allowCredentials[0].id`. No JS test runner exists in this repo for
   `web/templates/*.html` (they're plain server-rendered templates, not part
   of the Next.js frontend `.agents/frontend-test.md` covers), so this test
   executes the actual production script text rather than a reimplementation
   — it would not have caught a bug in logic the harness reimplemented itself.
   Confirmed it fails for the expected reason (`navigator.credentials.get()`
   never called — the assertion's own message) by stashing the fix and
   rerunning before restoring it.
   - Pitfall hit while writing the harness: the first filename I used,
     `signin_js_test.go`, was silently excluded from every build — Go's
     filename-based build-constraint matching treats a `_js` suffix before
     `_test.go` as an implicit `GOOS=js` constraint (`js` is a real, valid
     `GOOS`), so `go list`/`go test` never even saw the file with no error of
     any kind. Renamed to `signin_beginlogin_script_test.go`.
   - Also hit: Node 22 exposes a read-only global `navigator` (its built-in
     minimal polyfill), so `global.navigator = {...}` threw
     `TypeError: Cannot set property navigator of #<Object> which has only a
     getter`. Used `Object.defineProperty(global, "navigator", {configurable:
     true, value: {...}})` instead.
2. `web/templates/signin.html`: `beginLogin()` now resolves `body.publicKey`
   into `decodeAssertionOptions` instead of the raw parsed body, matching
   `signup_passkey.html`'s existing `decodeCreationOptions(beginData.publicKey)`
   pattern. `attemptSignin()` is unchanged — it already wraps the object
   `beginLogin()` resolves back into `{publicKey: ..., signal: ...}` for
   `navigator.credentials.get()`, which is correct once `beginLogin()` returns
   the unwrapped, decoded options rather than the still-wrapped raw body.
3. Verify: `go build ./...`, `go test ./internal/bff/...` (all green,
   including the new test and the full existing signin/login suites).
