# Copy-paste CSS button styles + plain HTML integration example

1. Add `sdk/sign-in-button/css/sign-in-button.css`: `.phb-button` base +
   `--light/--dark/--neutral` + `--compact/--full` modifier classes. Assumes
   the matching SVG from `assets/` is inlined as the element's content (that
   SVG already self-styles default/hover/disabled via its own scoped
   `<style>`); the stylesheet's job is the one thing an inlined,
   `focusable="false"` SVG can't do on its own — forward keyboard
   focus-visible from the wrapping link to the SVG's inset `.phb-btn-ring`,
   with ring colors matched to `gen/tokens.go` `SchemePalette.FocusRing` per
   scheme — plus disabled affordance (`pointer-events`/`cursor`).
2. Add `sdk/sign-in-button/html/example.html`: single copy-paste example
   (light/full), inlining the exact contents of
   `assets/button-light-full.svg` (verified byte-for-byte equivalent),
   `href="/auth/login"` with an inline comment stating this must be the
   integrating site's own login-initiation endpoint and must never be
   replaced with a hand-built Harbor `/authorize` URL, `aria-label="Sign in
   with Private Harbor"`.
3. Verify: SVG inlined in example.html matches the committed asset exactly
   (scripted diff); the anchor is the only focusable element on the page so
   Tab lands on it; CSS braces balanced and ring colors present. Full
   browser rendering isn't available in this container (no libglib/system
   deps, no root to install) — logic verified statically; real visual QA is
   Task 9 in this feature.
4. Commit and push.

# Task 4: Dependency-light React SignInWithPrivateHarborButton component

1. Add `sdk/sign-in-button/react/SignInWithPrivateHarborButton.tsx`
   implementing the `SignInWithPrivateHarborButtonProps` contract from spec
   REQ-002 (`href` required/RP-owned, `variant`, `size`, `disabled`,
   `ariaLabel` — no `state`/`nonce`/`code_challenge`/`client_id`/
   `redirect_uri`). The SVG per variant/size is reproduced inline as JSX
   (byte-faithful to `assets/button-<variant>-<size>.svg`) rather than
   imported from the asset file, so the component has zero bundler
   requirements (no SVGR/raw-loader config needed) — documented in a code
   comment, with the bundler-driven alternative noted for consumers who
   prefer it. Reuses the `phb-button*`/`phb-btn*` classes from
   `css/sign-in-button.css`.
2. Add `sdk/sign-in-button/react/index.ts` barrel export and
   `sdk/sign-in-button/react/package.json` (name, version 0.1.0,
   `peerDependencies.react`, `files`, `license: Apache-2.0`), plus a local
   `tsconfig.json` so the package can be typechecked standalone.
3. Verify: no pnpm/tsc preinstalled in this container, but `npm` exists
   unlinked at `/usr/lib/node_modules/npm/bin/npm-cli.js`; installed
   `typescript`/`react`/`@types/react` as devDependencies in
   `react/node_modules` and ran `tsc --noEmit` — zero errors.
4. Commit and push.

# Task 5: Minimal executable RP integration example (Go) — state/nonce/PKCE S256

1. Add `sdk/sign-in-button/examples/minimal-rp/main.go`: wires an
   `http.ServeMux` with `/auth/login` and `/auth/callback`, performs OIDC
   discovery (`{ISSUER}/.well-known/openid-configuration`, validating the
   returned `issuer` matches configured `ISSUER` exactly) at startup to
   find the authorization/token endpoints, and owns the in-memory
   `sessionStore` (pending pre-auth records + established post-auth
   sessions) shared by both handlers.
2. Add `login.go`: `LoginHandler{AuthorizeURL, ClientID, RedirectURI,
   Sessions}`. `ServeHTTP` mints CSPRNG `state`/`nonce`/PKCE
   `code_verifier` (+ S256 `code_challenge`), stores them server-side keyed
   by a fresh opaque session id set as an `HttpOnly`/`Secure`/`SameSite=Lax`
   cookie, and redirects to `AuthorizeURL` with `redirect_uri` fixed to the
   pre-configured `RedirectURI` field (never derived from the request).
3. Add `callback.go`: `CallbackHandler{TokenEndpoint, ClientID,
   RedirectURI, Issuer, Sessions, HTTPClient}`. `ServeHTTP` looks up the
   pending session via `takePending` (delete-on-read, so a state/session is
   redeemable at most once), rejects any state mismatch or unknown session
   with a generic `"login failed"` (no detail leaked), exchanges the code
   via stdlib `net/http` (posting `code_verifier`), decodes the ID token
   claims (no signature verification — documented as a hard production
   requirement, not in scope for this state/nonce/PKCE demo) and checks
   `nonce`/`iss`/`aud`/`exp`, then rotates the session by minting a new
   post-auth session id and discarding the pre-auth one.
4. Add `README.md`: run command, required env vars (`ISSUER`, `CLIENT_ID`,
   `REDIRECT_URI`, optional `ADDR`), what's intentionally out of scope
   (JWKS signature verification).
5. Verify: `go build ./sdk/sign-in-button/...` and `go vet
   ./sdk/sign-in-button/...` both clean; `gofmt -l` clean; ran the server
   against a throwaway fake-IdP discovery endpoint on loopback and curled
   both routes — `/auth/login` redirects with `state`/`nonce`/
   `code_challenge`/`code_challenge_method=S256` and sets the session
   cookie; `/auth/callback` with a bogus `state` returns a generic 400.
6. Commit and push.

# Task 6: Contract tests — links cannot bypass state/PKCE, deterministic assets

1. Add `sdk/sign-in-button/examples/minimal-rp/security_test.go`: table-driven
   `httptest` cases against `LoginHandler` (missing query params, repeated
   requests, concurrent requests) asserting every redirect `Location` parses
   with non-empty `state`, `code_challenge`, and `code_challenge_method=S256`,
   and that `redirect_uri` always equals the configured `RedirectURI`
   regardless of request input (query params, headers, path). Add a
   `CallbackHandler` case proving a `state` mismatch is rejected with the
   generic error and never reaches `exchangeCode` (assert via a token
   endpoint stub that must NOT be hit).
2. Add `sdk/sign-in-button/gen/determinism_test.go`: call `Generate` into two
   fresh `t.TempDir()`s and diff byte-for-byte; call `Generate` into a third
   temp dir and diff against the committed `sdk/sign-in-button/assets/` tree,
   failing with a clear per-file diff message on drift (mirrors
   `make generate-check`).
3. Add `sdk/sign-in-button/react/SignInWithPrivateHarborButton.test.tsx`:
   render every variant × size × disabled combination, assert accessible
   name via `getByRole` is "Sign in with Private Harbor" (or the `ariaLabel`
   override), and assert (via a `Expect<Equal<...>>`-style compile check or
   runtime key-set check) the props type carries no `state`/`nonce`/
   `code_challenge`/`code_verifier` field. No test runner exists yet in
   `react/` — add `vitest` + `@testing-library/react` + `jsdom` as
   devDependencies and a `test` script, using the unlinked npm at
   `/usr/lib/node_modules/npm/bin/npm-cli.js` (aliased on PATH) discovered in
   Task 4.
4. Verify: `go test ./sdk/sign-in-button/...` green; deliberately revert one
   security check in `login.go`/`callback.go` at a time and confirm the
   corresponding test fails, then restore it; `npm test` in `react/` green.
5. Commit and push.

# Task 7: Integration and security documentation (REQ-006)

1. Ground every protocol claim in the actual source of truth before writing
   prose: read `internal/oidcapi/discovery.go` (exact discovery fields,
   including that `token_endpoint_auth_methods_supported` currently
   advertises only `["none"]`), `internal/oidc/errors.go` +
   `docs/design/flows/error-cases.md` (exact wire error codes and which
   channel each uses), `docs/design/protocol/tokens.md` (PKCE-mandatory,
   refresh rotation, JWKS rotation policy incl. grace/overlap windows from
   `internal/crypto/rotation.go`), `docs/design/protocol/ppid.md` (PPID
   derivation/sector rules), `internal/oidcapi/end_session.go` (logout is
   fully wired, not just planned), and `internal/oidc/auth_method.go` /
   `internal/mgmtapi/register_validate.go` (public vs confidential client
   auth is implemented at `/token`, `/introspect`, `/revoke` — the
   `docs/plans/client-secret-auth.md` plan doc describing this as a stub is
   stale).
2. Add `sdk/sign-in-button/docs/INTEGRATION.md`: discovery document field
   table, public/confidential client registration, PKCE S256-only mechanics,
   scopes/consent, PPID `sub` (link `docs/design/protocol/ppid.md`), logout
   (`/end_session` contract), refresh token rotation semantics (rotate,
   reuse ⇒ theft signal), JWKS rotation (grace period/overlap window, re-fetch
   on unknown `kid`), an error-code table a callback handler must map to
   user messages, and a copy-paste CSP directive set for the vendored
   SVG/CSS/React assets — no `unsafe-inline`, no third-party `script-src`.
   The one wrinkle is the inline `<style>` block each SVG/React variant
   carries for `:hover`/`:focus-visible`; used CSP hash sources instead of
   `unsafe-inline`, computing exact `sha256-` values per variant (verified
   `compact`/`full` share byte-identical style content per variant; the
   React-rendered string hashes differently than the vendored SVG file
   because it lacks the file's line breaks — documented both, plus the
   recompute command).
3. Add `sdk/sign-in-button/docs/SECURITY.md`: unqualified statement that the
   button must target the RP's own login-initiation endpoint and must never
   be wired to a hand-built `/authorize` URL, then each RP-owned
   responsibility (state, nonce, PKCE, redirect-URI allowlisting, session
   rotation, callback error handling) with a concrete risk explanation if
   omitted, cross-referencing `examples/minimal-rp/` (already written in
   Task 5, tested in Task 6) as the executable reference.
4. Verify: every discovery field, error code, and endpoint path quoted in
   both docs matches `internal/oidcapi/discovery.go` /
   `internal/oidc/errors.go` / `docs/design/flows/error-cases.md` /
   `docs/design/protocol/tokens.md` verbatim (manual cross-check, no
   generated-doc tooling in this repo); independently recomputed the CSP
   hashes with a second extraction method and confirmed they match; no Go
   files touched by this task, so no `go test` run needed — this is a
   docs-only change.
5. Commit and push.

# Task 14: Make disabled HTML buttons inert and preserve React focus styling

Rerun QA found two accessibility defects with browser evidence:

1. **Plain HTML/CSS disabled anchor not inert.** `aria-disabled="true"` +
   `pointer-events: none` blocks mouse clicks but `pointer-events` doesn't
   touch keyboard: the anchor stayed in the default Tab order and a native
   `<a href>` still navigates on Enter once focused.
2. **React focus ring not standalone.** The component's module doc claims
   zero-bundler/standalone use, but the anchor→ring `:focus-visible`
   forwarding rule (the wrapping `<a>` is the focusable element; the inline
   SVG is `focusable="false"`) only existed in `css/sign-in-button.css`,
   which the component neither imports nor requires. Standalone light fell
   back to the browser default outline; dark/neutral measured ~1.05:1/2.26:1
   contrast instead of the intended >=3:1 ring.

Fix:

1. `html/example.html`: added a second, explicitly disabled example anchor
   that omits `href` entirely (nothing to navigate to, and an `<a>` without
   `href` isn't part of the default Tab order), sets `tabindex="-1"` as
   belt-and-suspenders, and adds `role="link"` (dropping `href` also drops
   the implicit ARIA link role, which `aria-disabled="true"` needs to be
   announced as a *disabled link*). `css/sign-in-button.css`'s comment above
   `.phb-button[aria-disabled="true"]` now explains why `pointer-events`
   alone is insufficient and points at this markup pattern.
2. `react/SignInWithPrivateHarborButton.tsx`: appended the anchor-scoped
   `:focus`/`:focus-visible` outline-suppression and ring-forwarding rules
   (matching `css/sign-in-button.css`'s colors, sourced from
   `gen/tokens.go` `SchemePalette.FocusRing`) to each variant's own
   `VARIANT_STYLE` entry, so the component needs no external stylesheet.
   Recomputed the React CSP `sha256-` hashes in `docs/INTEGRATION.md`'s
   table for all three variants (the SVG-file column is untouched since
   `gen/generate.go`'s template wasn't touched — only the React string
   changed).
3. Tests (both new, in `react/`, reusing the existing vitest+jsdom setup):
   - `disabled-and-focus.test.tsx`: asserts each variant's rendered
     `<style>` contains the new forwarding rules; locks the CSP hash table
     to the actual rendered content so it can't silently drift; and — using
     `@testing-library/user-event` (added as a devDependency) for faithful
     Tab-order and Enter-activation simulation — proves disabled buttons are
     skipped by `Tab` and that a direct-focus Enter dispatches a `click`
     whose `defaultPrevented` is `true`, while enabled buttons behave the
     opposite way.
   - `html-example-disabled.test.tsx`: loads the real committed
     `html/example.html` + `css/sign-in-button.css` through
     `DOMParser`/jsdom (no hand-copied fixture) and asserts the disabled
     anchor has no `href`, `tabindex="-1"`, `role="link"`; that `Tab`
     genuinely skips it; that Enter on it dispatches no `click` at all
     (`user-event` only synthesizes Enter→click for an `<a>` that actually
     has an `href`, matching real browsers); and that the CSS file's
     existing focus-forwarding rules are present for all three variants.
   - Learned mid-implementation: a same-target native `click` listener
     added directly to the `<a>` fires *before* React's delegated `onClick`
     (attached on an ancestor container) during the bubble phase — reading
     `event.defaultPrevented` inside that listener races ahead of React's
     `preventDefault()`. Fixed by capturing the `Event` object reference and
     reading `.defaultPrevented` only after `await user.keyboard(...)`
     resolves, once the whole synchronous dispatch chain has finished.
4. Verify: `npm test` (37/37 passing) and `npm run typecheck` clean in
   `react/`; `go test ./sdk/sign-in-button/...` clean (generator/assets
   untouched); `go run ./sdk/sign-in-button/gen` into a scratch dir still
   diffs byte-identical against committed `assets/` (generation parity);
   `go vet`/`gofmt -l` clean.
5. Commit and push.
