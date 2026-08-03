# Tasks: "Sign in with Private Harbor" button + brand kit

## Prerequisites

- [ ] None — this is a new, standalone subtree (`sdk/sign-in-button/`); it
      does not depend on any in-flight change to `internal/oidc*`.

## Implementation

- [ ] `REUSE.toml`: add an override block for `sdk/**` → `Apache-2.0`
      (same pattern as the existing `api/**`/`deploy/**` overrides).
- [ ] `sdk/sign-in-button/README.md`: kit overview, quick start, and a
      "Consuming this kit" section covering vendoring via git subtree/
      submodule or a published package, for Harbor Cloud onboarding and
      `harbor-dummy-app` (both external, non-AGPL consumers).
- [ ] `sdk/sign-in-button/gen/`: Go generator (`text/template`-based,
      stdlib only) rendering design tokens into SVG variants; wire a `go
      generate` directive.
- [ ] `sdk/sign-in-button/assets/`: commit the generated logomark + button
      SVGs for `{light,dark,neutral} × {compact,full}`, each with
      default/hover/focus/disabled states.
- [ ] `sdk/sign-in-button/css/sign-in-button.css`: button classes for every
      variant/size/state.
- [ ] `sdk/sign-in-button/html/example.html`: copy-paste HTML example
      wired to a placeholder RP-owned login endpoint (`/auth/login`), with
      an explicit comment against pointing it at `/authorize`.
- [ ] `sdk/sign-in-button/react/SignInWithPrivateHarborButton.tsx` +
      `package.json` (peer dep: `react` only): dependency-light component
      per REQ-002's prop contract.
- [ ] `sdk/sign-in-button/examples/minimal-rp/`: executable Go RP example
      (`main.go`, `login.go`, `callback.go`) implementing
      `LoginHandler`/`CallbackHandler` per REQ-003 (CSPRNG state, PKCE
      S256, nonce, server-side session, redirect-URI allowlist, generic
      callback error mapping).
- [ ] `sdk/sign-in-button/docs/INTEGRATION.md`: OIDC discovery, public vs.
      confidential clients, PKCE S256, scopes/consent, PPID `sub`, logout,
      refresh rotation, JWKS rotation, error codes, CSP (REQ-006).
- [ ] `sdk/sign-in-button/docs/SECURITY.md`: RP-owned responsibilities
      (state, nonce, PKCE, redirect allowlisting, session rotation,
      callback error handling); explicit "never hand-build `/authorize`"
      statement (REQ-006).
- [ ] `sdk/sign-in-button/docs/BRAND-GUIDELINES.md`: misuse guidance
      (min size, clear space, prohibited alterations) + evidence-backed
      privacy language, no unproven certification claims (REQ-007).

## Tests

- [ ] `sdk/sign-in-button/gen/determinism_test.go`: regenerate into a temp
      dir twice; assert byte-identical output, and that output matches
      the committed `assets/` tree (REQ-005).
- [ ] `sdk/sign-in-button/examples/minimal-rp/security_test.go`: table-
      driven `httptest` cases proving every login-initiation redirect
      carries `state` + `code_challenge`/`code_challenge_method=S256`,
      and the callback handler rejects `state` mismatches (REQ-003,
      REQ-004).
- [ ] `sdk/sign-in-button/react/SignInWithPrivateHarborButton.test.tsx`:
      renders each variant/size/disabled combination; asserts the
      accessible name and that `state`/`nonce`/PKCE are not accepted
      props (REQ-002).
- [ ] Accessibility check (documented run command in the kit README):
      verify focus-visible outline, `aria-label`/accessible name, and
      WCAG 2.1 AA contrast for every rendered variant/state.

## Validation

- [ ] `go build ./... && go vet ./... && go test ./...` (repo root — the
      Go generator/example must not break the existing build).
- [ ] `cd sdk/sign-in-button/react && pnpm typecheck && pnpm lint && pnpm
      test` (per `.agents/frontend-test.md`'s three checks).
- [ ] `make agent-check`
- [ ] `openspec validate private-harbor-sign-in-button-kit-e7fc304b --strict`
