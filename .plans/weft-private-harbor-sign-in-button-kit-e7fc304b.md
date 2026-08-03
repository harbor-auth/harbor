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
