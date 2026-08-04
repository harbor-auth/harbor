# "Sign in with Private Harbor" — button + brand kit

The official button assets, copy-paste HTML/CSS, a dependency-light React
component, and a minimal executable relying-party (RP) example for
integrating "Sign in with Private Harbor" into a website.

> **License:** this subtree (`sdk/sign-in-button/**`) is **Apache-2.0**, an
> explicit override of the repository-wide AGPL-3.0-only default — see
> [`../../REUSE.toml`](../../REUSE.toml). It contains no code from `internal/`
> and no AGPL-licensed code. See "Consuming this kit" below.

## Contents

| Path | What |
|---|---|
| `assets/` | Deterministically-generated, vendored SVG button + logomark variants (`{light,dark,neutral} × {compact,full}`, each with default/hover/focus/disabled states) |
| `gen/` | The Go generator that produces `assets/` from design tokens (`go generate`) |
| `css/` | Copy-paste CSS for every button variant/size/state |
| `html/` | A copy-paste HTML integration example |
| `react/` | `SignInWithPrivateHarborButtonProps` component (peer dep: `react` only) |
| `examples/minimal-rp/` | An executable Go RP demonstrating the RP-owned security model (state, nonce, PKCE S256) |
| `docs/` | Integration (`INTEGRATION.md`), security (`SECURITY.md`), and brand (`BRAND-GUIDELINES.md`) documentation |

## Quick start

The button always links to **your own login-initiation endpoint** — never a
hand-built Harbor `/authorize` URL. Your endpoint is responsible for minting
`state`, `nonce`, and the PKCE `code_verifier`/`code_challenge` (S256) before
redirecting to Harbor; see `docs/SECURITY.md` for why and `examples/minimal-rp/`
for a working implementation.

HTML:

```html
<link rel="stylesheet" href="/vendor/sign-in-button/sign-in-button.css">

<a class="phb-button phb-button--light phb-button--full"
   href="/auth/login"
   aria-label="Sign in with Private Harbor">
  <!-- inline SVG from assets/, or <img src="..."> -->
  Sign in with Private Harbor
</a>
```

React:

```tsx
import { SignInWithPrivateHarborButton } from "./sign-in-button/react/SignInWithPrivateHarborButton";

<SignInWithPrivateHarborButton href="/auth/login" variant="light" size="full" />
```

`href` must be a path or URL your own server controls (e.g. `/auth/login`).
Nothing in this kit accepts `state`, `nonce`, `code_challenge`, `client_id`,
or `redirect_uri` as props — those belong to your login-initiation endpoint,
not the button.

## Consuming this kit

`sdk/sign-in-button/` is designed to be vendored by external, non-AGPL
repositories — including **Harbor Cloud onboarding** and **harbor-dummy-app**
— without pulling in any AGPL-licensed or internal Harbor code:

- **Nothing under this subtree imports from `internal/**` or any other
  AGPL-3.0-only path in this repo.** Its only intra-repo relationship is the
  `REUSE.toml` override that grants it Apache-2.0; it does not depend on
  `internal/oidc*`, `internal/httpserver`, or any other package for behavior.
- **The Go code here compiles as an independent tree.** It shares this
  repo's root `go.mod` today (single-module convenience for CI), but nothing
  in `sdk/sign-in-button/**` references a package outside that subtree, so it
  can be copied into its own module (`go mod init`) unmodified if an
  independent release cadence is ever needed.
- **The React component has one peer dependency: `react`.** No icon
  libraries, no CSS-in-JS runtime, no bundler assumption.

Supported vendoring paths for consumers of this kit:

1. **`git subtree`** (recommended for infrequent updates):
   ```sh
   git subtree add --prefix=vendor/sign-in-button \
     https://github.com/harbor-auth/harbor.git main --squash -- sdk/sign-in-button
   ```
2. **`git submodule`** (if the consumer wants a pinned, explicit checkout):
   ```sh
   git submodule add https://github.com/harbor-auth/harbor.git vendor/harbor
   # then reference vendor/harbor/sdk/sign-in-button/** directly
   ```
3. **A published package** — the Go package (`go get
   github.com/harbor-auth/harbor/sdk/sign-in-button/...`) or a future
   standalone npm package built from `react/`. Either path is compatible
   with this subtree's structure; publishing is an operator-side decision
   independent of this repo (see the feature's design notes).

Whichever path is used, every file added under this subtree carries a
`// SPDX-License-Identifier: Apache-2.0` header (see `doc.go`), so the
license boundary travels with the code even when vendored in isolation from
the rest of this repository.

## Accessibility

Every button variant meets WCAG 2.1 AA contrast, exposes a visible
focus-visible outline, and has an explicit accessible name ("Sign in with
Private Harbor" by default, overridable). See `docs/INTEGRATION.md` for the
accessibility check command and `docs/BRAND-GUIDELINES.md` for minimum size
and clear-space rules.

## Security

The button/component never constructs a Harbor `/authorize` URL — it only
ever links to an endpoint you own. Read `docs/SECURITY.md` before
integrating; it explains why this matters and lists every responsibility
(state, nonce, PKCE, redirect-URI allowlisting, session rotation, callback
error handling) that stays on the relying party.
