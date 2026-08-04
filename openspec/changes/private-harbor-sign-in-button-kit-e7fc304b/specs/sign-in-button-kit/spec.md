# Spec: Sign in with Private Harbor — button + brand kit

Defines the standalone `sdk/sign-in-button/` package: deterministic brand
assets, copy-paste HTML/CSS/React integration, a minimal executable RP
example proving the RP-owned security model, and the documentation set
relying parties need to integrate correctly and consistently.

## ADDED Requirements

### Requirement: REQ-001 Deterministic, vendored SVG brand assets

The system SHALL provide a Go generator that produces byte-deterministic SVG
brand assets for every required variant, and the generated output MUST be
committed (vendored) under `sdk/sign-in-button/assets/`.

Variants MUST cover: color scheme (`light`, `dark`, `neutral`) × size
(`compact`, `full`), plus the logomark alone. Each interactive button asset
MUST define `default`, `hover`, `focus`, and `disabled` visual states. No
generated asset may reference a remote URL (no external `<image>`/`href`
fetch, no tracking pixel, no analytics script).

```go
package gen

// Variant identifies one button rendering.
type Variant struct {
	Scheme string // "light" | "dark" | "neutral"
	Size   string // "compact" | "full"
}

// Generate renders every asset in Variants to dir, deterministically
// (stable float formatting, no timestamps, stable attribute ordering).
func Generate(dir string) error
```

#### Scenario: All required variants are generated

**Given** the asset generator is run against an empty output directory
**When** `Generate` completes
**Then** the output directory contains a button SVG for every
(scheme × size) combination in `{light,dark,neutral} × {compact,full}`,
plus a standalone logomark SVG

#### Scenario: Interactive states are present

**Given** a generated button SVG for any (scheme, size) pair
**When** the SVG is inspected
**Then** it defines distinguishable `default`, `hover`, `focus`, and
`disabled` visual states (e.g. via `<style>` classes or state-suffixed
sibling files), each with a WCAG 2.1 AA-compliant contrast ratio against its
background

#### Scenario: No remote dependency

**Given** any generated SVG or the HTML/CSS/React examples that reference it
**When** the asset is inspected for network references
**Then** it contains no remote `<script>`, tracking pixel, external font, or
CDN-hosted `href`/`src`

### Requirement: REQ-002 Integration surfaces target the RP's own endpoint

The system SHALL ship copy-paste HTML/CSS and a dependency-light React
component whose link/action target MUST be a value the integrating site
supplies (its own login-initiation endpoint) and MUST NEVER be constructed
by the kit as a Harbor `/authorize` URL.

```tsx
export interface SignInWithPrivateHarborButtonProps {
  /** The RP's OWN login-initiation URL (e.g. "/auth/login"). Never an
   *  `/authorize` URL — the kit does not accept OIDC parameters. */
  href: string;
  variant?: "light" | "dark" | "neutral";
  size?: "compact" | "full";
  disabled?: boolean;
  /** Overrides the default accessible label; defaults to
   *  "Sign in with Private Harbor". */
  ariaLabel?: string;
}
```

#### Scenario: Component accepts no OIDC parameters

**Given** the `SignInWithPrivateHarborButtonProps` type
**When** its fields are enumerated
**Then** none of `state`, `nonce`, `code_challenge`, `client_id`, or
`redirect_uri` appear as props — only `href` (RP-owned) and presentation
props exist

#### Scenario: Plain HTML example posts to the RP's endpoint

**Given** the copy-paste HTML example in `html/example.html`
**When** its anchor/form target is inspected
**Then** it points at a placeholder RP-owned path (e.g. `/auth/login`), with
an inline comment instructing integrators never to replace it with a
Harbor `/authorize` URL

#### Scenario: Every button state is keyboard-accessible

**Given** the rendered button (HTML or React) in a browser
**When** a user tabs to the button
**Then** a visible focus indicator meeting WCAG 2.1 AA appears, and pressing
Enter/Space activates the same `href` navigation as a mouse click

### Requirement: REQ-003 Minimal executable RP integration example

The system SHALL provide a minimal, executable Go RP example under
`sdk/sign-in-button/examples/minimal-rp/` that demonstrates the RP-owned
security responsibilities end to end: it MUST generate a CSPRNG `state`, an
S256 PKCE verifier/challenge pair, and a `nonce`; it MUST store them
server-side (not in a client-readable cookie); it MUST validate the
`redirect_uri` against an explicit allowlist before use; and its callback
handler MUST reject any response whose `state` does not match the
server-side session.

```go
package minimalrp

// LoginHandler serves the RP's OWN login-initiation endpoint. It mints
// state/nonce/PKCE, persists them server-side keyed by an opaque session
// cookie, and redirects to Harbor's /authorize with those parameters.
type LoginHandler struct {
	AuthorizeURL string // Harbor's /authorize endpoint for this issuer/region
	ClientID     string
	RedirectURI  string // MUST be pre-registered/allowlisted
}

func (h *LoginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request)

// CallbackHandler serves the RP's OWN redirect_uri. It verifies state,
// exchanges the code for tokens (with the PKCE verifier), verifies the ID
// token nonce, and rotates the RP's session.
type CallbackHandler struct{}

func (h *CallbackHandler) ServeHTTP(w http.ResponseWriter, r *http.Request)
```

#### Scenario: Login handler never omits PKCE/state

**Given** a request to the example RP's login-initiation endpoint
**When** `LoginHandler.ServeHTTP` builds the redirect to Harbor's
`/authorize`
**Then** the redirect URL always contains a non-empty `state` and a
`code_challenge_method=S256` with a non-empty `code_challenge`

#### Scenario: Callback rejects state mismatch

**Given** a callback request whose `state` query parameter does not match
the value stored in the server-side session for that browser
**When** `CallbackHandler.ServeHTTP` processes the request
**Then** it rejects the request with a generic error (no state-mismatch
detail leaked to the response body) and does not proceed to token exchange

#### Scenario: Redirect URI is allowlist-checked

**Given** a `LoginHandler` configured with a specific `RedirectURI`
**When** the handler builds the authorize redirect
**Then** the `redirect_uri` parameter sent to Harbor is always the
pre-configured, allowlisted value — never derived from user-controlled
input (e.g. a query parameter or `Referer` header)

### Requirement: REQ-004 Contract tests prove links cannot bypass state/PKCE

The system SHALL include automated tests that fail the build if any code
path in the example RP or kit tooling can produce an authorization redirect
missing `state` or PKCE S256 parameters.

#### Scenario: Fuzzed/edge-case login requests still include state+PKCE

**Given** a table of edge-case requests to the login-initiation handler
(missing query params, repeated calls, concurrent requests)
**When** each request is processed
**Then** every resulting redirect to Harbor's `/authorize` includes a
non-empty `state`, `code_challenge`, and `code_challenge_method=S256`

#### Scenario: No exported helper bypasses the pattern

**Given** the `minimalrp` package's exported API surface
**When** it is enumerated
**Then** no exported function returns or writes an `/authorize` URL without
also being the sole function responsible for minting that URL's
`state`/PKCE parameters (i.e. there is no lower-level "build authorize URL"
helper an integrator could call directly and accidentally omit them)

### Requirement: REQ-005 Deterministic asset generation is verified

The system SHALL include a test that regenerates all brand assets and fails
if the output differs from the committed `assets/` tree, or if two
successive generations differ from each other.

#### Scenario: Regeneration matches committed assets

**Given** the committed contents of `sdk/sign-in-button/assets/`
**When** the generator is re-run into a fresh temporary directory
**Then** every generated file is byte-identical to the corresponding
committed file (no drift)

#### Scenario: Generation is repeatable

**Given** two independent invocations of the generator in the same process
or across processes
**When** their outputs are compared
**Then** they are byte-identical (no timestamps, random IDs, or
map-iteration-order artifacts leak into the output)

### Requirement: REQ-006 Integration and security documentation

The system SHALL document, in `sdk/sign-in-button/docs/`, OIDC discovery
(`/.well-known/openid-configuration`), the distinction between public and
confidential clients, mandatory PKCE S256, scopes/consent, pairwise subject
identifiers (PPID `sub`), logout, refresh token rotation, JWKS rotation,
the standard OIDC/OAuth error codes an RP callback handler must handle, and
a recommended Content-Security-Policy for pages embedding the button. It
MUST state explicitly that the RP owns `state`, `nonce`, PKCE, redirect-URI
allowlisting, session rotation, and callback error handling — the kit
provides assets and an example, not a hosted SDK that performs these steps
for the RP.

#### Scenario: Security responsibilities are explicit

**Given** `docs/SECURITY.md` in the kit
**When** it is read
**Then** it states, without qualification, that the button MUST target the
RP's own login-initiation endpoint and MUST NEVER be wired directly to a
hand-built `/authorize` URL, and lists each RP-owned responsibility
(state, nonce, PKCE, redirect allowlisting, session rotation, callback
error handling) with a one-paragraph explanation of the risk if omitted

#### Scenario: CSP guidance is concrete

**Given** `docs/INTEGRATION.md`'s CSP section
**When** it is read
**Then** it provides a copy-paste `Content-Security-Policy` directive set
sufficient to render the vendored SVG/CSS/React assets with no `unsafe-
inline` script requirement and no third-party script-src additions

### Requirement: REQ-007 Brand misuse and evidence-backed privacy guidance

The system SHALL document acceptable and prohibited uses of the "Sign in
with Private Harbor" mark (minimum size, clear-space, prohibited
recoloring/distortion, prohibited implication of endorsement), and MUST NOT
include any certification or regulatory-compliance claim (e.g. "GDPR
certified", "SOC 2 certified") unless a link to a verifiable, dated audit
artifact is included alongside the claim.

#### Scenario: Minimum size and clear space are specified

**Given** `docs/BRAND-GUIDELINES.md`
**When** it is read
**Then** it specifies a minimum rendered height (in px) and a minimum
clear-space margin (proportional to the logomark) below which the mark
must not be used

#### Scenario: No unproven compliance claims

**Given** every privacy/compliance statement across the kit's docs and
in-asset copy
**When** the statements are checked against linked evidence
**Then** each statement either (a) links to a verifiable artifact already
present in this repo (e.g. `docs/design/product/`, an audit doc) or (b) is
phrased as a design property ("Harbor uses pairwise identifiers so RPs
cannot correlate users across sites") rather than a certification claim
