# Design: "Sign in with Private Harbor" button + brand kit

## Key Decisions

### Decision 1: New top-level `sdk/sign-in-button/` subtree, Apache-2.0

**Chosen:** A standalone top-level directory, licensed **Apache-2.0** via a
new `REUSE.toml` override (same rationale as the existing `api/`/`deploy/`
overrides: "permissive for broad client/SDK generation").
**Rationale:** The kit must be vendorable by Harbor Cloud onboarding and
`harbor-dummy-app` — both outside this repo, neither able to depend on
AGPL-3.0 code. A dedicated subtree with its own SPDX headers keeps the AGPL
boundary explicit and auditable (README.md "Proprietary components" note).
Nesting it under `web/` (AGPL by default) or `.agents/`/`tools/` (wrong
audience — those are MIT, agent/dev tooling) would blur that boundary or
mis-signal intent.
**Alternatives considered:** Reuse `api/` (wrong domain — OpenAPI/proto
contracts, not client-side assets/code); a separate private repo (adds
release/versioning overhead not yet justified; revisit if the kit needs an
independent release cadence).

### Decision 2: Go generator for deterministic SVG assets, output vendored

**Chosen:** A small Go program (`sdk/sign-in-button/gen/`, stdlib
`text/template` + `encoding/xml`-safe templating) renders the button/logomark
SVG variants from one set of design tokens (color, wording, size) and writes
them to `assets/`. Generated `assets/**/*.svg` are **committed** (vendored),
not built on the fly.
**Rationale:** Deliverable requires "vendored/versioned assets" and
"assets are deterministic" — a test-covered, stdlib-only Go generator is
reproducible byte-for-byte (fixed float formatting, stable key ordering,
no timestamps) and matches this repo's Go-first, no-remote-script
convention. Avoids a Node/pnpm dependency purely for static SVG output; the
React component still only needs `react` at runtime.
**Alternatives considered:** Hand-authored SVGs per variant (12+ files,
drifts on brand tweaks, no single source of truth — rejected); a Node/SVG
templating pipeline (adds a build dependency the deliverable explicitly
avoids — "do not require a remote tracking script" and vendored assets favor
a checked-in, regenerable-but-static output).

### Decision 3: React component is a thin, dependency-light wrapper

**Chosen:** `react/SignInWithPrivateHarborButton.tsx` — a single component,
peer dep `react` only (no icon libraries, no CSS-in-JS runtime). It renders
the same vendored SVG + CSS classes as the plain HTML example, and accepts
`variant` (light/dark/neutral), `size` (compact/full), `href`
(RP's own login-initiation URL) and `label`/`aria-label` overrides as props.
**Rationale:** "Framework examples ... if it can remain dependency-light" —
a single file with one peer dependency satisfies that without forcing a
build toolchain choice (bundler-agnostic; consumers copy the file or import
the package). Matches Harbor's own frontend stack (Next.js/React, `pnpm`,
per `.agents/frontend-test.md`) for internal consistency.
**Alternatives considered:** A styled-components/Tailwind variant (adds a
runtime/build dependency — rejected); a Web Component (broader compat but
no existing precedent in this repo — deferred, note as a future option in
the kit README).

### Decision 4: The button always targets the RP's own login-initiation URL

**Chosen:** Every asset/example/doc treats the button's `href`/`onClick`
target as **RP-owned** (e.g. `/auth/login`), never a hand-built
`/authorize?...` URL. The RP's own endpoint is responsible for minting
`state`, `nonce`, the PKCE `code_verifier`/`code_challenge` (S256 only),
checking its redirect-URI allowlist, and only then redirecting to Harbor's
`/authorize`.
**Rationale:** This is the single most important security property of the
kit. A client-side-constructed `/authorize` URL cannot carry a
server-verifiable `state`/PKCE pairing (the verifier must stay
server-side/HttpOnly to resist XSS), and it re-creates exactly the class of
bug this repo's own invariants (`INV-PKCE-MANDATORY`, `INV-REDIRECT-EXACT`,
`docs/DESIGN.md` §11.7) exist to catch on the server side — the kit closes
the client-side half of that gap. The minimal RP example
(`examples/minimal-rp/`) is the executable proof of this pattern, and the
contract test (Decision 5) makes "cannot bypass state/PKCE" machine-checked
rather than aspirational prose.
**Alternatives considered:** A generic `<a href="{authorizeUrl}">` helper
that builds the full `/authorize` URL for the RP (rejected outright — this
is exactly the anti-pattern the deliverable calls out).

### Decision 5: Contract tests as the "cannot bypass" proof

**Chosen:** `examples/minimal-rp/security_test.go` uses `httptest` to drive
the example RP's login-initiation handler and asserts: (a) the redirect to
Harbor always carries non-empty `state`, `code_challenge`, and
`code_challenge_method=S256`; (b) the callback handler rejects any request
whose `state` doesn't match the server-side session; (c) no exported helper
in the package can produce an `/authorize` URL without those three
parameters. `gen/determinism_test.go` regenerates all assets twice per test
run and asserts byte-identical output (and that the committed `assets/**`
match a fresh generation, catching drift the way `make generate-check`
catches Go codegen drift).
**Rationale:** Matches this repo's existing pattern of encoding security
invariants as tests (`invariants/registry.yaml`) rather than prose docs
alone, and the deliverable explicitly asks for "tests that verify generated
links cannot bypass state/PKCE and that assets are deterministic."
**Alternatives considered:** Docs-only guidance (rejected — the deliverable
requires an executable check); a full OIDC conformance run against a live
Harbor instance (out of scope — `conformance/` already covers the server
side; this kit tests the RP-side contract in isolation).

### Decision 6: Brand/privacy claims are evidence-linked, not asserted

**Chosen:** `docs/BRAND-GUIDELINES.md` and the privacy section cite only
verifiable facts already documented elsewhere in this repo (e.g. PPID
pairwise identifiers, §3.2; no-tracking design, `docs/design/product/`) and
explicitly disclaim any certification/compliance claim (e.g. no "GDPR
certified" language) unless a real audit artifact is linked.
**Rationale:** Deliverable requires "evidence-backed privacy language. No
claims of certification/compliance without proof" — this is a legal/trust
requirement, not a technical one, so the design constrains the *prose*, not
just the code.
**Alternatives considered:** Marketing-style superlative claims (rejected —
violates the explicit constraint and this project's stated ethics-first
positioning, `docs/design/product/privacy-positioning.md`).

## Open Questions (non-blocking, flag in tasks.md)

- Whether Harbor Cloud onboarding consumes `sdk/sign-in-button/` via git
  subtree/submodule or a published npm/Go-module release is an
  operator-side decision outside this repo; the kit is structured (single
  subtree, Apache-2.0, no internal imports) to support either path.
