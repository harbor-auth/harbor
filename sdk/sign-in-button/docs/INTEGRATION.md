# Integration guide

This document covers the OIDC/OAuth protocol details a relying party (RP)
needs to integrate "Sign in with Private Harbor": discovery, client
registration, PKCE, scopes/consent, subject identifiers, logout, token
rotation, key rotation, error handling, and the Content-Security-Policy the
vendored assets require.

The button itself (`assets/`, `css/`, `html/`, `react/`) never talks to any
of these endpoints directly — it is a styled `<a href>` to a login-initiation
path **you** own. Everything below is what *your* login-initiation and
callback endpoints need to do. See
[`SECURITY.md`](SECURITY.md) for why that split is non-negotiable, and
[`../examples/minimal-rp/`](../examples/minimal-rp/) for a working
implementation of every item in this document.

## OIDC discovery

Fetch `{issuer}/.well-known/openid-configuration` at startup rather than
hardcoding endpoint URLs — Harbor is deployed per-region, each region is its
own issuer (`https://eu.harbor.id`, `https://us.harbor.id`, `https://au.harbor.id`,
…), and discovery keeps your RP correct across regions without per-region
config beyond the issuer URL itself.

The discovery document is served by
[`GetOpenIDConfiguration`](../../../internal/oidcapi/discovery.go) and is
edge-cacheable (`Cache-Control: public, max-age=3600`). As of this SDK
version it advertises:

| Field | Value |
|---|---|
| `issuer` | The regional issuer, e.g. `https://eu.harbor.id` |
| `authorization_endpoint` | `{issuer}/authorize` |
| `token_endpoint` | `{issuer}/token` |
| `userinfo_endpoint` | `{issuer}/userinfo` |
| `end_session_endpoint` | `{issuer}/end_session` |
| `revocation_endpoint` | `{issuer}/revoke` |
| `introspection_endpoint` | `{issuer}/introspect` |
| `jwks_uri` | `{issuer}/jwks.json` |
| `response_types_supported` | `["code"]` — no implicit flow |
| `subject_types_supported` | `["pairwise"]` — see [PPID `sub`](#pairwise-subject-identifiers-ppid) below |
| `id_token_signing_alg_values_supported` | `["ES256"]` |
| `grant_types_supported` | `["authorization_code", "refresh_token"]` — no client-credentials, no ROPC |
| `scopes_supported` | `["openid", "profile", "email", "offline_access"]` |
| `code_challenge_methods_supported` | `["S256"]` — PKCE `plain` is not offered and is rejected if sent |
| `token_endpoint_auth_methods_supported` | `["none"]` |

Treat this table as illustrative, not a value to hardcode: always read the
live discovery document rather than copying these values into your
configuration, since a region's document is the authoritative source and can
change (see [JWKS rotation](#jwks-rotation) and [refresh token
rotation](#refresh-token-rotation) below for the parts of the contract that
are explicitly designed to change over time).

## Public versus confidential client registration

Register your RP once with Harbor before any user can sign in (`client_id`,
redirect URI allowlist, sector identifier, requested scopes). Two
`token_endpoint_auth_method` shapes are available, matching RFC 7591 §2 and
validated by Harbor's registration endpoint:

- **Public client** (`token_endpoint_auth_method: "none"`) — no client
  secret. This is the shape a browser-side app (or a backend that can't
  keep a secret confidential) must use, and it's what the discovery
  document above currently advertises as supported. PKCE is what binds the
  code exchange to the party that started the flow, replacing the secret.
- **Confidential client** (`token_endpoint_auth_method: "client_secret_basic"`
  or `"client_secret_post"`) — a server-side RP that can hold a secret
  presents it at `/token` (and at `/introspect` / `/revoke`, which
  additionally *require* client authentication and reject public clients
  outright, since a client with no secret has no way to authenticate
  itself). PKCE is still mandatory even for confidential clients — see
  below.

[`examples/minimal-rp`](../examples/minimal-rp/) registers and runs as a
**public** client, which is the expected shape for the sign-in button kit:
the button's login-initiation endpoint typically lives alongside the
front-end it serves, and a public client with PKCE gives that endpoint no
secret to leak. If your backend architecture calls for a confidential
client instead, the protocol requirements below (PKCE, state, nonce,
redirect-URI allowlisting) are identical either way — only client
authentication at the token endpoint changes.

## PKCE is mandatory — S256 only

Every authorization request, public or confidential client, **must**
include `code_challenge` and `code_challenge_method=S256`
([`tokens.md` §3.1](../../../docs/design/protocol/tokens.md): "OAuth 2.1
semantics — Authorization Code flow + PKCE mandatory for all clients
(public and confidential)"). `code_challenge_methods_supported` in
discovery lists only `S256` — the legacy `plain` method is not offered, and
an `/authorize` request that omits PKCE or sends an unsupported method is
rejected with `invalid_request`
([`error-cases.md`](../../../docs/design/flows/error-cases.md)).

The exchange, exactly as [`login.go`](../examples/minimal-rp/login.go) and
[`callback.go`](../examples/minimal-rp/callback.go) implement it:

1. Generate a CSPRNG `code_verifier` (43–128 chars, RFC 7636 §4.1).
2. Compute `code_challenge = BASE64URL(SHA256(code_verifier))` and send it
   (never the verifier) in the `/authorize` redirect.
3. Send the plaintext `code_verifier` — for the first time — in the
   back-channel `POST /token` request that exchanges the authorization
   code.
4. Harbor recomputes `SHA256(code_verifier)` and compares it
   constant-time against the stored `code_challenge`; a mismatch returns
   `invalid_grant` **without** consuming the code, so the legitimate holder
   of the correct verifier can still retry.

An intercepted authorization code is useless without the `code_verifier`,
which never travels over the front channel — this is what makes PKCE the
defense against code interception on a redirect-based flow.

## Scopes and consent

Request only the scopes you need from `scopes_supported`:
`openid` (required — identifies the request as OIDC), `profile`, `email`,
and `offline_access` (required to receive a refresh token; see [Refresh
token rotation](#refresh-token-rotation)). An unknown or disallowed scope
is rejected at `/authorize` with `invalid_scope`.

Harbor's login/consent UI (Harbor-COLD) prompts the user to approve the
requested scopes on first authorization for your `client_id`; claims
outside `openid`/`sub` (e.g. `email`, `email_verified`) are only emitted
in tokens when the matching scope was both requested and consented to. If
the user declines consent, `/authorize` redirects back with
`error=access_denied` — your callback handler must treat this as a normal,
expected outcome (see [Error codes](#error-codes) below), not a bug.

## Pairwise subject identifiers (PPID)

The `sub` claim Harbor issues is **not** a stable, global user identifier —
it's a pairwise identifier (PPID), unique per `(user, your registered
sector)`. The same user authenticating at a different RP (a different
sector) gets a *different* `sub`; you cannot use `sub` to correlate a user
across RPs, and neither can Harbor's own operators without the user's
per-user secret. Full derivation, storage, and the sector-identifier rules
that determine when your `sub` values stay stable across a `client_id` /
`redirect_uri` rotation are specified in
[`docs/design/protocol/ppid.md`](../../../docs/design/protocol/ppid.md).

Practical implication for your callback handler: treat `sub` as an opaque,
per-your-RP identifier and key your local user records on it directly. Do
not expect it to match any identifier from another identity provider or
another RP's Harbor integration.

## Logout (end-session endpoint)

Harbor implements OIDC RP-Initiated Logout 1.0 at the
`end_session_endpoint` discovery advertises (`{issuer}/end_session`, both
`GET` and `POST`):

```
GET /end_session
  ?id_token_hint=<ID token issued to your client_id>
  &post_logout_redirect_uri=<must exactly match a registered logout_uris entry>
  &state=<opaque value echoed back to you on redirect>
```

- `id_token_hint` is required. Harbor verifies its signature and reads
  `aud` as the authoritative `client_id` — an absent or invalid hint (or
  one whose signature doesn't verify) degrades to Harbor's default
  logged-out page rather than acting on any of its claims.
- Successful logout revokes **only** your RP's sessions for that user
  (looked up via the PPID `sub` → grant → internal user, never exposing the
  internal user ID to you), not the user's sessions at other RPs.
- `post_logout_redirect_uri` is honored only if it **exactly matches** a
  URI you registered in `logout_uris`; otherwise Harbor redirects to its
  own default logged-out page instead of an unvalidated URI. Register your
  logout redirect URI the same way you register `redirect_uris` for login.
- `state`, if supplied, is echoed back on the redirect so you can restore
  UI context and defend against logout CSRF the same way you would for
  login `state`.

## Refresh token rotation

If you requested and were granted `offline_access`, the token response
includes a refresh token: **opaque, CSPRNG-generated, one-time-use, and
rotating**
([`docs/design/protocol/tokens.md` §3.5](../../../docs/design/protocol/tokens.md)).
Concretely:

- Every `grant_type=refresh_token` exchange atomically revokes the
  presented token and issues a **new** refresh token alongside fresh
  access/ID tokens — never reuse a refresh token you've already exchanged.
- Presenting a refresh token that has *already been rotated away* (reuse)
  is treated as a theft signal: Harbor revokes the entire session family
  for that user↔RP pairing and returns `invalid_grant`. If this happens to
  a legitimate client, it usually means two callers raced on the same
  stored token (e.g. a bug storing/loading the refresh token across
  multiple processes) — store the refresh token you get back from *every*
  exchange, and only ever use the most recent one.
- Refresh tokens are long-lived and DB-backed; a JWT access/ID token is
  short-lived (~5–15 minutes) and is *not* individually revocable — this
  is deliberate (§3.5's "revoke the ability to get a new one, not the
  token itself"). Don't build revocation logic that expects to invalidate
  an already-issued access token directly; revoking the refresh token (or
  the whole session via [logout](#logout-end-session-endpoint) / consent
  withdrawal) is what stops future access tokens from being minted.

## JWKS rotation

Verify ID tokens (and JWT access tokens, if you use the JWT format) against
`jwks_uri` (`{issuer}/jwks.json`), matching the token's `kid` header to a
key in the JWKS document. `GetJwks` serves the document with
`Cache-Control: public, max-age=300` — cache it for up to five minutes, but
your JWKS client must be able to **re-fetch on a `kid` miss**: Harbor
rotates its signing key on a schedule (currently a 60-second grace period
before the new key starts signing, and a 15-minute overlap window during
which both the old and new key remain published so in-flight tokens signed
with the retiring key still verify), and an emergency rotation (suspected
key compromise) can retire the old key with **zero** grace/overlap. A
verifier that only ever fetches JWKS once at startup will start rejecting
valid tokens the moment a rotation happens.

Practical rule: on an unrecognized `kid`, re-fetch the JWKS once
(rate-limited — don't re-fetch per request on a sustained attack sending
bogus `kid`s) before rejecting the token. Never accept a token without a
successful signature verification against a key actually present in the
JWKS document; never fall back to `alg: none` or skip verification for any
reason.

## Error codes

`/authorize` errors redirect to *your* redirect URI (302, with `error`,
`error_description`, and the echoed `state`) — except when Harbor can't yet
prove your redirect URI is legitimate (unknown `client_id` or a
`redirect_uri` that isn't an exact match for your registration), in which
case Harbor renders an HTML error page instead of redirecting anywhere.
`/token` errors are a back-channel JSON body with `Cache-Control: no-store`
and no redirect. Full rationale:
[`docs/design/flows/error-cases.md`](../../../docs/design/flows/error-cases.md).

Your callback handler must be able to receive an `error` query parameter
(on the redirect from `/authorize`) and map at least these codes to a
user-facing message — never surface the raw code or `error_description`
verbatim to the user, and never let a `/token` failure reveal *why* it
failed beyond the standard code (Harbor's own `error_description`s are
already deliberately generic to prevent account/client enumeration):

| Code | Where it appears | Meaning | Suggested user-facing message |
|---|---|---|---|
| `access_denied` | `/authorize` redirect | User declined consent | "Sign-in was cancelled." — offer to retry, not an error state |
| `login_required` | `/authorize` redirect (`prompt=none`) | No active session, silent auth not possible | Prompt for a normal (non-silent) sign-in |
| `consent_required` | `/authorize` redirect (`prompt=none`) | Consent needed, silent auth not possible | Prompt for a normal (non-silent) sign-in |
| `interaction_required` | `/authorize` redirect (`prompt=none`) | User interaction needed | Prompt for a normal (non-silent) sign-in |
| `invalid_request` | `/authorize` or `/token` | Malformed request (e.g. missing PKCE/state/nonce) — an RP bug, not a user error | "Something went wrong signing you in. Please try again." + alert your own monitoring |
| `invalid_scope` | `/authorize` redirect | Unknown/unpermitted scope requested — an RP configuration bug | Same generic message; fix your scope configuration |
| `unauthorized_client` | `/authorize` redirect | Your client isn't allowed this flow/scope combination | Same generic message; check your registration |
| `unsupported_response_type` | `/authorize` redirect | `response_type` wasn't `code` — an RP bug | Same generic message; fix your integration |
| `server_error` | `/authorize` redirect | Harbor-side fault | "Sign-in is temporarily unavailable. Please try again shortly." |
| `temporarily_unavailable` | `/authorize` redirect | Harbor overloaded/maintenance | Same as `server_error` |
| `invalid_grant` | `/token` JSON body | Expired/reused/mismatched code, PKCE mismatch, or a revoked/reused refresh token | "Your sign-in session expired. Please try again." — restart the flow from your login-initiation endpoint, don't retry the same code/token |
| `invalid_client` | `/token`/`/introspect`/`/revoke`, HTTP 401 | Client authentication failed (confidential clients only) | Not user-facing — this indicates a misconfigured client secret; alert your own monitoring |
| `unsupported_grant_type` | `/token` JSON body | `grant_type` wasn't `authorization_code` or `refresh_token` — an RP bug | Not user-facing; fix your integration |

Also handle the ID-token-side checks that are **your** responsibility, not
Harbor's: a `state` value that doesn't match what you stored server-side
before redirecting (drop the response — don't proceed), a `nonce` claim in
the ID token that doesn't match the one you sent (reject the token), and
`iss`/`aud`/`exp` mismatches when verifying the ID token's signature
against JWKS. None of these arrive as an `error` query parameter — they're
checks your callback code must perform itself, exactly as
[`callback.go`](../examples/minimal-rp/callback.go) does.

## Content-Security-Policy for the vendored assets

The button ships as **vendored, same-origin assets** — no remote script,
no third-party origins, no tracking pixel — so your CSP for the pages that
embed it needs no third-party `script-src` entry at all. The one wrinkle
is that the SVG assets (`assets/*.svg`) and the React component both style
themselves with an inline `<style>` element (so `:hover` /
`:focus-visible` states work without extra CSS), which under a strict CSP
needs to be allowed without `unsafe-inline`. Because these assets are
deterministically generated and vendored (not fetched at runtime), a
CSP **hash source** is the correct fit: it allows exactly this fixed
inline `<style>` content and nothing else.

Baseline policy (adjust `default-src`/`img-src`/etc. to the rest of your
page — these are only the directives the button/kit itself needs):

```
Content-Security-Policy:
  default-src 'self';
  script-src 'self';
  style-src 'self' <hash-for-your-variant(s)-below>;
  img-src 'self';
  base-uri 'self'
```

No `unsafe-inline` and no third-party origin appears anywhere above.
`script-src 'self'` is sufficient because neither the vendored SVGs, the
CSS, nor the React component (`react/SignInWithPrivateHarborButton.tsx`)
emit any inline `<script>` or `on*=` handler attribute — the React
component wires its click-guard via `onClick` (a real event listener
attached by React, not an inline HTML attribute), which CSP `script-src`
does not restrict.

**Which hash to add** depends on which variant(s) you use and whether you
embed the vendored SVG file directly (`html/example.html`'s pattern) or
render the React component (whose inline style string is built the same
way but without the SVG file's line breaks, and therefore hashes to a
different value). Add only the hash(es) for the variant(s)/integration
path(s) you actually use:

| Variant | Vendored SVG file (`assets/button-<variant>-{compact,full}.svg`) | React component (`react/SignInWithPrivateHarborButton.tsx`) |
|---|---|---|
| `light` | `sha256-62XpGooscRy5iN+MLPJz6N2S3OWLWOcAXSeLLTBNC/k=` | `sha256-4S1/HyusT/zkBtWf6qtskXcllqF+IRlKjMUK7U5Ot3U=` |
| `dark` | `sha256-AtfPZaHn0+2SmjDPgYp9wV2Bdp0NGZDplGdaz0ySFsA=` | `sha256-pfsVDN/v7MVZW6A1p7FKLyen8wSrUVa3Ik8VUpKwF0Q=` |
| `neutral` | `sha256-Wxuqml9i+e72cPYx6h6qvQAsy4zsNtMWzHvzKNST1Cc=` | `sha256-X+Z88WRYmWX2eV0zXG+ytnbvw5dagnwA3zfG1rcf+kQ=` |

(The `compact` and `full` SVG files for a given variant share byte-identical
`<style>` content, so one hash per variant covers both sizes.)

These hashes are tied to the *exact* vendored asset bytes shipped in this
SDK version — if you regenerate `assets/` from a newer `gen/` (or the
button component changes upstream), recompute them rather than trusting
the table above indefinitely. To recompute the hash for a vendored SVG
file's inline style block:

```sh
python3 -c "
import hashlib, base64, re, sys
data = open(sys.argv[1], 'rb').read()
content = re.search(rb'<style>(.*?)</style>', data, re.S).group(1)
print('sha256-' + base64.b64encode(hashlib.sha256(content).digest()).decode())
" assets/button-light-full.svg
```

If your setup already generates a per-request CSP nonce for server-rendered
pages (common in SSR React frameworks), using that nonce on the rendered
`<style>` tag is an equally valid alternative to the hash approach and
avoids the recompute step — apply whichever fits your existing CSP
tooling.
