# Security model

## The one rule that matters

**The button MUST target the relying party's (RP's) own login-initiation
endpoint. It MUST NEVER be wired to a hand-built Harbor `/authorize` URL.**

There is no qualification to this rule and no supported configuration that
relaxes it. Every asset in this kit enforces it structurally, not just by
convention:

- The HTML/CSS example (`html/example.html`) links to `/auth/login` — a
  placeholder for *your* endpoint — and its inline comment says so
  explicitly.
- The React component
  (`react/SignInWithPrivateHarborButtonProps`) accepts only `href`,
  `variant`, `size`, `disabled`, and `ariaLabel`. There is **no** `state`,
  `nonce`, `code_challenge`, `client_id`, or `redirect_uri` prop — the
  component's type signature makes it impossible to pass OIDC parameters
  through it even if you tried.
- The executable reference implementation,
  [`examples/minimal-rp/`](../examples/minimal-rp/), demonstrates the
  correct shape end-to-end and is covered by tests
  (`examples/minimal-rp/security_test.go`) that assert the login handler
  never accepts caller-supplied `state`, `nonce`, `redirect_uri`, or
  `client_id` — every one of those values is either minted fresh
  server-side or pulled from startup configuration, never from the
  incoming request.

### Why this is non-negotiable

If a page constructs `/authorize?client_id=...&redirect_uri=...` (or any
other Harbor endpoint URL) directly in static markup or client-side
script — instead of linking to a same-origin endpoint that builds that
request server-side — it strips out the protections described below by
construction: there is no server-side place to mint or check `state`, no
server-side place to generate or verify a PKCE `code_verifier`, and no
server-side session to bind a `nonce` or an authorization code to. The
result is exposure to CSRF (an attacker's `/authorize` redirect completing
against the victim's session), authorization-code injection (a stolen or
attacker-supplied code accepted without proof it belongs to the current
browser session), and, depending on how the response is handled, outright
token leakage to script running on the page. None of these are
theoretical edge cases in OAuth/OIDC — they are the exact failure modes
the Authorization Code + PKCE flow exists to prevent, and they only stay
prevented if the flow's cryptographic material is generated and checked
somewhere the browser (and any script running in it) cannot see or
influence: your own backend.

The reference implementation exists precisely so you don't have to take
this on faith — read
[`examples/minimal-rp/login.go`](../examples/minimal-rp/login.go) and
[`examples/minimal-rp/callback.go`](../examples/minimal-rp/callback.go) to
see exactly where each of the following responsibilities is discharged in
running code, and treat it as the executable reference for what your own
login-initiation and callback endpoints must do.

## RP-owned responsibilities

Harbor's protocol surface (`/authorize`, `/token`, `/jwks.json`,
`/end_session`, and discovery) supplies the cryptographic *bindings* —
it echoes `state`, embeds `nonce` into the ID token, verifies the PKCE
`code_challenge`, and signs tokens with a key published in JWKS. It cannot
enforce that *you* generate, store, and check these correctly, because
that logic necessarily runs on your side of the redirect. Each item below
is entirely your responsibility; each risk described is what happens if
you skip it.

### `state`

**What you must do:** generate a fresh, high-entropy `state` value per
login attempt, store it server-side (bound to the browser via a session
cookie, not embedded in the URL you control), send it in the `/authorize`
request, and — on callback — reject the request unless the returned
`state` exactly matches what you stored, *before* doing anything else with
the request.

**Risk if omitted:** login CSRF. An attacker can initiate their own
authorization flow, capture the resulting callback URL (with their own
valid `code`), and trick a victim into visiting it. Without a `state`
check tying the callback to a `state` the victim's own browser session
generated, your callback handler has no way to distinguish "the user I
just sent to Harbor is coming back" from "someone is handing me an
arbitrary authorization response" — the victim can end up authenticated
as the attacker's account (a well-documented OAuth CSRF class), or, in
flows that trust the callback more broadly, worse.

### `nonce`

**What you must do:** generate a fresh, high-entropy `nonce` per login
attempt, store it alongside `state`, send it in the `/authorize` request,
and — after verifying the ID token's signature — check that the token's
`nonce` claim matches exactly.

**Risk if omitted:** ID token replay/injection. `nonce` is what binds a
specific ID token to a specific browser-side authorization request. Without
checking it, a previously-issued, still-unexpired ID token (obtained
through any means — a different flow, a compromised log, a proxy) could be
replayed into your callback handler and accepted as though it were the
result of the login attempt currently in progress.

### PKCE (`code_verifier` / `code_challenge`, S256)

**What you must do:** generate a CSPRNG `code_verifier` per login attempt,
derive `code_challenge = BASE64URL(SHA256(code_verifier))`, send only the
challenge in the `/authorize` request, keep the verifier server-side, and
send it — for the first time — in the back-channel `/token` exchange. Never
use `code_challenge_method=plain`; Harbor doesn't offer it
(`code_challenge_methods_supported: ["S256"]`) and rejects an `/authorize`
request that omits PKCE entirely with `invalid_request`.

**Risk if omitted:** authorization-code interception/theft. The
authorization code travels through the browser (a redirect URL, browser
history, referrer headers, a malicious browser extension, or a
man-in-the-middle on a misconfigured redirect target) and is inherently
exposed to more parties than the back-channel `/token` exchange. PKCE is
what makes an intercepted code useless: without the matching
`code_verifier` — which never appears on the front channel — the token
endpoint refuses the exchange. Skip PKCE (or implement it incorrectly, or
reuse a verifier across attempts) and a leaked code becomes directly
redeemable by whoever captured it. See
[`docs/design/protocol/tokens.md` §3.1](../../../docs/design/protocol/tokens.md)
and [`docs/design/flows/error-cases.md`](../../../docs/design/flows/error-cases.md)
for Harbor's enforcement of this on the server side — enforcement that
only has teeth if your RP actually generates and checks a verifier.

### Redirect-URI allowlisting

**What you must do:** register the exact, static `redirect_uri`(s) your
callback endpoint uses, and — critically — always send the *pre-registered,
startup-configured* value in your `/authorize` request. Never derive
`redirect_uri` from anything in the incoming request (a query parameter, the
`Host`/`Origin`/`Referer` header, or similar). Harbor independently
exact-matches the `redirect_uri` you send against your registered
allowlist and refuses to redirect anywhere else — including refusing to
redirect its *own* error responses anywhere else, which is why an unknown
`client_id` or mismatched `redirect_uri` renders an HTML error page
instead of a redirect (there is no proven-safe target yet to redirect to).

**Risk if omitted:** open redirect / authorization-code exfiltration. If
your login-initiation endpoint lets any part of the incoming request
influence the `redirect_uri` it sends to Harbor, an attacker can construct
a link that starts a real login flow but points the resulting
authorization code at a URI they control, exfiltrating the code (and
anything else on that redirect) off your site entirely. Harbor's
allowlist check limits *which* URIs a code can be sent to, but only for
URIs your registration actually restricts — a dynamically-constructed
`redirect_uri` that happens to satisfy your allowlist syntax is still a
hole you created.

### Session rotation

**What you must do:** after a successful callback (state verified, code
exchanged, nonce verified, ID token validated), issue a **new** session
identifier rather than reusing whatever pre-login/pending-auth session
identifier the browser presented. [`callback.go`](../examples/minimal-rp/callback.go)
does this by design: the pre-auth session (used to store `state`/`nonce`/
`code_verifier`) is deleted on read (single use) and a fresh
post-login session is minted separately.

**Risk if omitted:** session fixation. If an attacker can plant a
pre-chosen session identifier in a victim's browser before the victim logs
in (e.g. via a cookie that isn't scoped correctly, or a session ID your
app accepts from a URL parameter) and your app continues using that same
identifier as the authenticated session after login, the attacker — who
already knows the identifier — is now authenticated as the victim too.
Rotating the session identifier at the login/authentication boundary is
the standard defense; skipping it turns any other cookie-fixation bug
elsewhere in your app into a full account takeover.

### Callback error handling

**What you must do:** handle both of Harbor's error channels correctly —
an `error` query parameter on the `/authorize` redirect (e.g.
`access_denied`, `invalid_scope`, `login_required`) and a JSON error body
from the back-channel `/token` call (e.g. `invalid_grant`,
`invalid_client`) — and collapse them into **generic, non-revealing**
user-facing messages. See
[`INTEGRATION.md`'s error-code table](INTEGRATION.md#error-codes) for the
full mapping every callback handler should implement. Never surface a raw
Harbor `error_description` to the end user, and never let your own error
responses distinguish "this user doesn't exist" from "that code was
already used" from any other internal reason — Harbor's own
`error_description`s are already deliberately generic
([`docs/design/flows/error-cases.md`](../../../docs/design/flows/error-cases.md):
"Generic `error_description`s — never reveal whether a user account or
client exists, or why auth failed beyond the standard code"), and a
verbose callback handler can undo that protection on your side of the
integration.

**Risk if omitted:** account/client enumeration and a confusing or
exploitable failure surface. A callback handler that echoes Harbor's raw
error text, or that responds differently depending on *why* the token
exchange failed, gives an attacker a free oracle for probing which
usernames, clients, or authorization codes are valid — exactly the class
of leak Harbor's own generic error text is designed to prevent. Beyond
information leakage, mishandling `invalid_grant` on a reused code
specifically means missing Harbor's theft signal: a reused code causes
Harbor to revoke every token minted from it, and your app should react to
that failure by forcing re-authentication, not by silently retrying or
ignoring the error.

## Reference implementation

[`examples/minimal-rp/`](../examples/minimal-rp/) is the executable
reference for everything above: a minimal, runnable RP (`go run
./sdk/sign-in-button/examples/minimal-rp`) whose `/auth/login` and
`/auth/callback` handlers implement `state`, `nonce`, PKCE (S256), and
session rotation, with `examples/minimal-rp/security_test.go` asserting
the security-relevant behavior (no caller-supplied flow parameters
accepted, state mismatches rejected generically, and more) as executable
tests rather than prose claims. Its README explicitly calls out what it
deliberately leaves out for brevity — ID token signature verification
against JWKS — which a production RP must add; see
[`INTEGRATION.md`'s JWKS rotation section](INTEGRATION.md#jwks-rotation)
for what that verification needs to handle correctly.
