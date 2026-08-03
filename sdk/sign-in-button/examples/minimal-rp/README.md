# minimal-rp

A minimal, executable relying-party (RP) reference implementation for "Sign
in with Private Harbor". It exists to demonstrate — in runnable code, not
just documentation — the security model the rest of this kit assumes: the
button never constructs a Harbor `/authorize` URL, it only ever links to an
endpoint *you* own, and that endpoint is responsible for state, nonce,
PKCE, redirect-URI allowlisting, session rotation, and callback error
handling. See [`../../docs/SECURITY.md`](../../docs/SECURITY.md) for the
full explanation of why each of these matters.

## What it does

- `GET /auth/login` (`login.go`) — mints a CSPRNG `state`, `nonce`, and a
  PKCE `code_verifier`/`code_challenge` (S256) pair, stores them
  server-side keyed by an opaque, `HttpOnly` session cookie, and redirects
  to the identity provider's authorization endpoint (discovered from
  `ISSUER` at startup) with `redirect_uri` set to the pre-configured,
  allowlisted `REDIRECT_URI` — never a value derived from the incoming
  request.
- `GET /auth/callback` (`callback.go`) — rejects any request whose `state`
  doesn't match the server-side session (generic error, no detail leaked),
  exchanges the authorization `code` for tokens via the stdlib
  `net/http` client (sending `code_verifier` so the token endpoint can
  verify PKCE), checks the ID token's `nonce` against the one minted at
  login, and then rotates the session — the pre-auth session identifier is
  discarded and a fresh one is issued, so session fixation gains an
  attacker nothing.

Both handlers are plain `http.Handler`s wired into an `http.ServeMux` in
`main.go`, which also performs OIDC discovery
(`{ISSUER}/.well-known/openid-configuration`) at startup to find the
authorization and token endpoints.

**Not included, and required for production:** verifying the ID token's
signature against the issuer's JWKS. `callback.go` decodes the ID token's
claims without verifying the signature — enough to demonstrate the
state/nonce/PKCE flow this example is about, not enough to trust the
claims in production. See `docs/SECURITY.md`.

## Run

```sh
ISSUER=https://auth.example.com \
CLIENT_ID=your-client-id \
REDIRECT_URI=http://localhost:8080/auth/callback \
go run ./sdk/sign-in-button/examples/minimal-rp
```

Then visit `http://localhost:8080/auth/login` in a browser.

## Environment variables

| Variable | Required | Description |
|---|---|---|
| `ISSUER` | yes | The identity provider's issuer URL, e.g. `https://auth.example.com`. Used for OIDC discovery (`{ISSUER}/.well-known/openid-configuration`) and to validate the ID token's `iss` claim. |
| `CLIENT_ID` | yes | This RP's registered OIDC `client_id`. |
| `REDIRECT_URI` | yes | The exact, pre-registered callback URL, e.g. `http://localhost:8080/auth/callback`. Must match what's registered with the identity provider byte-for-byte. |
| `ADDR` | no | Address to listen on. Defaults to `:8080`. |

This example is a **public client** (no `client_secret`): PKCE (S256) is
what proves possession of the original request to the token endpoint. See
`docs/SECURITY.md` for when a confidential client (with a client secret)
is appropriate instead.

## Build

```sh
go build ./sdk/sign-in-button/examples/minimal-rp
```
