# Design: fix-bff-session-binding

## Nonce scheme: two cookies, not one

The existing `__Host-harbor-bff` cookie carries the `request_id` (session lookup
key). We introduce a **separate** `__Host-harbor-bff-nonce` cookie that carries
the raw 256-bit browser nonce. Both are:

- Minted at `/authorize` (harbor-hot), before the login redirect
- `HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/`
- TTL = BFF session TTL (5 min)

This two-cookie design preserves existing semantics of `request_id` (session
lookup at `/login`, `/login/complete`, `/authorize/complete`) while adding the
nonce binding. No changes to the `BFFSessionStore` interface; nonce hash rides on
`BFFSessionRecord` (JSON-additive for Redis).

**Rejected alternative:** a single cookie holding both nonce and request_id as a
compound value — more parsing complexity, higher risk of subtle errors.

## Hash-at-rest

`SHA-256(raw_nonce)` is stored in `BFFSessionRecord.BrowserNonceHash`. The raw
nonce is only ever in the browser cookie. A Redis store compromise yields only the
hash, which cannot be used to forge the cookie.

## Constant-time comparison

All nonce checks use `crypto/subtle.ConstantTimeCompare` on the SHA-256 digests.

## M2 — absolute redirect

`LoginHandler` gains an `authorizeCompleteURL string` field. `FinishLoginWithParsedData`
builds the redirect from this field instead of the literal string `/authorize/complete`.
`cmd/harbor-mgmt/main.go` reads `AUTHORIZE_COMPLETE_URL` from the environment and
passes it to `NewLoginHandler`; it fails closed (exits 1) at boot if the URL is
unset or malformed.

## Single-host topology constraint

`__Host-` prefix forces `Path=/` and no `Domain`, so a cookie set by harbor-hot
(which serves `/authorize`) can only be received by harbor-mgmt's `/login` if both
binaries serve the same public hostname (path-routed ingress: `/login*` → mgmt,
everything else → hot). This topology is documented in `deploy/README.md`. If
harbor-hot and harbor-mgmt must serve separate hostnames, `__Host-` cookies cannot
span them — a signed handoff token in the redirect would be needed instead. That
case is out of scope for this change.

## DESIGN alignment

Serves DESIGN §9 (BFF session is the authenticated seam), §11.2 (login ceremony),
§11.7 (never redirect to an unproven URI). Closes a gap between the design intent
and the implementation. No DESIGN amendment required.

## Cookie clearing

`GetAuthorizeComplete` clears both `__Host-harbor-bff` and `__Host-harbor-bff-nonce`
on success (one-time-use).
