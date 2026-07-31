# Proposal: fix-bff-session-binding

## Why

Two CRITICAL audit findings (C3 + M2) in `docs/plans/audit-2026-07-30-wiring-and-auth.md`:

**C3 — Login session fixation → account takeover.** `internal/bff/login.go` sets
the browser's `__Host-harbor-bff` cookie to whatever `request_id` arrives in the
URL query string at `/login`. An attacker can start `/authorize` with their own
`client_id` + `redirect_uri`, capture `request_id=R`, lure a victim to
`/login?request_id=R`, and — after the victim completes their passkey ceremony —
receive an auth code for the victim's account redirected to their own
`redirect_uri`.

**M2 — Absolute redirect missing.** `internal/bff/login.go` builds a relative
`/authorize/complete?...` which resolves against the harbor-mgmt origin.
`/authorize/complete` is registered on harbor-hot, so this 404s unless both
binaries share one hostname.

## What changes

1. **Browser nonce** — a second 256-bit CSPRNG value minted at `/authorize`,
   stored as `SHA-256(nonce)` in `BFFSessionRecord.BrowserNonceHash`, and set in
   a new `__Host-harbor-bff-nonce` cookie **before** redirecting to `LOGIN_URL`.
2. **Gate at every ceremony step** — `BeginLogin`, `FinishLogin`, and
   `GetAuthorizeComplete` all verify `sha256(cookie_nonce) == BrowserNonceHash`
   (constant-time). Mismatch or absence → refuse, no redirect.
3. **Stop minting cookie from URL** — `/login` no longer calls `SetBFFCookie`
   from `request_id` in the query string. The cookie MUST already be present (set
   by `/authorize`).
4. **Absolute redirect** — replace the relative `/authorize/complete?...` with an
   absolute, configured `AUTHORIZE_COMPLETE_URL`. harbor-mgmt fails closed at boot
   if the env var is unset.
5. **Topology documentation** — document the one-public-host / path-routed ingress
   constraint imposed by the `__Host-` cookie prefix in `deploy/README.md` and
   Helm values.

## Non-goals

- Changing the WebAuthn ceremony cookie (`harbor_webauthn_session`) — already
  one-time-use via `SessionStore.Take`.
- Supporting split-host (harbor-hot and harbor-mgmt on different public hostnames)
  — `__Host-` cookies cannot span two distinct origins; that requires a different
  design.
- Changing the `BFFSessionStore` interface — nonce rides on `BFFSessionRecord`,
  no new methods needed.
