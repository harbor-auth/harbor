---
title: Bind the BFF request_id to the browser (login session fixation)
status: draft
design_refs: [§9, §11.2, §11.7]
targets: [internal/bff/, internal/oidcapi/, cmd/harbor-hot/, cmd/harbor-mgmt/]
promoted_to: null
openspec: changes/fix-bff-session-binding
created: 2026-07-30
---

# Bind the BFF request_id to the browser (plan)

> **Severity: CRITICAL.** Audit findings C3 (session fixation → account takeover)
> and M2 (cross-host redirect) —
> [`audit-2026-07-30-wiring-and-auth.md`](./audit-2026-07-30-wiring-and-auth.md).

## Problem

### C3 — session fixation

`internal/bff/login.go:99,148` sets the browser's `__Host-harbor-bff` cookie to
whatever `request_id` arrives **in the URL query string**:

```go
requestID := r.URL.Query().Get("request_id")   // :99
// ... nothing establishes that THIS browser initiated THIS request_id ...
SetBFFCookie(w, requestID, DefaultCookieMaxAge) // :148
```

The request_id is minted at `/authorize` on harbor-hot and handed to the browser
via a redirect, so there is **no browser binding at creation time**. An
attacker-initiated request_id is indistinguishable from a victim-initiated one:

1. Attacker starts `/authorize` with **their own** registered `client_id` +
   `redirect_uri`; captures `request_id=R` from the redirect.
2. Attacker lures the victim to `https://mgmt.harbor.id/login?request_id=R`.
3. Victim's browser is issued cookie `=R`, performs a normal-looking passkey
   assertion, POSTs `/login/complete`.
4. `FinishLoginWithParsedData` writes the **victim's** userID into session `R`
   (`login.go:279`).
5. `GetAuthorizeComplete` (`oidcapi/authorize.go:216-245`) reads `request_id`
   **from the query string** with no cookie comparison, issues a code for the
   victim, and redirects it to the **attacker's** `redirect_uri`.

`SameSite=Strict` does not defend this: step 2 is a top-level navigation so the
cookie is *set* normally, and step 3 is same-site.

### M2 — the redirect that cannot work

`internal/bff/login.go:294` builds a **relative** `"/authorize/complete?..."`,
which resolves against the harbor-mgmt origin. `/authorize/complete` is
registered on **harbor-hot** (`cmd/harbor-hot/main.go:236`). Unless both binaries
share one hostname — contradicting `WEBAUTHN_RP_ORIGINS` being "the dashboard/BFF
origin, NOT the issuer" — this 404s at the last step of every login. Both bugs
live in the same two files, so they are fixed together.

## Proposed approach

Introduce a **browser nonce** that is minted where the flow starts and proven at
every subsequent step. The `request_id` stays the server-side session key; the
nonce is what ties that session to one browser.

1. **Mint at `/authorize`** (`oidcapi/authorize.go:authorizeWithBFFSession`):
   generate a second 256-bit CSPRNG value, store its **SHA-256** on the
   `BFFSessionRecord` as `BrowserNonceHash`, and set it in the
   `__Host-harbor-bff` cookie **before** redirecting to `LOGIN_URL`. Store the
   hash, not the value, so a store compromise does not yield live cookies.
2. **Require at `/login`** (`bff.LoginHandler.BeginLogin`): read the cookie,
   hash it, constant-time compare against the looked-up session. On mismatch or
   absence, refuse — do **not** set a cookie from the URL. This is the line that
   kills the fixation.
3. **Require at `/login/complete`**: same check before `SetUser`.
4. **Require at `/authorize/complete`**: same check before `AuthorizeWithUser`.
   Failure renders the existing no-redirect error page — never a redirect to a
   URI whose session ownership is unproven (§11.7).
5. **Cookie scope.** `__Host-` forces `Path=/` and no `Domain`, so the cookie
   cannot be shared between two different hosts. If harbor-hot and harbor-mgmt
   are on different hosts, `__Host-` cannot span them. Resolve this explicitly:
   **the supported topology is one public host fronting both binaries** (path-routed
   ingress: `/login*` → mgmt, everything else → hot). Document it in
   `deploy/README.md`, and make the M2 fix an **absolute** redirect built from a
   new `AUTHORIZE_COMPLETE_URL` (or the issuer) rather than a relative path — so
   a split-host deployment fails loudly at config time instead of 404-ing at
   runtime.
6. Extend `BFFSessionStore` with the nonce field. Both the in-memory and Redis
   implementations must round-trip it; the Redis record is JSON so this is
   additive.

### Rejected alternatives

- *Signed/encrypted request_id.* Proves Harbor minted it, not that **this
  browser** received it. Does not stop fixation.
- *Origin/Referer checks only.* Weaker (headers are strippable in some flows) and
  does not bind the specific session.

## DESIGN alignment

Serves §9 (BFF session is the authenticated seam), §11.2 (login ceremony), §11.7
(never redirect to an unproven URI). No DESIGN change — this closes a gap between
the design's intent and the implementation.

## Target code paths

- `internal/bff/session.go` — `BrowserNonceHash` on the record; store interface
- `internal/bff/session_redis.go` — round-trip the field
- `internal/bff/cookie.go` — mint/compare helpers (constant-time)
- `internal/bff/login.go` — require the nonce at both `/login` steps; absolute redirect
- `internal/oidcapi/authorize.go` — mint at `/authorize`, require at `/authorize/complete`
- `cmd/harbor-hot/main.go`, `cmd/harbor-mgmt/main.go` — new config for the absolute URL
- `deploy/README.md`, `deploy/helm/` — document + configure the single-host topology

## Implementation checklist

- [ ] Add `BrowserNonceHash []byte` to `BFFSessionRecord`; update both stores
- [ ] Mint nonce + set cookie in `authorizeWithBFFSession` **before** the login redirect
- [ ] Constant-time `subtle.ConstantTimeCompare` gate in `BeginLogin`, `FinishLogin`, `GetAuthorizeComplete`
- [ ] Replace the relative `/authorize/complete` redirect with an absolute, configured URL; fail closed at boot if unset
- [ ] Document the single-public-host / path-routed ingress topology
- [ ] Tests: **fixation** — attacker-minted `request_id` + victim browser ⇒ `/login` refuses, no code is ever issued (this is the headline test; name it so)
- [ ] Tests: missing cookie, wrong cookie, expired session ⇒ uniform refusal, no `Location` header
- [ ] Tests: happy path still completes end-to-end through the e2e harness
- [ ] Tests: nonce is never logged and never returned in a response body
- [ ] Author & verify paired OpenSpec change: `@openspec new fix-bff-session-binding` then `openspec validate fix-bff-session-binding --strict`
- [ ] Reconcile & promote: `@plan promote fix-bff-session-binding`

## Risks & open questions

- **Topology decision is load-bearing.** If Harbor must support hot and mgmt on
  separate public hosts, `__Host-` prefixed cookies cannot span them and this
  design needs a different carrier (e.g. a signed handoff token in the redirect
  that is exchanged for a host-local cookie). Confirm the single-host assumption
  before building; if it is wrong, stop and re-plan rather than dropping the
  `__Host-` prefix.
- Existing in-flight sessions are invalidated on deploy. Acceptable — the BFF
  session TTL is 5 minutes.
- Do **not** change the WebAuthn ceremony cookie (`harbor_webauthn_session`) in
  this feature; it is already one-time-use via `SessionStore.Take`.

## Definition of done

- A session created by one browser cannot be advanced or completed by another,
  proven by an explicit fixation regression test.
- `/login`, `/login/complete`, `/authorize/complete` all fail closed without a
  matching browser nonce.
- The post-login redirect is absolute and validated at boot.
- `go build ./...`, `go vet ./...`, `go test ./...`, `make agent-check`, and the
  e2e login flow all green.
