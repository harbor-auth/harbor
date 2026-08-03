> **Cross-references:** [trust-model](trust-model.md) (§2.1–2.3) · [privacy-positioning](privacy-positioning.md) (§2.4) · [deploy/README.md](../../../deploy/README.md) (single-public-host, path-routed BFF topology) · code: `internal/bff/signup.go`, `internal/bff/signin.go`, `internal/bff/returnto.go`

# Public Signup / Sign-In CTA URL Contract

| | |
|---|---|
| Status | implemented |
| Audience | external teams building the Harbor Cloud marketing site and demo |
| Code | `internal/bff/signup.go`, `internal/bff/signin.go`, `internal/bff/returnto.go`, `cmd/harbor-mgmt/main.go` |
| Verified by | `internal/bff/signup_cta_contract_test.go` (`go test ./internal/bff/... -run TestSignupCTAContract`) |
| Last reconciled | 2026-08-03 |

## Purpose

This is the **stable, versioned URL contract** that external sites (the Harbor
Cloud marketing site, the public demo) link against to send a visitor into
Harbor's passkey signup or sign-in journey. It documents only behavior that
exists in the merged code today — no certifications, deletion timing,
anonymity, or "zero knowledge" claims are made anywhere in this contract (see
[privacy-positioning](privacy-positioning.md) §2.4 for what Harbor does and
does not promise). Changes to any URL, parameter, or status code documented
here are breaking changes and require a new path or an explicit version bump
to this doc — external callers should be able to link to these URLs today and
have that link keep working.

## Prerequisite: single public host, path-routed topology

Every URL below is served by **harbor-mgmt** and must be reached through the
**same public hostname** the OIDC hot path (harbor-hot) is served from — see
[deploy/README.md § BFF Topology](../../../deploy/README.md#bff-topology--single-public-host-required)
for why the `__Host-` session cookies these routes set cannot span two
hostnames. A marketing/demo CTA is therefore always a link to
`https://auth.example.com/signup` (or `/signin`), never to a separate
harbor-mgmt-only hostname.

## The three published URLs

### 1. `GET /signup`

- **Auth:** none (pre-session, public).
- **Response:** `200 text/html`, `Content-Type: text/html; charset=utf-8`.
- **Body:** the privacy-promise copy plus a region picker built from the
  server's own accepted region list (currently EU / US / APAC). Selecting a
  region and submitting the form on this page is what actually starts
  enrollment — it `POST`s JSON to the existing `POST /enroll` endpoint.
- **Query parameters:** none are required, and none are read by the handler
  today. A request such as `GET /signup?return_to=...&region=...` still
  returns the same `200` page — the parameters are accepted (no error) but
  are currently **inert**: the region is chosen in-page via the radio-button
  form, not pre-selected from a `region` query value, and a `return_to` value
  supplied here is **not** carried into the rest of the journey (there is no
  session-state carrier wired yet — see [Known gaps](#known-gaps-follow-on-work)).
  External callers may append these parameters for forward-compatibility but
  must not depend on them having an effect yet.

### 2. `GET /signup?return_to=<url>&region=<code>`

Identical endpoint to (1) — documented as its own row only because it is the
literal CTA shape marketing/demo links are expected to use once `return_to`/
`region` threading ships. As of this writing it behaves exactly as described
above: `200 text/html`, both parameters accepted and ignored.

### 3. `GET /signin?return_to=<url>`

- **Auth:** none (pre-session, public).
- **Response:** `200 text/html`, `Content-Type: text/html; charset=utf-8`.
- **Body:** a discoverable-credential ("passkey") sign-in page with **no
  identifier field** — the browser's own passkey UI supplies the account.
- **`return_to` handling:** validated once, server-side, against the
  `return_to` allowlist (below). The **validated** value (never the raw
  client-supplied one) is embedded into the page for its script to navigate to
  after a successful `POST /login/complete`. An absent or rejected value falls
  back to `/` and is never echoed back to the client.
- **Side effects:** creates a short-lived BFF session record and sets the
  `__Host-harbor-bff` browser-nonce cookie before the page is rendered — this
  is required by the `GET /login` / `POST /login/complete` ceremony the
  page's script drives, but has no visible effect on the response itself
  (still `200`, same body shape regardless of `return_to`).

## `return_to` allowlist semantics

Both `GET /signin` and the post-completion `GET /signup/success` page (reached
only after finishing signup, not itself a CTA target) validate `return_to`
through the same function, `bff.ValidateReturnTo` (`internal/bff/returnto.go`):

- A **same-origin relative path** starting with `/` (and not `//`, which
  browsers treat as protocol-relative to a foreign host) is always accepted.
- An **absolute `https://` URL** (or scheme-less `//host/...`) is accepted
  only when its host exactly matches (case-insensitive) an entry in the
  `RETURN_TO_ALLOWLIST` environment variable — a comma-separated list of
  hostnames configured on harbor-mgmt, e.g.
  `RETURN_TO_ALLOWLIST=marketing.harborauth.com,demo.harborauth.com`. Matching
  is on the host only; include the port in an allowlist entry if the target
  uses a non-default port.
- Anything else — empty, malformed, an opaque scheme (`javascript:`,
  `data:`, ...), an insecure scheme, a foreign host, embedded control
  characters, or a backslash-obfuscated host — silently falls back to `/` and
  is **never** echoed back to the client (closed-set failure mode; no error
  page reveals what was rejected or why).

External sites should link with `return_to` set to their own fully-qualified
`https://` URL and confirm their hostname has been added to harbor-mgmt's
`RETURN_TO_ALLOWLIST` before relying on the redirect — an un-allowlisted host
degrades gracefully to Harbor's own default landing path rather than erroring.

## Region parameter semantics

`GET /signup`'s in-page region picker only ever offers the subset of
`EU` / `US` / `APAC` that `internal/region.Parse` currently accepts
(`internal/bff/signup.go`'s `allowedSignupRegions`) — a region retired from
`region.Parse` disappears from the picker automatically rather than offering a
choice the backend would reject. The region is submitted as a JSON field
(`{"region": "EU"}`) in the `POST /enroll` request the page's own form issues;
it is **not** read from this page's query string (see above).

## Known gaps (follow-on work, not part of this contract yet)

- `return_to` is not yet threaded as session state from `GET /signup` through
  to `GET /signup/success` — only `GET /signin` and `GET /signup/success`
  validate a `return_to` supplied directly on their own URL. Filed as a
  follow-on feature task; this doc will be updated (and the "inert parameter"
  language above removed) once that ships.
- `region` on `GET /signup`'s query string has no effect; the picker's
  in-page radio selection is authoritative.

## Verification

`internal/bff/signup_cta_contract_test.go` builds the real `SignupHandler` /
`SigninHandler` behind a `net/http.ServeMux` (the same `Routes()` wiring
`cmd/harbor-mgmt/main.go` uses) and asserts each of the three published URLs
above returns `200` with `Content-Type: text/html`. Run it with:

```sh
go test ./internal/bff/... -run TestSignupCTAContract -v
```

To check by hand against a running `harbor-mgmt` (with `DATABASE_URL`,
`REDIS_URL`, and the other required env vars set — see
`cmd/harbor-mgmt/main.go`):

```sh
curl -i 'https://auth.example.com/signup'
curl -i 'https://auth.example.com/signup?return_to=https%3A%2F%2Fmarketing.example.com%2Fwelcome&region=EU'
curl -i 'https://auth.example.com/signin?return_to=https%3A%2F%2Fmarketing.example.com%2Fwelcome'
```

Each must return `200` with an `text/html` body containing the region picker
(first two) or the passkey sign-in button (third).
