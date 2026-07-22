---
title: BFF Session Middleware (real login identity, §9)
status: implemented
design_refs: [§9, §11.1, §11.2]
code:  [internal/bff/, internal/oidcapi/, internal/oidc/, cmd/harbor-mgmt/]
spec:  []
tests: [internal/bff/]
depends_on: [user-enrollment, session-ppid-seam, webauthn-session-store]
plan: bff-session-middleware
last_reconciled: 2026-07-20
---

# BFF Session Middleware (real login identity, §9)

## Summary

Harbor authenticates the browser via a short-lived, server-side **Backend-For-
Frontend (BFF) session** instead of trusting a client-supplied `user_id` query
parameter (§9). A `/authorize` request creates an opaque, CSPRNG-keyed BFF
session, redirects the browser through a passkey assertion ceremony, and only
resumes the OIDC flow — issuing an auth code for the *authenticated* user — once
the ceremony writes the real `user_id` back into the session. This closes the
dev-only `?user_id` impersonation hole: no HTTP client can forge another user's
identity, and the passkey ceremony is now a genuine authentication gate
(§11.1, §11.2).

## Behavior (as-built)

**BFF session record & store** — `bff.BFFSessionRecord` carries the ceremony
state: `RequestID` (256-bit CSPRNG, base64url — the store key *and* cookie
value), the OIDC params captured at `/authorize` (`State`, `ClientID`,
`RedirectURI`, `Scope`, `Nonce`, `CodeChallenge`, `CodeChallengeMethod`), the
`UserID` (empty until the passkey ceremony completes), and `ExpiresAt`. The
`bff.BFFSessionStore` seam (`Create` / `Get` / `SetUser` / `Delete`) has two
implementations: `RedisBFFSessionStore` for production (JSON-encoded records
under `bff_session:<request_id>` with a 5-minute TTL and a Lua `SetUser` that
preserves TTL) and `InMemoryBFFSessionStore` for dev/test.

**`__Host-harbor-bff` cookie** — the browser is bound to its ceremony via a
cookie named `__Host-harbor-bff` (`bff.CookieName`). The `__Host-` prefix forces
`Secure`, `Path=/`, and no `Domain`; the cookie is `HttpOnly` (no JS access) and
`SameSite=Strict` (CSRF protection) with a 5-minute max-age
(`bff.DefaultCookieMaxAge`). It is cleared after the auth code is issued.

**Login handlers (`harbor-mgmt`)** — `bff.LoginHandler` exposes `BeginLogin`
(looks up the BFF session, resolves the user, calls WebAuthn `BeginLogin`, sets
the cookie, returns assertion options) and `FinishLogin` (validates the cookie +
BFF session, calls WebAuthn `FinishLogin`, writes `user_id` into the session via
`SetUser`, and redirects to `harbor-hot`'s `/authorize/complete?request_id=<id>`).
`bff.Middleware` reads the cookie, looks up the session, and injects an
authenticated `user_id` into the request context (`bff.UserIDFromContext`) when
present — leaving authorization to the handlers (fail-safe).

**Resuming the OIDC flow (`harbor-hot`)** — `oidcapi.Server.GetAuthorizeComplete`
reads the BFF session (which must now carry a non-empty `UserID`), calls
`oidc.Service.AuthorizeWithUser` to derive the PPID and issue the auth code for
the pre-authenticated user, **deletes** the BFF session (one-time use), clears
the cookie, and redirects to the RP with `code` + `state`. A missing/expired
session or an unset `UserID` renders a safe error page (no open redirect).

**Wiring (`cmd/harbor-mgmt`)** — the mgmt binary wires
`bff.NewRedisBFFSessionStore` when `REDIS_URL` is set and falls back to
`bff.NewInMemoryBFFSessionStore` otherwise; it registers the `/login` +
`/login/complete` routes on `bff.LoginHandler` and wraps the mux with
`bff.Middleware`.

## Interfaces / Endpoints

- `POST /login` (harbor-mgmt) — begin passkey assertion; sets `__Host-harbor-bff`.
- `POST /login/complete` (harbor-mgmt) — finish assertion; writes `user_id`;
  redirects to `/authorize/complete`.
- `GET /authorize/complete` (harbor-hot) — resume the OIDC flow for the
  authenticated user; issue code; delete session.
- Exported Go surface: `bff.BFFSessionStore`, `bff.BFFSessionRecord`,
  `bff.NewRedisBFFSessionStore`, `bff.NewInMemoryBFFSessionStore`,
  `bff.NewLoginHandler`, `bff.Middleware`, `bff.UserIDFromContext`,
  `bff.SetBFFCookie`/`ReadBFFCookie`/`ClearBFFCookie`, `bff.NewRequestID`,
  `bff.ErrBFFSessionNotFound`, `bff.ErrBFFSessionExpired`;
  `oidc.Service.AuthorizeWithUser` + `oidc.AuthorizeWithUserRequest`.

## Code map

| Path | Role |
|---|---|
| `internal/bff/session.go` | `BFFSessionStore` interface, `BFFSessionRecord`, `InMemoryBFFSessionStore`. |
| `internal/bff/session_redis.go` | `RedisBFFSessionStore` — TTL-bounded records, TTL-preserving `SetUser`. |
| `internal/bff/cookie.go` | `__Host-harbor-bff` cookie helpers (Secure, HttpOnly, SameSite=Strict). |
| `internal/bff/auth.go` | `BFFAuthSource` + context helpers — real user identity from session context. |
| `internal/bff/middleware.go` | Cookie→session→context middleware. |
| `internal/bff/login.go` | `LoginHandler` — `BeginLogin` / `FinishLogin`. |
| `internal/bff/requestid.go` | `NewRequestID` — 256-bit CSPRNG session IDs. |
| `internal/oidcapi/authorize.go` | `GetAuthorizeComplete` — resume OIDC flow, issue code, one-time delete. |
| `internal/oidc/service.go` | `AuthorizeWithUser` — issue a code for a pre-authenticated user. |
| `cmd/harbor-mgmt/main.go` | Wires the BFF store, login routes, and middleware. |

## Security & privacy invariants

- **No client-controlled identity (§9)** — the authenticated `user_id` comes
  only from a completed passkey ceremony written server-side into the BFF
  session; the insecure `?user_id` query-param path is gone.
- **CSRF binding** — the `__Host-harbor-bff` cookie (`SameSite=Strict`,
  `HttpOnly`, `Secure`, `__Host-` prefix) binds the ceremony to the originating
  browser tab.
- **One-time use** — the BFF session is deleted after the code is issued; replay
  of a consumed `request_id` fails closed (error page, no redirect).
- **Bounded lifetime** — 5-minute TTL on both the Redis record and the cookie.
- **Open-redirect defense** — an unknown/expired `request_id` or an unset
  `UserID` renders a PII-free error page rather than redirecting.
- **PII-free session state** — the record holds OIDC protocol params and an
  internal `user_id`, no user PII (email/name).

## Tests

`internal/bff/` (in-memory + miniredis):

- `session_test.go` / `session_redis_test.go` — Create/Get/SetUser/Delete,
  TTL expiry, not-found/expired errors, and concurrent-access safety
  (50 goroutines in-memory, 20 against miniredis, `-race`).
- `cookie_test.go` — `__Host-` security properties round-trip.
- `login_test.go` — `BeginLogin`/`FinishLogin` happy path + every error path.
- `flow_test.go` — full BFF flow across `oidcapi` (`/authorize`,
  `/authorize/complete`) and `bff` (`/login`, `/login/complete`): session
  created → cookie set → `user_id` written → code issued; plus
  complete-before-login and unknown-`request_id` error-page cases.
- `security_test.go` — 5 security-property tests.

## Known gaps / TODOs

- **Dev user resolver** — `cmd/harbor-mgmt` currently wires a `devUserResolver`
  that resolves the user from a query param for local development; production
  user resolution (enrollment lookup) is the follow-up.
- **Cross-origin dev** — `harbor-hot` and `harbor-mgmt` run on different origins
  in dev, so the BFF record must be readable by both (shared Redis in prod).
- **Step-up auth (§11.4)** — the record is extensible for future step-up
  (fresh assertion on a live session); not implemented in v1.
