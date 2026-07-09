---
title: WebAuthn Passkey Registration & Login
status: implemented
design_refs: [§3.1, §7.1, §9, §6.5]
code:  [internal/webauthn/, cmd/harbor-mgmt/]
spec:  []
tests: [internal/webauthn/]
depends_on: []
plan: null
last_reconciled: 2026-07-08
---

# WebAuthn Passkey Registration & Login

## Summary

Passkeys (FIDO2/WebAuthn) are Harbor's primary, phishing-resistant authentication
factor (docs/DESIGN.md §3.1). `internal/webauthn` implements the registration and
assertion ceremonies on top of the certified `go-webauthn` library, wired into
the management/cold-path binary `cmd/harbor-mgmt`. It follows §1.7's pure-core /
thin-I/O split: the ceremony engine delegates to the library while all
persistence sits behind the `Store` / `SessionStore` interfaces, so the sqlc-backed
credential/session stores plug in later without touching ceremony code.

## Behavior (as-built)

**Four ceremony endpoints** (all `POST`, JSON in/out):

- `/webauthn/register/begin` → returns `CredentialCreation` options; stores the
  challenge under an opaque session key set as an HttpOnly cookie.
- `/webauthn/register/finish` → parses the attestation, verifies it against the
  stored challenge, and persists the new passkey.
- `/webauthn/login/begin` → returns `CredentialAssertion` options + session cookie.
- `/webauthn/login/finish` → validates the assertion, runs **clone detection**,
  and persists the advanced signature counter.

**Ceremony session** — the `harbor_webauthn_session` cookie (`HttpOnly`, `Secure`,
`SameSite=Strict`, `Path=/webauthn`, `MaxAge=300`) carries only an opaque lookup
key, not a bearer token. `SessionStore.Take` is **one-time-use** (it deletes the
entry) and treats an expired entry (5-minute TTL) as absent, so a challenge can't
be replayed.

**Clone detection (§3.1)** — on `FinishLogin`, a `CloneWarning` from the library
(sign-count regression) **fails closed** with `ErrClonedAuthenticator` and the
stored counter is *not* updated. The in-memory store adds a second, defensive
monotonicity guard: an update that doesn't strictly advance the counter (after
the first assertion) is refused with `ErrSignCountRegression`.

**IDOR guard (§9)** — the ceremony user handle is read from a client-supplied
base64url `user_id` query param **only** when `allowInsecureUserID` is true (a
dev-only path). When false (the production default) every endpoint refuses with
`501 not_implemented` and never reads the param. In production the identity must
come from the authenticated dashboard session; this gate is a scaffold until the
BFF session middleware lands.

**Enumeration-safe errors (§6.5)** — `ErrUserNotFound` deliberately has **no**
distinct response: it collapses into the generic `invalid_request` (400), so an
unknown user is indistinguishable from a malformed ceremony. `ErrSessionNotFound`
→ `session_expired` (400); `ErrClonedAuthenticator` → `cloned_authenticator`
(401); any other error → generic `invalid_request` (400). No PII in any message.

**Storage** — `InMemoryStore` / `InMemorySessionStore` are dev/test only (no
encryption at rest); production uses the sqlc-backed users/credentials/sessions
queries behind the same interfaces.

## Interfaces / Endpoints

- Endpoints: the four `POST /webauthn/{register,login}/{begin,finish}` routes.
- Exported Go: `RegisterRoutes(mux, svc, allowInsecureUserID)`, `NewHandler`,
  `NewService`, `Config`, `Store` / `SessionStore` interfaces,
  `InMemoryStore` / `InMemorySessionStore`, `User` / `NewUser`, and the error
  vars (`ErrUserNotFound`, `ErrSessionNotFound`, `ErrClonedAuthenticator`,
  `ErrSignCountRegression`).
- Env vars (`cmd/harbor-mgmt`): `PORT`, `WEBAUTHN_RP_ID`,
  `WEBAUTHN_RP_DISPLAY_NAME`, `WEBAUTHN_RP_ORIGINS`,
  `WEBAUTHN_ALLOW_INSECURE_USER_ID` (default `false`; logs a loud warning when on).

## Code map

| Path | Role |
|---|---|
| `internal/webauthn/user.go` | Package doc + the `User` value implementing `gowebauthn.User`. |
| `internal/webauthn/service.go` | Ceremony engine — Begin/Finish for register + login, clone-detection fail-closed. |
| `internal/webauthn/store.go` | `Store` / `SessionStore` interfaces + in-memory impls, one-time sessions, sign-count monotonicity guard. |
| `internal/webauthn/handlers.go` | HTTP handlers, the `allowInsecureUserID` IDOR gate, enumeration-safe error mapping, session-cookie helpers. |
| `cmd/harbor-mgmt/main.go` | Wires the ceremonies into harbor-mgmt; RP config + insecure-user-id flag + dev demo user. |

## Security & privacy invariants

- **Phishing-resistant primary factor (§3.1)** — passkeys, no shared secret.
- **IDOR defense (§9)** — client-supplied identity refused in production (501);
  never trusted as the authenticated subject.
- **Clone detection fails closed (§3.1)** — sign-count regression rejects the
  login and never persists a backwards counter.
- **Challenge replay defense** — one-time, short-TTL ceremony sessions.
- **No user enumeration (§6.5)** — unknown-user collapses to a generic error;
  all messages are PII-free.
- **No cross-user / cross-region enumeration surface (§5)** — lookups are by the
  opaque user handle only.
- **Cookie hardening (§7.4, §9)** — `HttpOnly` + `Secure` + `SameSite=Strict`.

## Tests

`internal/webauthn/` unit tests cover the handlers (IDOR 501-when-disabled guard,
enumeration-safe 400 for unknown users, missing/invalid `user_id`, missing
cookie), the service ceremonies and clone-detection fail-closed path, the store
(one-time sessions, TTL expiry, sign-count monotonicity), and the `User` value.

## Known gaps / TODOs

- **Storage is in-memory / dev only** — the sqlc-backed users/credentials/sessions
  stores (db/queries) are not yet wired behind the interfaces.
- **`allowInsecureUserID` is a scaffold** — replace with the authenticated BFF
  session as the identity source (§9); the demo user is seeded only in that mode.
- **MFA / step-up (§7.1)** and passkey management UI (§9) are out of scope here.
