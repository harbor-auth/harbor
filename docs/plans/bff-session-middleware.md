---
title: BFF session middleware (§9 — secure browser session, real login identity)
status: draft
design_refs: [§9, §11.1, §11.2]
targets: [internal/oidc/, internal/webauthn/, cmd/harbor-mgmt/, cmd/harbor-hot/]
promoted_to: null
openspec: changes/bff-session-middleware
created: 2026-07-14
---

# BFF session middleware (plan)

> **Dependency order:** depends on **`user-enrollment`** (needs real `users.id`
> values in the DB) and **`session-ppid-seam`** (the BFF session feeds the
> real `SessionResolver`). Build after both. This is the last scaffold removed
> before a real end-to-end login is possible.

## Problem

`internal/webauthn/handlers.go` reads the user identity from a raw
**`user_id` query parameter** — a dev-only hack documented with:

> "SCAFFOLD: the identity is read from the base64url `user_id` query parameter …
> deliberate placeholder until the BFF session middleware lands"

This means any HTTP client can impersonate any user by supplying an arbitrary
`user_id`. The passkey ceremonies (`/webauthn/registration/begin`,
`/webauthn/assertion/begin`) are therefore completely bypassed as an
authentication gate — the RP calls `/authorize`, Harbor auto-approves the demo
user, and no real identity is ever verified. There is no CSRF protection, no
session binding, and no way to know which browser initiated the ceremony.

The BFF (Backend-For-Frontend) session is the architectural answer (§9): a
short-lived, server-side session cookie issued by `harbor-mgmt` that
- Identifies the **browser tab** that started the `/authorize` request (prevents
  cross-tab session fixation).
- Carries the `request_uri` / `state` so the ceremony can resume the OIDC flow
  after passkey verification.
- Holds the authenticated `user_id` after `FinishLogin` so `harbor-hot`'s
  `SessionResolver` can retrieve it without trusting a client-supplied param.

## Proposed approach

Implement the BFF session as a simple, signed, short-lived HTTP-only cookie:

1. **`/authorize` redirects to the login UI with a `request_id`.**
   `harbor-hot` handles `/authorize`, validates the OIDC request, writes a
   short-lived BFF session record (Redis or Postgres; TTL = PKCE `state`
   lifetime ≈ 5 min) keyed by an opaque `request_id`, and redirects the browser
   to `harbor-mgmt/login?request_id=<id>`.

2. **`harbor-mgmt/login` initiates the passkey assertion.**
   Looks up the BFF session record by `request_id`, calls
   `webauthn.BeginAssertion` (keyed to the real `users.id` resolved from the
   session), and sets a `__Host-harbor-bff` HTTP-only, SameSite=Strict, Secure
   cookie carrying the `request_id` (CSRF binding).

3. **Browser completes the passkey ceremony.**
   `FinishAssertion` validates the WebAuthn response, looks up the cookie for
   CSRF binding, writes the authenticated `user_id` back to the BFF session
   record, and redirects back to `harbor-hot/authorize/complete?request_id=<id>`.

4. **`harbor-hot` resumes the OIDC flow.**
   Reads the BFF session record (now has `user_id`), passes it to the real
   `SessionResolver`, which derives the PPID and records consent → issues the
   auth code. The BFF session record is then deleted (one-time use).

5. **Delete the insecure `user_id` query param path** in
   `internal/webauthn/handlers.go`.

### Cookie security properties

- `__Host-` prefix: forces `Secure`, `Path=/`, no `Domain` (hardened against
  subdomain attacks).
- `HttpOnly`: not accessible to JavaScript.
- `SameSite=Strict`: CSRF protection.
- Short TTL (5 min): limits exposure if stolen.
- One-time use: deleted after `FinishAssertion` so replay is impossible.

### BFF session store

Use Redis (same instance as `auth-code-persistence`) with a 5-min TTL.
Keys: `bff_session:<request_id>` → JSON `{state, client_id, redirect_uri, user_id?}`.
In dev (no Redis), use an in-memory map protected by a `sync.Map`.

## DESIGN alignment

Realises §9 (BFF session) and the login-UI redirect step of §11.2 (step 2 of
the OIDC login flow sequence). Closes the last gap that prevents a real user
from logging in without code changes. Does **not** change `DESIGN.md`.

## Target code paths

- `internal/bff/session.go` — `BFFSessionStore` interface + Redis impl + in-memory impl
- `internal/bff/middleware.go` — cookie read/write helpers, `__Host-` enforcement
- `internal/webauthn/handlers.go` — replace `user_id` query param with BFF session lookup
- `internal/oidc/service.go` / `cmd/harbor-hot/main.go` — write BFF session at `/authorize`; read it at the completion step
- `cmd/harbor-mgmt/main.go` — `/login` handler + `FinishAssertion` → write `user_id` to BFF session
- `internal/bff/session_test.go`, `internal/webauthn/handlers_test.go`

## Implementation checklist

- [ ] `BFFSessionStore` interface: `Create(ctx, id, record) error`, `Get(ctx, id) (BFFSessionRecord, bool, error)`, `SetUser(ctx, id, userID) error`, `Delete(ctx, id) error`.
- [ ] Redis implementation of `BFFSessionStore` (TTL = 5 min; JSON encoding).
- [ ] In-memory implementation of `BFFSessionStore` for dev/test.
- [ ] `__Host-harbor-bff` cookie helpers: write (Secure, HttpOnly, SameSite=Strict, Path=/), read, clear.
- [ ] `harbor-hot`: at `/authorize` (after OIDC request validation), write BFF session; redirect to `harbor-mgmt/login?request_id=<id>`.
- [ ] `harbor-mgmt/login`: read BFF session; call `webauthn.BeginAssertion`; set cookie.
- [ ] `harbor-mgmt/login/complete`: validate cookie (CSRF); call `webauthn.FinishAssertion`; write `user_id` to BFF session; redirect to `harbor-hot/authorize/complete`.
- [ ] `harbor-hot/authorize/complete`: read BFF session (must have `user_id`); run `SessionResolver`; delete BFF session; issue auth code.
- [ ] **Delete** the insecure `user_id` query parameter path from `internal/webauthn/handlers.go`.
- [ ] Tests: missing cookie ⇒ 401; tampered `request_id` ⇒ 400; replay (deleted session) ⇒ 400; cross-tab (wrong cookie) ⇒ 400; CSRF binding enforced.
- [ ] Author & verify paired OpenSpec change: `openspec validate bff-session-middleware --strict`
- [ ] Reconcile & promote: `@plan promote bff-session-middleware`

## Risks & open questions

- **Cross-origin redirect**: `harbor-hot` and `harbor-mgmt` run on different ports/origins in dev; the BFF session record must be readable by both (Redis or a shared Postgres table). In prod they share a regional Redis.
- **`request_id` entropy**: 256-bit CSPRNG, base64url-encoded. Never reuse.
- **Concurrent tabs**: each `/authorize` creates its own `request_id`; tab A's BFF session is independent of tab B's. This is by design — no cross-tab sharing.
- **Step-up auth (§11.4)**: sensitive management actions will eventually require a fresh assertion on a live BFF session; leave the session record extensible (`StepUpRequiredAt`, `StepUpCompletedAt`) without implementing step-up in v1.

## Definition of done

`go build/vet/test ./...` green; the insecure `user_id` query param is gone;
a real passkey ceremony drives the `user_id` into the BFF session record;
`harbor-hot`'s `SessionResolver` reads the authenticated identity from the BFF
session (no hardcoded demo user); cookie security properties enforced; CSRF
binding tested; `make agent-check` clean. Ready to `@plan promote`.
