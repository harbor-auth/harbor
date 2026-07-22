# fix-auth-bypass — Remove FixedAuthSource / stub resolver from harbor-hot

> **Priority:** P0 (Wave 6, production-readiness audit blocker 1.1)
> **Effort:** 2–4 h · **Root feature** (consumes the completed `bff-flow-wiring` seam)

## Problem

`cmd/harbor-hot/main.go` `run()` wires the OIDC service with a hardcoded auth
identity — every `/authorize` issues tokens for the same demo user regardless
of who is calling:

```go
oidcSvc := oidc.NewService(oidc.ServiceConfig{
    ...
    Sessions: oidc.NewStubSessionResolver("demo-user-ppid"),
    ...
})
```

(The DB-wired variant uses `oidc.NewFixedAuthSource("00000000-0000-0000-0000-000000000001")`
inside a `PPIDSessionResolver` — same bypass, different spelling.)

This is a **total authentication bypass**. The `bff-flow-wiring` feature
(`feat_90b6e7b2`, completed) already built everything needed on the service
side:

- `bff.BFFAuthSource` (`internal/bff/auth.go`) — reads the authenticated
  user_id from the request context set by the BFF session middleware; returns
  `ErrNotAuthenticated` (fail-closed) when absent.
- `oidc.PPIDSessionResolver` (`internal/oidc/resolver.go`) — the real
  `SessionResolver`: authenticates via `AuthSource`, derives the per-RP PPID,
  records consent. Fail-closed on every error path.
- `Service.ValidateAuthorizeRequest` + `Service.AuthorizeWithUser`
  (`internal/oidc/service.go`) — the BFF flow: validate → create BFF session →
  redirect to login UI → `/authorize/complete` issues the code for the
  session's real user.
- `oidcapi.Config.BFFSessions` / `LoginURL` (`internal/oidcapi/server.go`) —
  when set, `/authorize` uses the BFF flow instead of the legacy immediate-code
  `Authorize` path.

**This is a pure wiring gap in `main.go`** — no new service code is needed.

## Fix

In `cmd/harbor-hot/main.go` `run()`:

1. **Wire the BFF session store**: Redis-backed (`bff` Redis store) when
   `REDIS_URL` is set; in-memory only as an explicit dev fallback with a loud
   `logger.Warn`. Pass it as `oidcapi.Config.BFFSessions` together with
   `LoginURL` from env `LOGIN_URL` (e.g. `https://mgmt.harbor.id/login`).
2. **Replace the resolver**: construct
   `oidc.NewPPIDSessionResolver(oidc.PPIDSessionResolverConfig{ Auth: bff.NewBFFAuthSource(), Loader: <secret loader>, Grants: <grant store> })`
   and pass it as `ServiceConfig.Sessions`. Use `clients.DBSecretLoader` +
   DB grant store when `DATABASE_URL` is set (matching the existing DB wiring
   pattern); the in-memory loader/grant store remain a dev-only fallback.
3. **Delete every occurrence** of `NewStubSessionResolver` / `NewFixedAuthSource`
   from `cmd/` (both harbor-hot and any harbor-mgmt dev wiring that reaches
   production paths). They may remain in `_test.go` files only.
4. **Fail-closed startup guard**: if `HARBOR_ENV=production` (or `DATABASE_URL`
   is set) and the BFF flow is not fully configured (no `LOGIN_URL` or no BFF
   session store), refuse to start with a clear error. A production binary must
   never fall back to the legacy `Authorize` path with a stub identity.

## Correctness invariants

- An `/authorize` request with **no established BFF/WebAuthn session** must
  never mint an authorization code directly — it must redirect to the login UI
  (BFF flow) or error. `BFFAuthSource.AuthenticatedUserID` returning
  `ErrNotAuthenticated` must surface as an auth failure, never as a fallback
  identity.
- The user_id used for code issuance must come **only** from the BFF session
  established by a completed passkey ceremony — never from a query param, form
  field, or constant.
- PPID derivation stays fail-closed (`PPIDSessionResolver` already enforces
  this — do not weaken it).

## Tests

- `cmd/harbor-hot` wiring test (or e2e): with BFF configured, `GET /authorize`
  with a valid client returns a **302 to the login URL** (not a code).
- E2E happy path: passkey login → `/authorize/complete` → code → `/token`
  yields tokens whose `sub` is the PPID for the **logged-in** user; two
  different users get different `sub`s for the same client.
- Negative: `/authorize/complete` without an authenticated BFF session → error,
  no code issued.
- Grep-gate test (or CI check): `NewFixedAuthSource|NewStubSessionResolver`
  does not appear in any non-test file under `cmd/`.

## No scaffold remains

After this change, `FixedAuthSource` and `stubSessionResolver` are referenced
only by tests inside `internal/oidc`. Update
`docs/plans/production-readiness.md` row 1.1 → Resolved in the same change.
