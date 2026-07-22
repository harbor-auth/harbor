---
title: BFF flow wiring — activate the BFF authorize/complete flow in harbor-hot
status: draft
design_refs: [§4.1, §9, §11.2]
targets: [cmd/harbor-hot/]
promoted_to: null
openspec: changes/bff-flow-wiring
created: 2026-07-22
---

# BFF flow wiring (plan)

> **Dependency order:** independent of `webauthn-db-wiring` and
> `redis-enrollment-session` at the code level. Both BFF pieces depend on the
> shared `redisClient` at runtime, so Redis must be available. Land any order;
> can run in parallel on Weft.

## Problem

The BFF (backend-for-frontend) authorize flow is fully implemented but not
active in `cmd/harbor-hot/main.go`. Today the binary:

- Does **not** import `github.com/harbor/harbor/internal/bff`.
- Builds `oidcapi.New(oidcapi.Config{…})` **without** the `BFFSessions`,
  `LoginURL`, or `BFFSessionTTL` fields, so the OIDC API cannot stash a BFF
  session or redirect to the login UI.
- Registers routes via `openapi.HandlerFromMux(srv, http.NewServeMux())`
  **without** wiring `GET /authorize/complete` — the endpoint that resumes the
  OIDC flow after passkey authentication (`srv.GetAuthorizeComplete`).

The net effect: `harbor-hot` still runs the legacy `FixedAuthSource`, and the
real, per-request BFF login handoff (§9, §11.2) never engages even when Redis
and a login URL are configured.

## Proposed approach

Make the BFF flow the active path when its dependencies are present, without
removing the legacy fallback:

1. Import `github.com/harbor/harbor/internal/bff`.
2. Add `const bffSessionTTL = 5 * time.Minute`.
3. Read `loginURL := os.Getenv("LOGIN_URL")`.
4. When `redisClient != nil && loginURL != ""`, construct
   `bffStore := bff.NewRedisBFFSessionStore(redisClient, bffSessionTTL)` and set
   `BFFSessions: bffStore`, `LoginURL: loginURL`, `BFFSessionTTL: bffSessionTTL`
   on the `oidcapi.Config`.
5. Build the mux explicitly before passing to HandlerFromMux so the resume
   endpoint is registered:
   ```go
   mux := http.NewServeMux()
   mux.HandleFunc("GET /authorize/complete", srv.GetAuthorizeComplete)
   handler := openapi.HandlerFromMux(srv, mux)
   ```
6. If `redisClient == nil` or `loginURL == ""`, log a `Warn` that BFF auth is
   not active and the legacy `FixedAuthSource` remains in effect.

All referenced types/functions already exist — this is wiring only, confined to
`cmd/harbor-hot/main.go`.

## DESIGN alignment

Activates the BFF login handoff that fronts the authorization endpoint (§9
enrollment/registration handoff, §11.2 login → consent). No behaviour is
invented here; the plan connects existing, tested components and preserves the
legacy path as an explicit, logged fallback. Does **not** change `DESIGN.md`.

## Target code paths

- `cmd/harbor-hot/main.go` — import `bff`; add `bffSessionTTL`; read `LOGIN_URL`;
  conditionally set `BFFSessions`/`LoginURL`/`BFFSessionTTL`; build an explicit
  mux and register `GET /authorize/complete`; warn on the legacy fallback.

Explicitly **not** touched:
- `internal/bff/` — all implementations are complete.
- `internal/oidcapi/` — `GetAuthorizeComplete` and the config fields already exist.
- Generated OpenAPI handler — `GET /authorize/complete` is intentionally NOT in
  the spec (it is a Harbor-internal redirect endpoint, not a public API).

## Implementation checklist

- [ ] Add import `github.com/harbor/harbor/internal/bff`.
- [ ] Add `const bffSessionTTL = 5 * time.Minute`.
- [ ] Read `loginURL := os.Getenv("LOGIN_URL")`.
- [ ] When `redisClient != nil && loginURL != ""`: build `bffStore` and set the
      three config fields (`BFFSessions`, `LoginURL`, `BFFSessionTTL`).
- [ ] Build an explicit `mux := http.NewServeMux()`, register
      `GET /authorize/complete` → `srv.GetAuthorizeComplete`, then call
      `openapi.HandlerFromMux(srv, mux)`.
- [ ] Warn when `redisClient == nil` or `loginURL == ""` (BFF auth not active;
      legacy `FixedAuthSource` still in effect).
- [ ] Author & verify paired OpenSpec change: `openspec validate bff-flow-wiring --strict`.
- [ ] Reconcile & promote: `@plan promote bff-flow-wiring`.

## Risks & open questions

- **Partial config:** with only one of `redisClient`/`loginURL` present, the BFF
  flow must stay off (both are required). The explicit `&&` guard plus the `Warn`
  log make the degraded state visible rather than half-wiring the flow.
- **Route ordering:** `GET /authorize/complete` must be registered on the mux
  *before* `openapi.HandlerFromMux` wraps it; the explicit `mux` variable makes
  that ordering unambiguous.
- No data-model risk: no new stores, migrations, or interfaces.

## Definition of done

`go build/vet/test ./...` green; with `redisClient` and `LOGIN_URL` set,
`harbor-hot` serves `GET /authorize/complete` and drives the BFF login handoff;
without them, it logs the legacy-fallback warning and continues on
`FixedAuthSource`; `make agent-check` clean. Ready to `@plan promote`.
