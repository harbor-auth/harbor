# Proposal: BFF flow wiring — activate the BFF authorize/complete flow in harbor-hot

## Problem

The BFF authorize flow is implemented but inert in `cmd/harbor-hot/main.go`. The
binary does not import `internal/bff`, builds `oidcapi.New(oidcapi.Config{…})`
without the `BFFSessions`, `LoginURL`, or `BFFSessionTTL` fields, and registers
routes via `openapi.HandlerFromMux(srv, http.NewServeMux())` without wiring
`GET /authorize/complete` (`srv.GetAuthorizeComplete`). So `harbor-hot` stays on
the legacy `FixedAuthSource` and the real per-request BFF login handoff (§9,
§11.2) never engages, even when Redis and a login URL are configured.

## Proposed Solution

Wire the BFF flow in `cmd/harbor-hot/main.go` only:

1. Import `github.com/harbor/harbor/internal/bff`.
2. Add `const bffSessionTTL = 5 * time.Minute`.
3. Read `loginURL := os.Getenv("LOGIN_URL")`.
4. When `redisClient != nil && loginURL != ""`, build
   `bffStore := bff.NewRedisBFFSessionStore(redisClient, bffSessionTTL)` and set
   `BFFSessions: bffStore`, `LoginURL: loginURL`, `BFFSessionTTL: bffSessionTTL`
   on the config.
5. Build an explicit `mux`, register `GET /authorize/complete`, then pass it to
   `openapi.HandlerFromMux`:
   ```go
   mux := http.NewServeMux()
   mux.HandleFunc("GET /authorize/complete", srv.GetAuthorizeComplete)
   handler := openapi.HandlerFromMux(srv, mux)
   ```
6. Warn when `redisClient == nil` or `loginURL == ""` (BFF auth not active;
   legacy `FixedAuthSource` still in effect).

All referenced types/functions already exist.

## Non-Goals

- No changes to `internal/bff`, `internal/oidcapi`, or the OpenAPI-generated
  handler (`GetAuthorizeComplete` and the config fields already exist).
- No new stores, migrations, or interfaces.
- Not removing the legacy `FixedAuthSource` — it remains the explicit fallback.
- `GET /authorize/complete` will NOT be added to the OpenAPI spec — it is a
  Harbor-internal redirect endpoint, not a public API surface.

## Success Criteria

- [ ] With `redisClient != nil && loginURL != ""`, the config carries
      `BFFSessions`, `LoginURL`, and `BFFSessionTTL`, and `GET /authorize/complete`
      is served.
- [ ] With either dependency missing, a `Warn` logs that BFF auth is not active
      and the legacy `FixedAuthSource` is still in effect.
- [ ] `bffSessionTTL` is `5 * time.Minute`.
- [ ] Only `cmd/harbor-hot/main.go` changes.
- [ ] `go build ./... && go vet ./... && go test ./...` pass.
- [ ] `make agent-check` clean.
