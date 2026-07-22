# Tasks: BFF flow wiring

## Prerequisites

- [ ] `bff.NewRedisBFFSessionStore` exists (`internal/bff/session_redis.go`).
- [ ] `oidcapi.Config` has `BFFSessions`, `LoginURL`, and `BFFSessionTTL` fields
      (`internal/oidcapi/server.go`).
- [ ] `srv.GetAuthorizeComplete` exists (`internal/oidcapi/authorize.go`).
- [ ] `redisClient` is already constructed in `cmd/harbor-hot/main.go`.

## Implementation

- [ ] Add import `github.com/harbor/harbor/internal/bff`.
- [ ] Add `const bffSessionTTL = 5 * time.Minute`.
- [ ] Read `loginURL := os.Getenv("LOGIN_URL")`.
- [ ] When `redisClient != nil && loginURL != ""`: build
      `bffStore := bff.NewRedisBFFSessionStore(redisClient, bffSessionTTL)` and set
      `BFFSessions: bffStore`, `LoginURL: loginURL`, `BFFSessionTTL: bffSessionTTL`
      on the `oidcapi.Config`.
- [ ] Build an explicit `mux := http.NewServeMux()`; register
      `mux.HandleFunc("GET /authorize/complete", srv.GetAuthorizeComplete)`;
      then `handler := openapi.HandlerFromMux(srv, mux)`. This replaces the
      current inline `openapi.HandlerFromMux(srv, http.NewServeMux())`.
- [ ] Log `Warn` when `redisClient == nil` or `loginURL == ""` that BFF auth is
      not active and the legacy `FixedAuthSource` is still in effect.

## Tests

- [ ] No new unit tests required — `GetAuthorizeComplete` and the BFF store are
      already covered; rely on `go build` + `go vet` + `go test` for the wiring
      change.
- [ ] Smoke check: with `redisClient` and `LOGIN_URL` set, confirm
      `GET /authorize/complete` returns a non-404; without them, confirm the
      legacy-fallback `Warn` is logged at startup.

## Validation

- [ ] `go build ./... && go vet ./... && go test ./...`
- [ ] `make agent-check`
- [ ] `openspec validate bff-flow-wiring --strict`
