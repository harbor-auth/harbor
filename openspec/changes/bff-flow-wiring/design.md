# Design: BFF flow wiring

## Key Decisions

### Decision 1: Require BOTH `redisClient` and `loginURL` to activate the BFF flow
**Chosen:** Gate activation on `redisClient != nil && loginURL != ""`.
**Rationale:** The BFF flow needs a shared session store (Redis) *and* a login UI
to redirect to; with only one, the handoff cannot complete. Requiring both keeps
the flow all-on or all-off rather than half-wired.
**Alternatives considered:** Activating on either signal (produces a broken
partial flow, rejected).

### Decision 2: Keep the legacy `FixedAuthSource` as an explicit, logged fallback
**Chosen:** When the BFF dependencies are absent, leave `FixedAuthSource` in
effect and log a `Warn`.
**Rationale:** Local/dev and incremental rollout still need a working authorize
path; a loud warning makes the degraded mode obvious without blocking startup.
Mirrors the pattern used by all other conditional store selections in the codebase.
**Alternatives considered:** Failing startup when BFF is unconfigured (breaks dev
bring-up, rejected).

### Decision 3: Register `GET /authorize/complete` on an explicit mux before wrapping
**Chosen:** `mux := http.NewServeMux(); mux.HandleFunc("GET /authorize/complete", srv.GetAuthorizeComplete); handler := openapi.HandlerFromMux(srv, mux)`.
**Rationale:** The generated `HandlerFromMux` composes over the mux; registering
the resume route on that same mux first guarantees it is served alongside the
generated routes. Naming the mux makes the ordering explicit and reviewable. The
flow test (`internal/bff/flow_test.go`) uses this same pattern, confirming it is
the correct registration approach.
**Alternatives considered:** Passing an inline `http.NewServeMux()` to
`HandlerFromMux` (leaves no place to register the resume route — the current bug,
rejected); a wrapper/multiplexer around the generated handler (unnecessary
complexity, rejected).

### Decision 4: `bffSessionTTL = 5 * time.Minute` as a single named constant
**Chosen:** One `const bffSessionTTL` feeding both the store constructor and the
config's `BFFSessionTTL`.
**Rationale:** A single source prevents the store TTL and the config TTL from
drifting apart; 5 minutes matches the BFF store's documented default and the
value already used in `cmd/harbor-mgmt/main.go`.
**Alternatives considered:** Separate literals at each call site (drift risk,
rejected).
