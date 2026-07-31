# Technical Design: fix-mgmt-context-auth

## Architecture decision: CallerSource interface (not direct bff import)

`internal/bff/dashboard.go` already imports `internal/mgmtapi`. A direct import of
`internal/bff` from `internal/mgmtapi` would create a package cycle. The arch test
(`internal/arch/arch_test.go`) enforces import boundaries via `go list -deps`.

Instead, define a tiny interface in `internal/mgmtapi`:

```go
// CallerSource resolves the authenticated caller's user ID from the request
// context. The production implementation reads from the BFF session context
// (bff.UserIDFromContext); tests use a fake.
type CallerSource interface {
    CallerID(ctx context.Context) string
}
```

The concrete adapter lives in `cmd/harbor-mgmt` (the only package that can import both):

```go
type bffCallerAdapter struct{}
func (bffCallerAdapter) CallerID(ctx context.Context) string {
    return bff.UserIDFromContext(ctx)
}
```

Wired via: `mgmtServer.WithCallerSource(bffCallerAdapter{})`

## Shared helper

```go
func (s *Server) callerID(w http.ResponseWriter, r *http.Request,
    endpoint telemetry.EndpointName) (string, bool) {
    if s.callerSource == nil {
        recordError(endpoint, "unauthorized")
        s.writeError(w, http.StatusUnauthorized, "unauthorized",
            "user authentication required")
        return "", false
    }
    userID := s.callerSource.CallerID(r.Context())
    if userID == "" {
        recordError(endpoint, "unauthorized")
        s.writeError(w, http.StatusUnauthorized, "unauthorized",
            "user authentication required")
        return "", false
    }
    return userID, true
}
```

Every handler replaces `r.Header.Get(UserIDHeader)` with `s.callerID(w, r, endpoint)`.

## Test approach

- Unit tests: inject `fakeCallerSource("user-123")` via `WithCallerSource`; for
  unauthenticated cases inject `fakeCallerSource("")` or `nil`.
- Negative unit test: header present but no session → 401 (CallerSource returns "").
- Negative unit test: header with user-B alongside session for user-A → scoped to user-A.
- Regression guard: source-scan test (`internal/arch` style) that fails if
  `X-Harbor-User-ID` or `UserIDHeader` reappears in `internal/mgmtapi/`.
- E2E: rely on BFF cookie from enrollment flow; skip gracefully if not wired.

## DESIGN alignment

- §9: BFF session is the only authenticated seam — this change enforces it.
- §6.5: PII-free, non-enumerable 401 envelope — unchanged.
- §4.1/§6.1: import boundary preserved (no new mgmtapi→bff edge).
