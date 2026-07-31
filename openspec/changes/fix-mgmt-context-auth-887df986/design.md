# Design: CallerSource seam for mgmtapi caller identity

## Arch boundary

`internal/mgmtapi` cannot import `internal/bff` directly:
`bff/dashboard.go` already imports `mgmtapi` (for `AuditTrailDeps`), so a
direct import would create a circular dependency that the arch test enforces.

## Solution: injected interface

```go
// internal/mgmtapi/caller.go
type CallerSource interface {
    CallerID(ctx context.Context) string
}
```

The production adapter lives in `cmd/harbor-mgmt` and wraps
`bff.UserIDFromContext`. It is injected at startup via
`(*Server).WithCallerSource(src CallerSource)`.

Test code uses `fakeCallerSource{userID: "..."}` — a trivial in-package stub.

## callerID helper

```go
func (s *Server) callerID(w http.ResponseWriter, r *http.Request, ep telemetry.EndpointName) (string, bool) {
    var userID string
    if s.callerSource != nil {
        userID = s.callerSource.CallerID(r.Context())
    }
    if userID == "" {
        recordError(ep, "unauthorized")
        s.writeError(w, http.StatusUnauthorized, "unauthorized", "user authentication required")
        return "", false
    }
    return userID, true
}
```

Every user-scoped endpoint calls this helper instead of
`r.Header.Get("X-Harbor-User-ID")`. Handlers return immediately on `ok=false`.

## Unauthenticated endpoints

`POST /enroll`, `POST /recovery/begin`, `POST /recovery/complete` legitimately
have no session yet and do **not** call `callerID`.
