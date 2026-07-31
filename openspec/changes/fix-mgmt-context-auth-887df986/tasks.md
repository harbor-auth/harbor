# Tasks: fix-mgmt-context-auth

## Prerequisites
- Go 1.25, no external dependencies added
- `internal/arch/arch_test.go` confirms mgmtapi cannot import bff (circular)

## Implementation

### T1: Define CallerSource interface and callerID helper in mgmtapi
Add `internal/mgmtapi/caller.go` with:
- `CallerSource` interface (`CallerID(ctx context.Context) string`)
- `(*Server).callerID(w, r, endpoint) (string, bool)` shared helper
- `(*Server).WithCallerSource(src CallerSource) *Server` wiring method
- `callerSource CallerSource` field on `Server`
- `fakeCallerSource` type for tests

### T2: Wire BFF adapter in cmd/harbor-mgmt
Add `bffCallerAdapter` in `cmd/harbor-mgmt/main.go` (or a new file there) adapting
`bff.UserIDFromContext` to `mgmtapi.CallerSource`. Call `mgmtServer.WithCallerSource`.
Files: `cmd/harbor-mgmt/main.go` (or new `cmd/harbor-mgmt/caller.go`)

### T3 (atomic): Convert all 14 call sites + delete UserIDHeader + migrate unit tests
- `internal/mgmtapi/consent.go`: 2 sites
- `internal/mgmtapi/relay.go`: 7 sites
- `internal/mgmtapi/compliance.go`: 2 sites
- `internal/mgmtapi/audit.go`: 1 site
- `internal/mgmtapi/mfa.go`: 1 site (via existing mfaUserID helper)
- `internal/mgmtapi/recovery.go`: 2 sites (only authenticated endpoints)
- Delete `UserIDHeader` const from `consent.go`
- Update all *_test.go files to use `fakeCallerSource` instead of `req.Header.Set(UserIDHeader, ...)`

### T4: Add negative/spoofing tests and cmd-level integration test
- Unit: header present + no session => 401 (fakeCallerSource returns "")
- Unit: header user-B + session user-A => response scoped to user-A
- Cmd-level: wire real bff.Middleware + bffCallerAdapter, assert spoofed header ignored

### T5: Add regression guard test
Add `internal/mgmtapi/header_guard_test.go` that scans `internal/mgmtapi/*.go`
(excluding itself) for `X-Harbor-User-ID` and `UserIDHeader` and fails if found.
Build needle via concatenation to avoid self-detection.

### T6: Rewrite e2e/recovery_test.go
Remove `userIDHeader` constant and all `req.Header.Set(userIDHeader, ...)` calls.
Rewrite `generateRecoveryCodes` to rely on the BFF cookie in the client jar.
Skip gracefully when the BFF session is not established.

## Validation
- `go build ./...` must pass
- `go vet ./...` must pass  
- `go test ./internal/mgmtapi/... ./internal/arch/...` must pass
- `go test ./...` must pass
- `grep -r "X-Harbor-User-ID" internal/ e2e/` must return nothing
- `openspec validate fix-mgmt-context-auth-887df986 --strict`
