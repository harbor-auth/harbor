# Spec: mgmtapi caller identity from BFF context

## ADDED Requirements

### REQ-001: CallerSource interface
The `internal/mgmtapi` package SHALL define a `CallerSource` interface with a single
method `CallerID(ctx context.Context) string`. The `Server` struct SHALL accept a
`CallerSource` via `WithCallerSource` and expose it through a shared `callerID` helper
that writes a 401 and returns `ok=false` when the resolved ID is empty.

**Scenario 1 — authenticated:**
Given a request with a valid BFF session cookie,
When the BFF middleware has populated the context,
Then `callerID` returns the session user ID and `ok=true`.

**Scenario 2 — unauthenticated:**
Given a request with no valid BFF session,
When `callerID` is called,
Then it writes HTTP 401 with `{"error":"unauthorized"}` and returns `ok=false`.

### REQ-002: No header-based identity
All user-scoped endpoints in `internal/mgmtapi` MUST NOT read caller identity from any
HTTP request header. The `UserIDHeader` constant and all `r.Header.Get(UserIDHeader)`
call sites SHALL be deleted. `grep -r "X-Harbor-User-ID" internal/ e2e/` MUST return
no results after this change.

**Scenario 1 — header spoofing rejected:**
Given a request carrying `X-Harbor-User-ID: <victim>` but no valid BFF session,
When the request reaches any user-scoped endpoint,
Then the response is HTTP 401.

**Scenario 2 — header ignored with real session:**
Given a request carrying `X-Harbor-User-ID: user-B` alongside a valid BFF session for user-A,
When the request reaches any user-scoped endpoint,
Then the handler operates as user-A (the session identity), never user-B.

### REQ-003: Regression guard
A test in `internal/mgmtapi` or `internal/arch` SHALL scan the `internal/mgmtapi/`
source tree for the string `X-Harbor-User-ID` (and the symbol `UserIDHeader`) and fail
if either is found. The test MUST exclude its own source file from the scan.

**Scenario:**
Given the regression guard test is part of `go test ./...`,
When anyone adds `r.Header.Get("X-Harbor-User-ID")` to any mgmtapi file,
Then the guard test fails and the change is rejected.

### REQ-004: Unaffected unauthenticated endpoints
`POST /enroll`, `POST /recovery/begin`, `POST /recovery/complete` MUST continue to
function without a BFF session. These endpoints legitimately have no authenticated
session at the time they are called.

**Scenario:**
Given a request with no BFF session cookie,
When the request targets `POST /enroll`,
Then the response is not 401.
