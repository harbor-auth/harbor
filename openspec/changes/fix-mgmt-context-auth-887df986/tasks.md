# fix-mgmt-context-auth-887df986 — Tasks

> Plan: `docs/plans/fix-mgmt-context-auth.md` · Audit finding C1.

## Prerequisites

- `internal/arch/arch_test.go` reviewed: direct `bff` import not permitted.
- `cmd/harbor-mgmt/main.go` already wires `bff.Middleware` (context, not header).

## Implementation

- [x] Add `CallerSource` interface and `callerID` helper in
      `internal/mgmtapi/caller.go`; add `(*Server).WithCallerSource`
- [x] Wire `bffCallerAdapter` (wraps `bff.UserIDFromContext`) in
      `cmd/harbor-mgmt`
- [x] Convert all 14 `r.Header.Get(UserIDHeader)` call sites to `s.callerID`
- [x] Delete `UserIDHeader` constant and its doc comment from `consent.go`

## Tests

- [x] Update all `mgmtapi` unit tests to seed context via `fakeCallerSource`,
      not headers
- [x] Add negative spoofing unit tests: header + no session → 401; header +
      session for different user → scoped to session user
- [x] Add regression guard test scanning non-test `.go` files for
      `X-Harbor-User-ID` / `UserIDHeader`
- [x] Rewrite `e2e/recovery_test.go` to remove `X-Harbor-User-ID` header usage

## Validation

- [x] `go build ./...` — green
- [x] `go vet ./...` — green
- [x] `go test ./...` — green
- [x] `grep -r "X-Harbor-User-ID" internal/ e2e/` — no production code matches
- [x] `openspec validate fix-mgmt-context-auth-887df986 --strict` — green
