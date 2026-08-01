# Tasks: Clean up compliance test comments

## Implementation

- [ ] Update the three stale caller-auth comments in
  `internal/mgmtapi/compliance_test.go` to describe authenticated caller
  context, `fakeCallerSource`, or session-derived identity.
- [ ] Confirm that no test logic, assertions, or runtime code changed.

## Validation

- [ ] Run `gofmt` if needed.
- [ ] Run the focused `internal/mgmtapi` tests.
- [ ] Run `go test ./...`.
- [ ] Run `make agent-check`.
- [ ] Run OpenSpec verification for
  `cleanup-compliance-test-comments-f90625ed`.
