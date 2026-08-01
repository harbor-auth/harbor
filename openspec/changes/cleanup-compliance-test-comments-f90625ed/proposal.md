# Proposal: Clean up compliance test comments

## Problem

Three security-test comments in `internal/mgmtapi/compliance_test.go` still
describe caller identity as coming from the removed `X-Harbor-User-ID` header.
The tests now inject authenticated caller context through `fakeCallerSource`, so
the stale wording obscures the security boundary that the tests exercise.

## Proposed Solution

Update the comments for caller-scoped export, cross-user export isolation, and
caller-scoped erasure to describe authenticated, session-derived caller
identity and the test-only `fakeCallerSource` seam. Do not change test code,
assertions, or runtime behavior.

## Non-Goals

- No changes to compliance endpoint authentication or authorization.
- No changes to test setup, assertions, or coverage.
- No reintroduction of identity-bearing request headers.

## Success Criteria

- [ ] All three comments accurately describe authenticated caller identity.
- [ ] No stale `X-Harbor-User-ID` wording remains in those comments.
- [ ] Focused management API tests and the full Go test suite pass.
- [ ] `make agent-check` passes.
