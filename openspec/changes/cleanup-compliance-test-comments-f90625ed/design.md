# Design: Clean up compliance test comments

## Approach

This is a documentation-only correction in
`internal/mgmtapi/compliance_test.go`. Preserve the existing tests verbatim and
replace only the three stale comments with wording aligned to the current
caller-auth flow: production identity is session-derived, while tests inject
the authenticated caller through `fakeCallerSource`.

## Constraints

- Do not change runtime behavior.
- Do not alter or weaken assertions.
- Do not imply that caller identity is accepted from a client-controlled
  header.
