# Specification: Compliance test caller-auth documentation

## ADDED Requirements

### Requirement: Accurate caller-auth test comments

The comments for `TestPostExport_CallerScoped`,
`TestSecurity_PostExport_CrossUserIsolation`, and
`TestPostErase_EraseCalledWithAuthenticatedUser` MUST describe identity as
coming from authenticated caller context. They MUST reflect that tests use
`fakeCallerSource` to model the session-derived identity used in production and
MUST NOT describe the removed `X-Harbor-User-ID` header as the identity source.

#### Scenario: Export comments describe authenticated caller scoping

**Given** the caller-scoped and cross-user isolation export tests
**When** a maintainer reads their comments
**Then** the comments explain that the bundler receives the authenticated
caller's identity supplied through the caller-source seam
**And** they do not claim identity comes from `X-Harbor-User-ID`

#### Scenario: Erase comment describes authenticated caller scoping

**Given** the caller-scoped erase test
**When** a maintainer reads its comment
**Then** the comment explains that the eraser receives session-derived caller
identity modeled by `fakeCallerSource`
**And** it does not claim identity comes from `X-Harbor-User-ID`

### Requirement: Comment-only behavior preservation

The cleanup MUST NOT change test setup, assertions, test strength, or runtime
behavior.

#### Scenario: Tests retain their security guarantees

**Given** the three comments have been corrected
**When** the management API and full Go test suites run
**Then** the existing caller-scoping and cross-user isolation assertions remain
unchanged and pass
