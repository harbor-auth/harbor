# Specification: mgmtapi Caller Identity

## Overview

This specification captures the security requirements for resolving caller
identity in `internal/mgmtapi`. The previous implementation read identity from
the `X-Harbor-User-ID` request header (audit finding C1 — universal account
takeover). The fixed implementation reads identity exclusively from the BFF
session context via an injected `CallerSource` interface.

## ADDED Requirements

### Requirement: CallerSource interface for decoupled identity resolution

`internal/mgmtapi` MUST expose a `CallerSource` interface with a single method
`CallerID(ctx context.Context) string` that returns the authenticated user's
internal ID from the request context, or `""` when no authenticated BFF session
is present.

#### Scenario: Production adapter resolves caller from BFF session context

```gherkin
Given a request with a valid BFF session for user "alice"
And the BFF middleware has populated the context with alice's user ID
When a user-scoped mgmtapi handler calls callerID(w, r)
Then CallerSource.CallerID returns "alice"
And the handler proceeds with user ID "alice"
```

#### Scenario: No session returns empty string

```gherkin
Given a request with no BFF session cookie
When CallerSource.CallerID is called
Then it returns ""
```

### Requirement: callerID helper fails closed on missing session

`(*Server).callerID(w, r)` MUST read caller identity exclusively from
`CallerSource.CallerID(r.Context())`. When the returned ID is `""`, it MUST
write an HTTP 401 response using the existing PII-free error envelope and
return `ok=false`. Handlers MUST return immediately when `ok=false`.

#### Scenario: Missing session returns 401

```gherkin
Given a user-scoped endpoint request
And no BFF session is present (CallerSource returns "")
When the handler calls callerID(w, r)
Then the response status is 401 Unauthorized
And the response body uses the standard error envelope
And ok=false is returned to the handler
```

#### Scenario: Valid session allows handler to proceed

```gherkin
Given a user-scoped endpoint request
And a valid BFF session for user "bob" is present
When the handler calls callerID(w, r)
Then userID "bob" and ok=true are returned
And the handler continues with user "bob"'s identity
```

### Requirement: Client-supplied identity header NEVER grants access

The `X-Harbor-User-ID` request header and the `UserIDHeader` constant MUST NOT
exist anywhere in `internal/mgmtapi` non-test source files. No user-scoped
endpoint SHALL read caller identity from any client-supplied HTTP header.

#### Scenario: Spoofed header with no session is rejected

```gherkin
Given a request to any user-scoped endpoint
And the request carries X-Harbor-User-ID: <victim-user-id>
And no valid BFF session is present
When the endpoint handler runs
Then the response status is 401 Unauthorized
And the victim's data is never accessed
```

#### Scenario: Spoofed header alongside a different user's session is ignored

```gherkin
Given a request to any user-scoped endpoint
And the request carries X-Harbor-User-ID: <user-b>
And a valid BFF session for <user-a> (user-a ≠ user-b) is present
When the endpoint handler runs
Then the handler uses user-a's identity
And user-b's data is never accessed
```

### Requirement: CallerSource is injected, not imported directly

`internal/mgmtapi` MUST NOT import `internal/bff` directly. The production
`CallerSource` adapter MUST be injected via `(*Server).WithCallerSource(src
CallerSource)` from `cmd/harbor-mgmt`. The architecture boundary test MUST
NOT be weakened to permit the direct import.

#### Scenario: cmd/harbor-mgmt injects the BFF adapter

```gherkin
Given the server is initialized in cmd/harbor-mgmt
When WithCallerSource is called with a bffCallerAdapter
Then every user-scoped endpoint resolves identity via bff.UserIDFromContext
And the mgmtapi package has no import of internal/bff
```

### Requirement: Unauthenticated enrollment and recovery endpoints are unaffected

`POST /enroll`, `POST /recovery/begin`, and `POST /recovery/complete` MUST NOT
call `callerID` — they legitimately have no authenticated session.

#### Scenario: Enrollment proceeds without BFF session

```gherkin
Given a POST /enroll request with no BFF session cookie
When the enrollment handler runs
Then it does not call callerID
And enrollment proceeds without a 401
```

### Requirement: Regression guard prevents header reintroduction

A package-level test in `internal/mgmtapi` MUST scan the package's non-test
`.go` source files and FAIL if either `"X-Harbor-User-ID"` or `"UserIDHeader"`
appears. This guards against future reintroduction of the spoofable header seam.

#### Scenario: Guard catches header constant reintroduction

```gherkin
Given a developer adds const UserIDHeader = "X-Harbor-User-ID" to mgmtapi
When the regression guard test runs
Then it fails with a descriptive error message
And CI is blocked
```

#### Scenario: Guard passes with clean production code

```gherkin
Given internal/mgmtapi non-test source files contain no header references
When the regression guard test runs
Then it passes with exit 0
```
