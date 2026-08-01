# Specification: BFF browser nonce gates

## ADDED Requirements

### Requirement: Login gates fail closed without a stored nonce hash

`BeginLogin` and `FinishLoginWithParsedData` MUST reject a session whose
`BrowserNonceHash` is absent. Rejection MUST occur before WebAuthn is started or
finished and before the BFF session cookie, authenticated user, or redirect is
produced.

#### Scenario: Begin login receives a session without a hash

```gherkin
Given a valid BFF session with no BrowserNonceHash
And the browser presents a syntactically valid nonce cookie
When BeginLogin handles the session
Then it returns an invalid_request error
And it does not start WebAuthn or set the BFF session cookie
```

#### Scenario: Finish login receives a session without a hash

```gherkin
Given a valid BFF session with no BrowserNonceHash
And the browser presents a syntactically valid nonce cookie
When FinishLoginWithParsedData handles the session
Then it returns an invalid_request error
And it does not finish WebAuthn, authenticate the session, or redirect
```

### Requirement: Authorization completion fails closed without a stored hash

`GetAuthorizeComplete` MUST reject an authenticated BFF session whose
`BrowserNonceHash` is absent. It MUST return the existing no-redirect error
response and MUST NOT issue an authorization code.

#### Scenario: Authorization completion receives a session without a hash

```gherkin
Given an authenticated BFF session with no BrowserNonceHash
And the browser presents a syntactically valid nonce cookie
When GetAuthorizeComplete handles the session
Then it returns the no-redirect bad-request error page
And it does not issue an authorization code
```

### Requirement: Existing browser binding behavior is preserved

For a session with a `BrowserNonceHash`, all three gates MUST continue to read
the existing nonce cookie and compare its decoded value with the stored hash
using the existing constant-time comparison. A session created by `/authorize`
with a matching nonce cookie MUST be allowed through the browser-nonce gate.

#### Scenario: Authorize-created session presents its matching cookie

```gherkin
Given /authorize created a session with HashNonce of a generated browser nonce
And the browser presents the corresponding nonce cookie
When the login and authorization completion gates evaluate the request
Then the browser-nonce checks pass
And normal flow processing continues
```

#### Scenario: Stored hash and cookie do not match

```gherkin
Given a session with a BrowserNonceHash
And the nonce cookie is missing, malformed, or hashes to a different value
When any browser-nonce gate evaluates the request
Then the request is rejected using the existing error behavior
```
