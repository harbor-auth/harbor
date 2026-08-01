# Specification: Fail-closed BFF browser nonce gates

## MODIFIED Requirements

### Requirement: Every BFF browser nonce gate requires a stored hash

`BeginLogin`, `FinishLoginWithParsedData`, and `GetAuthorizeComplete` MUST reject
a retrieved BFF session when `BrowserNonceHash` is empty. An absent hash MUST
never disable or bypass browser binding.

#### Scenario: BeginLogin rejects an absent stored hash

Given a valid BFF session whose BrowserNonceHash is absent
When BeginLogin receives its request_id
Then it returns the existing browser nonce mismatch error
And it does not resolve the user, start WebAuthn, or set a BFF cookie

#### Scenario: FinishLogin rejects an absent stored hash

Given a valid BFF session whose BrowserNonceHash is absent
When FinishLoginWithParsedData receives the session cookies
Then it returns the existing browser nonce mismatch error
And it does not finish WebAuthn or write a user ID to the session

#### Scenario: Authorize completion rejects an absent stored hash

Given an authenticated BFF session whose BrowserNonceHash is absent
When GetAuthorizeComplete receives its request_id
Then it returns the existing no-redirect authorization error page
And it does not issue an authorization code

### Requirement: Populated nonce hashes retain existing verification behavior

For a non-empty `BrowserNonceHash`, every gate MUST read the existing browser
nonce cookie and use `NonceMatches` for constant-time comparison. Missing,
malformed, or mismatched cookies MUST continue to be rejected.

#### Scenario: Authorize-created session completes normally

Given /authorize creates a BFF session with HashNonce(nonce)
And the browser presents the nonce cookie through the login flow
When all three browser nonce gates run
Then the matching nonce is accepted at each gate
And the authorization flow can issue a code after authentication
