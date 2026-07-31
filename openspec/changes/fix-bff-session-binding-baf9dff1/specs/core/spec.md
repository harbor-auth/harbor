# Spec: BFF Browser Nonce Binding (C3 + M2 fix)

Fixes CRITICAL audit findings C3 (login session fixation) and M2 (broken
post-login redirect). Introduces a cryptographic browser nonce minted at
`/authorize`, stored hash-at-rest, and verified at every subsequent ceremony
step. Replaces the broken relative redirect with an absolute, configured URL.

## ADDED Requirements

### Requirement: REQ-BFF-NONCE-001 Nonce minted at /authorize before login redirect

The authorization server SHALL generate a cryptographically-random 256-bit
browser nonce at `/authorize` (`authorizeWithBFFSession`), store
`SHA-256(nonce)` as `BFFSessionRecord.BrowserNonceHash`, and set the nonce
value in the `__Host-harbor-bff-nonce` cookie (HttpOnly, Secure,
SameSite=Strict, Path=/) BEFORE redirecting the browser to the login UI.
The raw nonce MUST NOT be stored at rest; only the SHA-256 hash is stored.

#### Scenario: Nonce cookie set before login redirect

**Given** a valid GET /authorize request with a registered client_id and BFF sessions enabled
**When** `authorizeWithBFFSession` creates the BFF session and redirects to LOGIN_URL
**Then** the response MUST include `Set-Cookie: __Host-harbor-bff-nonce=<value>` before the 302
**And** the BFFSessionRecord stored under the new request_id MUST have `BrowserNonceHash = SHA-256(<value>)`
**And** the SHA-256 hash stored MUST match the nonce cookie value

#### Scenario: CSPRNG failure fails closed

**Given** a CSPRNG failure when generating the 256-bit browser nonce
**When** `authorizeWithBFFSession` attempts to mint the nonce
**Then** the response MUST be a 400 error page with no Location header
**And** no BFF session MUST be created in the store

### Requirement: REQ-BFF-NONCE-002 Nonce required at BeginLogin — session fixation defense

The BFF login handler SHALL verify at `BeginLogin` that the
`__Host-harbor-bff-nonce` cookie is present and that
`SHA-256(cookie_value) == BFFSessionRecord.BrowserNonceHash` using
`crypto/subtle.ConstantTimeCompare`. The handler MUST NOT set the
`__Host-harbor-bff-nonce` or `__Host-harbor-bff` cookie from the URL.
Mismatch or absence MUST return 400 with no Location header.

#### Scenario: Fixation attack — attacker-minted request_id with victim browser (headline)

**Given** an attacker-created BFF session with request_id=R and `BrowserNonceHash = SHA-256(N_attacker)`
**And** a victim browser with no `__Host-harbor-bff-nonce` cookie (or a cookie with value N_victim ≠ N_attacker)
**When** the victim is lured to GET /login?request_id=R
**Then** BeginLogin MUST return 400
**And** no Location header MUST appear in the response
**And** the BFF session MUST NOT be advanced or modified
**And** no authorization code MUST ever be issued for this session

#### Scenario: Valid nonce allows BeginLogin to proceed

**Given** a BFF session with `BrowserNonceHash = SHA-256(N)`
**And** a browser request to GET /login?request_id=<id> with `__Host-harbor-bff-nonce=N`
**When** BeginLogin processes the request
**Then** the response MUST be 200 with WebAuthn assertion options
**And** BeginLogin MUST NOT set any new nonce or BFF session cookie

#### Scenario: Wrong nonce cookie at BeginLogin

**Given** a BFF session with `BrowserNonceHash = SHA-256(N1)`
**And** a browser request with `__Host-harbor-bff-nonce=N2` where `N2 ≠ N1`
**When** BeginLogin processes the request
**Then** the response MUST be 400 with no Location header

### Requirement: REQ-BFF-NONCE-003 Nonce required at FinishLogin before SetUser

The BFF login handler SHALL verify the `__Host-harbor-bff-nonce` cookie at
`FinishLogin`/`FinishLoginWithParsedData` using `crypto/subtle.ConstantTimeCompare`
BEFORE calling `sessions.SetUser`. Failure MUST return 400 with no redirect
and MUST NOT set the session UserID.

#### Scenario: Valid nonce allows FinishLogin to set UserID

**Given** a BFF session with `BrowserNonceHash = SHA-256(N)` and no UserID set
**And** a POST /login/complete with `__Host-harbor-bff=<request_id>` and `__Host-harbor-bff-nonce=N`
**When** FinishLogin completes the WebAuthn ceremony successfully
**Then** `session.UserID` MUST be set to the authenticated user
**And** the response MUST be 302 to the absolute `AUTHORIZE_COMPLETE_URL`

#### Scenario: Missing nonce at FinishLogin blocks SetUser

**Given** a BFF session with `BrowserNonceHash` set
**And** a POST /login/complete with `__Host-harbor-bff=<request_id>` but NO `__Host-harbor-bff-nonce` cookie
**When** FinishLogin processes the request
**Then** the response MUST be 400 with no Location header
**And** `session.UserID` MUST NOT be set

### Requirement: REQ-BFF-NONCE-004 Nonce required at GetAuthorizeComplete before code issuance

`GetAuthorizeComplete` SHALL verify the `__Host-harbor-bff-nonce` cookie using
`crypto/subtle.ConstantTimeCompare` before calling `AuthorizeWithUser`. Failure
MUST render the error page (no Location header, no authorization code). On success,
BOTH `__Host-harbor-bff` and `__Host-harbor-bff-nonce` MUST be cleared.

#### Scenario: Valid nonce allows code issuance and clears both cookies

**Given** a BFF session with `BrowserNonceHash = SHA-256(N)` and UserID set
**And** GET /authorize/complete?request_id=<id> with `__Host-harbor-bff-nonce=N`
**When** GetAuthorizeComplete processes the request
**Then** the response MUST be 302 to the RP redirect_uri with `code=<code>`
**And** `Set-Cookie: __Host-harbor-bff; Max-Age=-1` MUST appear in the response
**And** `Set-Cookie: __Host-harbor-bff-nonce; Max-Age=-1` MUST appear in the response

#### Scenario: Missing nonce at GetAuthorizeComplete blocks code issuance

**Given** a BFF session with `BrowserNonceHash` set and UserID set
**And** GET /authorize/complete?request_id=<id> with NO `__Host-harbor-bff-nonce` cookie
**When** GetAuthorizeComplete processes the request
**Then** the response MUST be 400 (error page) with no Location header
**And** no authorization code MUST be issued

### Requirement: REQ-BFF-NONCE-005 Nonce never logged or returned in response body

The raw nonce value MUST NEVER appear in any log output, response body, or HTTP
header other than the `Set-Cookie` header that delivers it to the browser.

#### Scenario: Nonce absent from all response bodies in BFF flow

**Given** a complete BFF login flow from /authorize through /authorize/complete
**When** all HTTP response bodies are collected
**Then** no response body MUST contain the raw nonce value

#### Scenario: Nonce absent from server log output

**Given** a complete BFF login flow with server logging enabled
**When** all log entries are collected
**Then** no log entry MUST contain the raw nonce value

### Requirement: REQ-BFF-M2-001 Absolute post-login redirect via AUTHORIZE_COMPLETE_URL

`LoginHandler.FinishLoginWithParsedData` SHALL construct the post-ceremony redirect
using an absolute URL from the `AUTHORIZE_COMPLETE_URL` configuration. harbor-mgmt
MUST fail closed at boot with a logged error and non-zero exit if `AUTHORIZE_COMPLETE_URL`
is unset when `DATABASE_URL` is set (production mode). The URL MUST NOT be a
relative path.

#### Scenario: Post-login redirect uses configured absolute URL

**Given** `AUTHORIZE_COMPLETE_URL = "https://auth.example.com/authorize/complete"`
**And** a successful passkey ceremony at POST /login/complete
**When** FinishLoginWithParsedData builds the redirect
**Then** the `Location` header MUST start with `"https://auth.example.com/authorize/complete"`
**And** the `Location` MUST NOT be a relative path like `/authorize/complete`

#### Scenario: Boot failure when AUTHORIZE_COMPLETE_URL unset in production

**Given** `AUTHORIZE_COMPLETE_URL` is not set and `DATABASE_URL` is set
**When** harbor-mgmt starts up
**Then** the process MUST exit with a non-zero status before binding any port
**And** an error MUST be logged indicating the missing configuration

### Requirement: REQ-BFF-TOPO-001 Single-host topology documented

The deployment documentation SHALL state that the supported topology for the BFF
login flow is ONE public hostname fronting both harbor-hot and harbor-mgmt via
path-routed ingress. Split-host deployments are NOT supported by this design
because `__Host-` prefixed cookies cannot span two different public origins.

#### Scenario: Topology described in deploy/README.md

**Given** a reader reviewing `deploy/README.md`
**When** they look for BFF topology guidance
**Then** the file MUST describe the single-public-host / path-routed ingress requirement
**And** it MUST note that split-host (hot and mgmt on separate public hostnames) is unsupported
**And** it MUST explain that `__Host-` cookie semantics prevent cross-origin cookie sharing
