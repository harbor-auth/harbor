# Spec: BFF login session fixation fix (C3 + M2)

Closes audit findings C3 (login session fixation → account takeover) and M2
(relative redirect that 404s cross-host) by introducing a browser nonce that
binds every BFF session to the specific browser that initiated the flow at
`/authorize`. Defines the nonce contract, the three-checkpoint gate, the
hash-at-rest requirement, and the absolute-redirect fix. Cross-links to
[`docs/plans/fix-bff-session-binding.md`](../../../../docs/plans/fix-bff-session-binding.md).

## ADDED Requirements

### Requirement: REQ-001 Browser nonce minted at /authorize

The system SHALL mint a 256-bit CSPRNG browser nonce at `/authorize` before
redirecting to the login UI.

At `/authorize` (in `authorizeWithBFFSession`), the system MUST generate a 32-byte
cryptographically random nonce via `crypto/rand`. Its SHA-256 hash MUST be stored
as `BFFSessionRecord.BrowserNonceHash`. The raw nonce MUST be placed in the
`__Host-harbor-bff-nonce` cookie (Secure, HttpOnly, SameSite=Strict, Path=/) with
the same TTL as the BFF session (5 minutes). The cookie MUST be set BEFORE the
redirect to `LOGIN_URL`. The hash, not the raw value, SHALL be persisted so that a
session-store breach does not yield live cookies.

```go
// NewBrowserNonce generates a 32-byte CSPRNG nonce.
func NewBrowserNonce() ([]byte, error)

// HashNonce returns the SHA-256 digest of nonce.
func HashNonce(nonce []byte) []byte

// SetBFFNonceCookie writes the nonce cookie to w.
func SetBFFNonceCookie(w http.ResponseWriter, nonce []byte, maxAge time.Duration)
```

#### Scenario: Nonce is minted and cookie is set before login redirect

**Given** a valid OIDC `/authorize` request with a configured BFF session store
**When** `authorizeWithBFFSession` processes the request
**Then** the response sets `__Host-harbor-bff-nonce` with the raw nonce before the 302 redirect, and `BFFSessionRecord.BrowserNonceHash` equals `SHA-256(nonce)`

#### Scenario: CSPRNG failure at /authorize returns error page

**Given** the CSPRNG is unavailable
**When** `authorizeWithBFFSession` calls `NewBrowserNonce`
**Then** the system returns an error page with no Location header (fail-closed)

#### Scenario: Nonce cookie has correct security attributes

**Given** a successful `/authorize` response
**When** the `__Host-harbor-bff-nonce` cookie is inspected
**Then** the cookie has Secure=true, HttpOnly=true, SameSite=Strict, Path=/, MaxAge=300

### Requirement: REQ-002 Nonce gate at BeginLogin

The system SHALL verify the browser nonce at the start of the login ceremony.

`LoginHandler.BeginLogin` MUST read the `__Host-harbor-bff-nonce` cookie, compute
`SHA-256(cookie_value)`, and constant-time compare it against
`BFFSessionRecord.BrowserNonceHash`. On mismatch or absent cookie when
`BrowserNonceHash` is non-empty, the handler MUST return 4xx with no redirect and
MUST NOT set any cookie from the URL `request_id`. This is the line that kills the
session fixation: without a matching nonce, an attacker-minted `request_id` cannot
be advanced by a victim browser.

#### Scenario: BeginLogin refuses when nonce cookie is absent

**Given** a BFF session with a non-empty `BrowserNonceHash`
**When** `BeginLogin` receives a request with no `__Host-harbor-bff-nonce` cookie
**Then** the response is 4xx, no Location header is set, and no BFF cookie is written

#### Scenario: BeginLogin refuses when nonce cookie is wrong

**Given** a BFF session with a non-empty `BrowserNonceHash`
**When** `BeginLogin` receives a request with a nonce cookie that does not match the stored hash
**Then** the response is 4xx, no Location header is set, and no BFF cookie is written

#### Scenario: BeginLogin succeeds when nonce matches

**Given** a BFF session with a non-empty `BrowserNonceHash` and the matching raw nonce in the cookie
**When** `BeginLogin` processes the request
**Then** the BFF session cookie is set and assertion options are returned

### Requirement: REQ-003 Nonce gate at FinishLogin

The system SHALL verify the browser nonce before writing the authenticated user ID to the session.

`LoginHandler.FinishLoginWithParsedData` MUST apply the same nonce gate as
`BeginLogin` — constant-time compare `SHA-256(cookie_nonce)` against
`BFFSessionRecord.BrowserNonceHash` — before calling `SetUser`. On mismatch or
absent cookie, the handler MUST return 4xx with no redirect, and the
`BFFSessionRecord.UserID` MUST remain empty (the victim's identity is never written
into the attacker's session).

#### Scenario: FinishLogin refuses when nonce cookie is absent

**Given** a BFF session with a non-empty `BrowserNonceHash` and the BFF session cookie present
**When** `FinishLoginWithParsedData` receives a request with no nonce cookie
**Then** the response is 4xx, no Location header is set, and `session.UserID` remains empty

#### Scenario: FinishLogin refuses when nonce cookie is wrong

**Given** a BFF session with a non-empty `BrowserNonceHash`
**When** `FinishLoginWithParsedData` receives a request with a nonce cookie that does not match
**Then** the response is 4xx, no Location header is set, and `session.UserID` remains empty

#### Scenario: Attacker-minted request_id — victim browser cannot authenticate

**Given** an attacker-created BFF session (request_id=R, BrowserNonceHash=H) where the attacker holds the matching nonce cookie
**When** a victim's browser (no nonce cookie) is lured to `/login?request_id=R`
**Then** `BeginLogin` returns 4xx, no code is ever issued, and `session.UserID` remains empty

### Requirement: REQ-004 Nonce gate at /authorize/complete

The system SHALL verify the browser nonce before issuing the authorization code.

`GetAuthorizeComplete` MUST apply the nonce gate before calling `AuthorizeWithUser`.
On mismatch or absent cookie, the handler MUST render the no-redirect error page
(§11.7) — never a redirect to a URI whose session ownership is unproven. After
successful code issuance, both `__Host-harbor-bff` and `__Host-harbor-bff-nonce`
cookies MUST be cleared (one-time use).

#### Scenario: GetAuthorizeComplete refuses when nonce is absent

**Given** a BFF session with a non-empty `BrowserNonceHash` and an authenticated UserID
**When** `/authorize/complete` receives a request with no nonce cookie
**Then** the response is the no-redirect error page (4xx, no Location header), no code is issued

#### Scenario: GetAuthorizeComplete refuses when nonce is wrong

**Given** a BFF session with a non-empty `BrowserNonceHash` and an authenticated UserID
**When** `/authorize/complete` receives a request with a nonce cookie that does not match
**Then** the response is the no-redirect error page (4xx, no Location header), no code is issued

#### Scenario: GetAuthorizeComplete clears both cookies after code issuance

**Given** a valid BFF session with matching nonce and authenticated UserID
**When** `/authorize/complete` issues the auth code
**Then** both `__Host-harbor-bff` and `__Host-harbor-bff-nonce` cookies are cleared (MaxAge=-1)

### Requirement: REQ-005 BrowserNonceHash round-trips in both session stores

The system SHALL persist `BrowserNonceHash` faithfully in both the in-memory and Redis session stores.

`BFFSessionRecord.BrowserNonceHash []byte` MUST be a field on the session record.
Both `InMemoryBFFSessionStore` and `RedisBFFSessionStore` MUST store and return it
unchanged. The Redis store serializes records as JSON; the `[]byte` field MUST
survive a JSON marshal/unmarshal round-trip (base64-encoded by Go's standard
library `encoding/json`).

#### Scenario: InMemoryBFFSessionStore round-trips BrowserNonceHash

**Given** a BFFSessionRecord with a non-nil BrowserNonceHash
**When** it is created and then retrieved from InMemoryBFFSessionStore
**Then** the retrieved BrowserNonceHash is byte-equal to the original

#### Scenario: RedisBFFSessionStore round-trips BrowserNonceHash

**Given** a BFFSessionRecord with a non-nil BrowserNonceHash
**When** it is created and then retrieved from RedisBFFSessionStore
**Then** the retrieved BrowserNonceHash is byte-equal to the original

### Requirement: REQ-006 Hash-at-rest: nonce never in store or logs

The system SHALL NEVER store the raw nonce in the session store, logs, or response bodies.

The raw nonce value MUST NOT appear in: `BFFSessionRecord` fields (only its
SHA-256 hash), application logs, HTTP response bodies, or HTTP Location headers.
The raw nonce exists transiently in memory (between `NewBrowserNonce()` and
`SetBFFNonceCookie()`) and in the browser cookie only. Any code path that logs or
returns session record fields MUST not expose the nonce.

#### Scenario: Response body does not contain the raw nonce

**Given** a valid nonce cookie is presented in a request to `BeginLogin`
**When** `BeginLogin` returns assertion options
**Then** the response body does not contain the base64url-encoded raw nonce

#### Scenario: Error responses do not echo cookie values

**Given** a request with any nonce cookie value (valid or invalid)
**When** any handler returns an error response
**Then** the response body does not echo the nonce cookie value

### Requirement: REQ-007 Absolute AUTHORIZE_COMPLETE_URL (M2 fix)

The system SHALL use an absolute, configured URL for the post-login redirect to `/authorize/complete`.

`LoginHandler` MUST accept an `authorizeCompleteURL string` parameter. On
`FinishLoginWithParsedData`, the redirect MUST be built as
`authorizeCompleteURL + "?request_id=" + requestID`. `cmd/harbor-mgmt/main.go`
MUST read `AUTHORIZE_COMPLETE_URL` from the environment and pass it to
`NewLoginHandler`. The binary MUST fail closed at startup if `AUTHORIZE_COMPLETE_URL`
is unset or empty.

#### Scenario: Post-login redirect uses the configured absolute URL

**Given** `AUTHORIZE_COMPLETE_URL=https://auth.example.com/authorize/complete`
**When** `FinishLoginWithParsedData` completes successfully
**Then** the redirect Location is `https://auth.example.com/authorize/complete?request_id=<id>`

#### Scenario: harbor-mgmt fails to start without AUTHORIZE_COMPLETE_URL

**Given** `AUTHORIZE_COMPLETE_URL` is not set in the environment
**When** `cmd/harbor-mgmt` starts
**Then** the process exits with an error message indicating the missing configuration

### Requirement: REQ-008 Single-public-host topology documented

The system SHALL document that the `__Host-` cookie prefix requires a single public hostname.

The `deploy/README.md` MUST document that the supported topology is one public
hostname routing `/login*` to harbor-mgmt and all other paths to harbor-hot. It
MUST explain that the `__Host-` cookie prefix enforces this constraint and that
splitting the two binaries onto separate public hostnames is not supported without
changing the cookie design.

#### Scenario: deploy/README.md describes the single-host topology

**Given** the `deploy/README.md` documentation
**When** the BFF topology section is read
**Then** it describes path-routed ingress with a single public hostname and explains the `__Host-` constraint
