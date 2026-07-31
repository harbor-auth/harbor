# Spec: Security Hardening & Cleanup

Adds a batch of security-hardening and correctness fixes across the BFF, HTTP
server, relay, OIDC discovery, database pool, migrations, and rate limiter.
Each requirement is behavior-preserving except where it closes a security gap.

## ADDED Requirements

### Requirement: REQ-001 Dashboard CSRF protection

The dashboard SHALL reject cross-site state-changing requests. A `DashboardCSRF`
middleware SHALL inspect the `Sec-Fetch-Site` request header and, when absent,
fall back to comparing the `Origin` header against the request host. Any request
determined to be cross-site SHALL receive HTTP 403 and MUST NOT reach the handler.
Same-site and same-origin requests SHALL pass through unchanged. The middleware
MUST apply to POST methods only — browsers may omit `Origin` on same-origin GETs.

#### Scenario: Cross-site Sec-Fetch-Site is rejected

**Given** a POST to a mutating dashboard route with `Sec-Fetch-Site: cross-site`
**When** the `DashboardCSRF` middleware evaluates the request
**Then** it returns HTTP 403 and the wrapped handler is never invoked

#### Scenario: Same-origin request passes

**Given** a POST with `Sec-Fetch-Site: same-origin`
**When** the middleware evaluates the request
**Then** the request is forwarded to the wrapped handler unchanged

#### Scenario: Origin fallback rejects mismatched host

**Given** a POST with no `Sec-Fetch-Site` header and an `Origin` host that differs from the request host
**When** the middleware evaluates the request
**Then** it returns HTTP 403

#### Scenario: Absent headers pass through

**Given** a POST with neither `Sec-Fetch-Site` nor `Origin` present
**When** the middleware evaluates the request
**Then** the request is forwarded (SameSite=Strict remains the active guard)

### Requirement: REQ-002 HTTP panic recovery with metrics

The HTTP server SHALL wrap all handlers in a `WithRecovery` middleware that
recovers from panics. On recovery it SHALL log at ERROR level with no PII and
MUST NOT include the panic value in either the response body or the log entry.
It SHALL increment the `harbor_http_panics_total` counter and SHALL respond with
HTTP 500. A recovered panic MUST NOT crash the process.

```go
package httpserver

func WithRecovery(next http.Handler, logger *slog.Logger) http.Handler
```

#### Scenario: Panic is recovered and counted

**Given** a handler wrapped by `WithRecovery` that panics
**When** a request reaches that handler
**Then** the response is HTTP 500, an ERROR log with no PII is emitted, and `harbor_http_panics_total` is incremented by one

#### Scenario: http.ErrAbortHandler is re-panicked

**Given** a handler that panics with `http.ErrAbortHandler`
**When** `WithRecovery` catches the panic
**Then** it re-panics so the net/http layer can handle the connection abort silently

### Requirement: REQ-003 Nil-safe dashboard rendering

`DashboardHandler` SHALL nil-check the consents, sessions, and credentials
collections before dereferencing them. A user with any of these unset SHALL
render the dashboard successfully and MUST NOT cause a panic or HTTP 500.

#### Scenario: User with nil collections renders successfully

**Given** an authenticated user whose consents, sessions, and credentials are nil
**When** `DashboardHandler` renders the dashboard
**Then** the response is HTTP 200 with a rendered page and no panic occurs

### Requirement: REQ-004 RELAY_DOMAIN threaded through email formatting

`relay.FormatEmail` SHALL accept the relay domain as an explicit parameter and
SHALL construct the relay address using the supplied domain. The domain MUST NOT
be hardcoded inside the function. Call sites SHALL source the domain from the
`RELAY_DOMAIN` environment variable.

```go
package relay

func FormatEmail(token string, relayDomain string) string
```

#### Scenario: Relay address uses configured domain

**Given** `relayDomain = "relay.example.com"` and a token `"abc123"`
**When** `FormatEmail("abc123", "relay.example.com")` is called
**Then** the returned address is `"abc123@relay.example.com"`

#### Scenario: Relay address and DNS instructions share the same domain

**Given** `RELAY_DOMAIN = "relay.example.com"`
**When** the relay management handler generates both the email address and the DNS setup instructions
**Then** both reference `relay.example.com` — they do not diverge

### Requirement: REQ-005 Correct OIDC discovery metadata

The OIDC discovery document SHALL NOT advertise the `EdDSA` signing algorithm
(no issuer or verifier supports it). It SHALL include a `revocation_endpoint`
and an `introspection_endpoint` corresponding to the endpoints the service
actually serves.

#### Scenario: Discovery omits EdDSA

**Given** a GET to the OIDC discovery endpoint
**When** the response JSON is parsed
**Then** `id_token_signing_alg_values_supported` does not contain `"EdDSA"`

#### Scenario: Discovery advertises revocation and introspection endpoints

**Given** a GET to the OIDC discovery endpoint
**When** the response JSON is parsed
**Then** both `revocation_endpoint` and `introspection_endpoint` are present and non-empty

### Requirement: REQ-006 Explicit pgxpool sizing from environment

The database connection pool SHALL read its sizing parameters from the
environment at startup: `DB_MAX_CONNS` (default 10), `DB_MIN_CONNS` (default 2),
and `DB_MAX_CONN_LIFETIME` (default 30m). The documentation SHALL note the
sizing arithmetic: replicas × `DB_MAX_CONNS` MUST remain below Postgres
`max_connections` with headroom for admin and monitoring connections.

#### Scenario: Pool honors environment overrides

**Given** `DB_MAX_CONNS=25`, `DB_MIN_CONNS=5`, and `DB_MAX_CONN_LIFETIME=15m`
**When** `ConnectDB` constructs the pool
**Then** the pgxpool config reflects max 25, min 5, and a 15-minute max connection lifetime

#### Scenario: Pool applies documented defaults when env is unset

**Given** none of the pool sizing environment variables are set
**When** `ConnectDB` constructs the pool
**Then** the config uses max 10, min 2, and a 30-minute max connection lifetime

### Requirement: REQ-007 No committed build artifacts

The repository MUST NOT contain committed build binaries. The `.gitignore`
SHALL exclude binaries so they cannot be reintroduced, and CI SHALL fail if a
committed file exceeds the configured size threshold.

#### Scenario: Binary is absent and excluded by gitignore

**Given** the current repository tree and `.gitignore`
**When** the tree is inspected
**Then** the previously committed binary is absent and `.gitignore` prevents re-tracking it

### Requirement: REQ-008 Migration lock and statement timeouts

Migration 0017 SHALL issue `SET lock_timeout` and `SET statement_timeout` before
acquiring any locks so a blocked migration fails fast rather than stalling
indefinitely. The numbering gap at 0014 SHALL be documented with a comment.

#### Scenario: Migration 0017 sets lock and statement timeouts

**Given** the up migration SQL for 0017
**When** the SQL is inspected
**Then** it contains both `SET lock_timeout` and `SET statement_timeout` before any locking DDL

### Requirement: REQ-009 Trusted-proxy-hop client IP resolution for rate limiting

The rate limiter SHALL derive the client IP using a trusted-proxy-hop model
governed by the `TRUSTED_PROXY_HOPS` environment variable (type: non-negative
integer). When `TRUSTED_PROXY_HOPS=N`, it SHALL select the Nth-from-right value
in `X-Forwarded-For`. The leftmost (client-supplied) value MUST NOT be used for
rate-limit keying. When `TRUSTED_PROXY_HOPS=0` (the default), the forwarded
header MUST be ignored and `RemoteAddr` MUST be used instead.

#### Scenario: Nth-from-right XFF value is selected

**Given** `TRUSTED_PROXY_HOPS=1` and `X-Forwarded-For: 1.1.1.1, 2.2.2.2, 3.3.3.3`
**When** the rate limiter resolves the client IP
**Then** it selects `3.3.3.3` and ignores the spoofable leftmost `1.1.1.1`

#### Scenario: Zero hops falls back to RemoteAddr

**Given** `TRUSTED_PROXY_HOPS=0` (or unset) and an `X-Forwarded-For` header present
**When** the rate limiter resolves the client IP
**Then** it uses `RemoteAddr` and ignores the `X-Forwarded-For` header entirely

#### Scenario: Forged leftmost XFF cannot escape the anonymous rate-limit bucket

**Given** a client sending a different random `X-Forwarded-For` leftmost value on each request and `TRUSTED_PROXY_HOPS=1`
**When** multiple requests arrive from the same `RemoteAddr`-visible IP
**Then** all requests resolve to the same rate-limit bucket key (the rightmost XFF value) and the limit is enforced
