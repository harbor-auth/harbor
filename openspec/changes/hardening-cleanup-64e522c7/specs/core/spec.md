# Spec: Hardening Cleanup — CSRF, Panic Recovery, XFF Rate-limit Fix

Nine independent security hardening items (audit M4 + M5). Each is self-contained.

## ADDED Requirements

### Requirement: REQ-CSRF-1 Sec-Fetch-Site primary CSRF check

For every POST to `/dashboard/apps/{grant_id}/revoke`, `/dashboard/sessions/{session_id}/revoke`, `/dashboard/credentials/{credential_id}/revoke`, and `/dashboard/relay/{address_id}/deactivate`, the server SHALL inspect the `Sec-Fetch-Site` request header.
- If `Sec-Fetch-Site` is present and its value is NOT `same-origin` or `none`, the server SHALL return `403 Forbidden`.
- GET requests SHALL NOT be gated.

#### Scenario: Cross-site POST is rejected

**Given** a POST request to `/dashboard/apps/x/revoke` with `Sec-Fetch-Site: cross-site`
**When** the CSRF middleware processes the request
**Then** the response status is `403 Forbidden` and the downstream handler is NOT called

#### Scenario: Same-origin POST is allowed

**Given** a POST request to `/dashboard/apps/x/revoke` with `Sec-Fetch-Site: same-origin`
**When** the CSRF middleware processes the request
**Then** the response status is NOT `403` and the downstream handler IS called

### Requirement: REQ-CSRF-2 Origin header fallback

When `Sec-Fetch-Site` is absent, the server SHALL inspect the `Origin` header. If `Origin` is present and does NOT match the BFF host (exact match), the server SHALL return `403 Forbidden`.

#### Scenario: Missing Sec-Fetch-Site with cross-origin Origin is rejected

**Given** a POST request with no `Sec-Fetch-Site` header but with `Origin: https://evil.example.com`
**When** the CSRF middleware processes the request
**Then** the response status is `403 Forbidden`

#### Scenario: Missing both headers allows the request

**Given** a POST request with neither `Sec-Fetch-Site` nor `Origin` header
**When** the CSRF middleware processes the request
**Then** the request is passed to the downstream handler

### Requirement: REQ-PANIC-1 Panic recovery middleware

Both `harbor-hot` and `harbor-mgmt` binaries SHALL install a recovery middleware that recovers panics and:
- Logs a single `slog.Error` entry with NO panic value and NO PII
- Increments a telemetry counter via the existing facade
- Writes `HTTP 500` with a generic body that does NOT include the panic value

#### Scenario: Panicking handler returns 500

**Given** an HTTP handler that calls `panic("something")`
**When** the recovery middleware wraps that handler and a request is processed
**Then** the response status is `500 Internal Server Error`
**And** the response body does NOT contain `something`
**And** a telemetry counter is incremented once

#### Scenario: Non-panicking handler is unaffected

**Given** an HTTP handler that returns `200`
**When** the recovery middleware wraps that handler
**Then** the response status is `200` and no panic counter is incremented

### Requirement: REQ-XFF-1 Trusted-proxy-hop rate-limit model

The `clientIP` function SHALL use a trusted-proxy-count model controlled by `TRUSTED_PROXY_HOPS` (integer env var, default `0`).
- When `TRUSTED_PROXY_HOPS=0`, the source IP SHALL be `RemoteAddr`.
- When `TRUSTED_PROXY_HOPS=N > 0` and the header has at least N entries, the source IP SHALL be the Nth-from-right entry.
- If the header has fewer than N entries, fall back to `RemoteAddr`.

#### Scenario: TRUSTED_PROXY_HOPS=0 ignores X-Forwarded-For

**Given** `TRUSTED_PROXY_HOPS=0` and request with `X-Forwarded-For: 1.2.3.4` and `RemoteAddr: 5.6.7.8:9000`
**When** `clientIP` is called
**Then** the returned IP is `5.6.7.8`

#### Scenario: TRUSTED_PROXY_HOPS=1 uses rightmost XFF entry

**Given** `TRUSTED_PROXY_HOPS=1` and `X-Forwarded-For: attacker, real-client` and `RemoteAddr: proxy:9000`
**When** `clientIP` is called
**Then** the returned IP is `real-client`

#### Scenario: Forged extra XFF entries cannot escape the bucket

**Given** `TRUSTED_PROXY_HOPS=1` and `X-Forwarded-For: random1, random2, real-client`
**When** `clientIP` is called
**Then** the returned IP is `real-client`, NOT `random1`
