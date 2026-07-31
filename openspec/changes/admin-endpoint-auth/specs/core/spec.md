# Specification: Admin Endpoint Authentication

## Overview

This specification defines the authentication requirements for the
`/admin/*` surface on the `harbor-hot` binary, covering middleware
enforcement, OpenAPI contract, boot guard, rate limiting, and network
containment.

## ADDED Requirements

### Requirement: REQ-1: AdminAuthMiddleware

The system MUST provide `AdminAuthMiddleware(cfg AdminAuthConfig) func(http.Handler) http.Handler`
in `internal/oidcapi/admin_auth.go` that:

- Requires `Authorization: Bearer <token>` on every request (scheme match
  case-insensitive per RFC 7235).
- Compares the SHA-256 hash of the presented token against the SHA-256 hash
  of the configured token using `crypto/subtle.ConstantTimeCompare` (hashing
  eliminates the length side-channel).
- Returns 401 with `WWW-Authenticate: Bearer error="invalid_token"` and the
  standard PII-free error envelope on any mismatch.
- NEVER logs or echoes the presented token value.
- Logs WARN on rejection and INFO on success (path + outcome only).

#### Scenario: Missing Authorization header returns 401

```
Given the admin endpoint is protected by AdminAuthMiddleware
When a request arrives with no Authorization header
Then the response status is 401
And the response body contains error="unauthorized"
And WWW-Authenticate: Bearer header is present
And the underlying handler is NOT invoked
```

#### Scenario: Wrong token returns 401

```
Given the admin endpoint is protected with token "correct-token"
When a request arrives with Authorization: Bearer wrong-token
Then the response status is 401
And the underlying handler is NOT invoked
```

#### Scenario: Correct token passes through

```
Given the admin endpoint is protected with token "correct-token"
When a request arrives with Authorization: Bearer correct-token
Then the response status is 200
And the underlying handler IS invoked
```

#### Scenario: Bearer scheme is case-insensitive

```
Given the admin endpoint is protected
When a request arrives with Authorization: bearer <correct-token>
Then the request is accepted (case difference in scheme is allowed per RFC 7235)
```

#### Scenario: Malformed Authorization header returns 401

```
Given the admin endpoint is protected
When a request arrives with Authorization: Basic dXNlcjpwYXNz
Then the response status is 401
```

### Requirement: REQ-2: Fail-Closed on Empty Token

The `AdminAuthMiddleware` MUST return 401 for every request when the
configured token is empty or unset — never pass through.

#### Scenario: Empty configured token always rejects

```
Given AdminAuthMiddleware is constructed with an empty token
When any request arrives at /admin/*
Then the response status is 401 for every request
```

### Requirement: REQ-3: WithAdminAuth Path-Prefix Dispatcher

The system MUST provide `WithAdminAuth(base http.Handler, mw func(http.Handler) http.Handler) http.Handler`
in `internal/oidcapi/server.go` that:

- Applies `mw` to any request whose path has the prefix `/admin/`.
- Passes all other requests through to `base` unmodified.
- Mirrors the `WithRateLimits` dispatcher pattern so the spec-generated
  router is not modified.

#### Scenario: Admin paths are gated

```
Given WithAdminAuth is wired with AdminAuthMiddleware
When a request arrives for /admin/keys/rotate without a valid token
Then the response is 401
```

#### Scenario: Non-admin paths are unaffected

```
Given WithAdminAuth is wired
When requests arrive for /token, /jwks.json, /healthz, /.well-known/openid-configuration
Then those requests pass through to the base handler without auth checks
```

### Requirement: REQ-4: Boot Guard — Fail Closed on Missing ADMIN_API_TOKEN

`cmd/harbor-hot/main.go` MUST refuse to start when `DATABASE_URL` is set
but `ADMIN_API_TOKEN` is unset or shorter than 32 characters, mirroring the
existing `KEK_SECRET` guard in `buildSigningStack`.

#### Scenario: Missing token + database configured causes startup error

```
Given DATABASE_URL is set
And ADMIN_API_TOKEN is not set
When harbor-hot starts
Then it logs a fatal error and exits non-zero
```

#### Scenario: Short token causes startup error

```
Given DATABASE_URL is set
And ADMIN_API_TOKEN is set to a value shorter than 32 characters
When harbor-hot starts
Then it logs a fatal error about minimum token length and exits non-zero
```

#### Scenario: Valid token allows startup

```
Given DATABASE_URL is set
And ADMIN_API_TOKEN is a 32+-character string
When harbor-hot starts
Then it starts successfully with admin auth enabled
```

### Requirement: REQ-5: Admin Rate Limits

`cmd/harbor-hot/main.go` MUST add both admin paths to `hotPathLimits` with
tight budgets so a leaked token cannot cause unbounded key rotation.

#### Scenario: Admin endpoints have rate limits

```
Given harbor-hot is running with a valid ADMIN_API_TOKEN
When /admin/keys/rotate is called more than the configured burst limit
Then subsequent requests receive 429 Too Many Requests
```

### Requirement: REQ-6: OpenAPI Security Contract

Both `POST /admin/keys/rotate` and `POST /admin/revoke-jwt` in
`api/openapi/harbor.yaml` MUST have a `security: [{bearerAuth: []}]` block
so generated clients and documentation reflect the auth requirement.

#### Scenario: Admin operations declare bearer auth in spec

```
Given the OpenAPI spec at api/openapi/harbor.yaml
When the spec is parsed
Then POST /admin/keys/rotate has security: [{bearerAuth: []}]
And POST /admin/revoke-jwt has security: [{bearerAuth: []}]
```

### Requirement: REQ-7: Network Containment at Ingress

The Kubernetes ingress MUST deny `/admin/` requests on the public host,
providing defence-in-depth behind the middleware layer.

#### Scenario: Public ingress blocks /admin/ path

```
Given the k8s ingress is configured per deploy/k8s/ingress.yaml
When a request for /admin/keys/rotate arrives at the public ingress
Then the ingress returns 403 or 404 before it reaches harbor-hot
```

### Requirement: REQ-8: ADMIN_API_TOKEN in Kubernetes Secret and Helm Chart

The `ADMIN_API_TOKEN` environment variable MUST be delivered to harbor-hot
via a Kubernetes Secret `secretKeyRef` and included in the Helm chart
`values.yaml` and secret template so upgrades do not break.

#### Scenario: ADMIN_API_TOKEN is provisioned via Helm

```
Given a Helm values.yaml with adminApiToken set
When `helm template` renders the harbor-hot deployment
Then the harbor-hot pod spec has ADMIN_API_TOKEN sourced from a Secret
```
