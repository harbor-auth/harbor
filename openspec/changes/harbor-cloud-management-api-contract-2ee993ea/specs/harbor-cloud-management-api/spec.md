## Purpose

Defines the authenticated internal contract harbor core exposes to Harbor
Cloud (the SaaS control plane) for minting management sessions, provisioning
namespaces, and rotating signing keys — reachable only over the private
WireGuard/`cloudIntegration` path, never on a public listener.

## ADDED Requirements

### Requirement: Service-scoped JWT authentication
The system SHALL authenticate every `/admin/v1/*` request on harbor-mgmt with
a short-lived, asymmetrically-signed (ES256/EdDSA) service JWT carrying `aud`,
`sub`, `scope`, `exp`, `iat`, and `jti` claims, verified in
`internal/cloudapi` against a configured trust-anchor public key. The
`ADMIN_API_TOKEN` operator credential and the RFC 7591 initial-access token
SHALL NEVER be accepted on this surface.

```go
type ServiceAuthVerifier interface {
    Verify(ctx context.Context, bearer string) (ServiceClaims, error)
}
```

#### Scenario: Valid service token is accepted
- **WHEN** a request presents a JWT with correct `aud`, unexpired `exp`, an
  unused `jti`, and a scope covering the requested operation
- **THEN** the request is authorized and the handler executes

#### Scenario: Wrong audience is rejected
- **WHEN** a request presents a validly-signed JWT whose `aud` does not equal
  `harbor-mgmt-cloudapi`
- **THEN** the response is 401 `invalid_token` and the handler is NOT invoked

#### Scenario: Missing required scope is rejected
- **WHEN** a request presents a validly-signed, correct-audience JWT whose
  `scope` claim does not include the scope required by the called route
- **THEN** the response is 403 `insufficient_scope` and the handler is NOT
  invoked

#### Scenario: Expired token is rejected
- **WHEN** a request presents a JWT whose `exp` is in the past
- **THEN** the response is 401 `invalid_token` and the handler is NOT invoked

#### Scenario: Replayed jti is rejected
- **WHEN** a request presents a JWT whose `jti` was already accepted once
  within its validity window
- **THEN** the response is 401 `token_replayed` and the handler is NOT invoked

#### Scenario: Operator or initial-access tokens are never accepted
- **WHEN** a request to `/admin/v1/*` presents `ADMIN_API_TOKEN` or a valid
  RFC 7591 initial-access token as the Bearer credential
- **THEN** the response is 401 `invalid_token`

#### Scenario: Fail-closed on unconfigured trust anchor
- **GIVEN** `CLOUD_SERVICE_AUTH_PUBLIC_KEY` is unset
- **WHEN** any request arrives at `/admin/v1/*`
- **THEN** the response is 401 for every request, regardless of the
  presented credential

### Requirement: Private-path-only reachability
The `/admin/v1/*` routes SHALL be registered only on harbor-mgmt, only when
`mgmt.cloudIntegration.enabled` is true, and SHALL NEVER be reachable from
harbor-hot's public listener or the public ingress host
(`auth.harborauth.com`).

#### Scenario: Routes absent when cloudIntegration is disabled
- **WHEN** harbor-mgmt starts with `cloudIntegration.enabled=false`
- **THEN** every `/admin/v1/*` path returns 404 (not registered)

#### Scenario: harbor-hot never exposes the contract
- **WHEN** the harbor-hot binary's route table is inspected
- **THEN** no `/admin/v1/*` path exists on harbor-hot

### Requirement: Namespace lifecycle with idempotent create/delete
The system SHALL provide `POST /admin/v1/namespaces`,
`GET /admin/v1/namespaces/{id}`, and `DELETE /admin/v1/namespaces/{id}`,
requiring an `Idempotency-Key` header on create and delete, keyed against a
stored `cloud_operations` ledger row.

#### Scenario: Namespace create is idempotent on retry
- **GIVEN** a namespace was created with `Idempotency-Key: K` and request body
  `B`
- **WHEN** the same `POST /admin/v1/namespaces` request is retried with the
  same `Idempotency-Key: K` and body `B`
- **THEN** the original response (status and body) is returned and no second
  namespace row is created

#### Scenario: Reused idempotency key with a different body is rejected
- **GIVEN** `Idempotency-Key: K` was used for one request body
- **WHEN** a request with `Idempotency-Key: K` and a DIFFERENT body arrives
- **THEN** the response is 409 `idempotency_key_reused`

#### Scenario: Duplicate namespace id is rejected
- **GIVEN** an active namespace `ns-1` exists
- **WHEN** `POST /admin/v1/namespaces` is called for `ns-1` with a fresh
  idempotency key
- **THEN** the response is 409 `namespace_already_exists`

#### Scenario: Delete is idempotent, including on an absent namespace
- **WHEN** `DELETE /admin/v1/namespaces/{id}` is called for a namespace that
  does not exist or was already deleted
- **THEN** the response is 204, every time

### Requirement: Namespace-scoped session minting with idempotency
`POST /admin/v1/sessions` SHALL mint a short-lived, namespace-scoped
credential (not an end-user OIDC session), require an `Idempotency-Key`
header, and bind the returned session strictly to the requested
`namespace_id`.

#### Scenario: Session mint is idempotent on retry
- **GIVEN** a session was minted with `Idempotency-Key: K`
- **WHEN** the same mint request is retried with `Idempotency-Key: K`
- **THEN** the same still-valid `session_id` is returned, no second session
  row is created

#### Scenario: Expired session is rejected
- **WHEN** a caller presents a session token whose `expires_at` has passed
- **THEN** the response is 410 `session_expired`

#### Scenario: Cross-tenant use of a session is rejected
- **GIVEN** a session was minted for namespace `ns-a`
- **WHEN** that session token is presented on an operation targeting
  namespace `ns-b`
- **THEN** the response is 403 `cross_tenant_forbidden` and no operation on
  `ns-b` is performed

### Requirement: Privileged key rotation, not customer self-service
`POST /admin/v1/keys/rotate` SHALL require the `keys:rotate` scope and SHALL
proxy to harbor-hot's existing, unmodified `/admin/keys/rotate` using a second
internal credential distinct from `ADMIN_API_TOKEN`. This route SHALL NEVER be
reachable from any customer/tenant-facing surface.

#### Scenario: Rotation proxies to harbor-hot with a distinct credential
- **WHEN** `POST /admin/v1/keys/rotate` is called with a valid `keys:rotate`
  scoped token
- **THEN** harbor-mgmt calls harbor-hot's `/admin/keys/rotate` using
  `MGMT_HOT_PROXY_TOKEN`, not `ADMIN_API_TOKEN`
- **AND** harbor-hot's audit log records `credential=cloud-proxy` for that
  call

#### Scenario: Missing keys:rotate scope is rejected
- **WHEN** `POST /admin/v1/keys/rotate` is called with a service token that
  lacks the `keys:rotate` scope
- **THEN** the response is 403 `insufficient_scope` and harbor-hot is never
  called

### Requirement: Audit events and rate limits on every route
Every `/admin/v1/*` request SHALL emit a PII-free audit event (caller `sub`,
route, scope checked, outcome) via `internal/telemetry`, and SHALL be subject
to a per-route rate limit that fails closed (rejects, does not silently
unlimit) when the rate limiter backend is unavailable.

#### Scenario: Successful and rejected calls are both audited
- **WHEN** any `/admin/v1/*` request completes, authorized or rejected
- **THEN** an audit event is recorded with the caller `sub`, route, and
  outcome, and contains no PII (no namespace-owner email, no token material)

#### Scenario: Rate limit exceeded is rejected
- **WHEN** a caller exceeds the configured burst/window for a given
  `/admin/v1/*` route
- **THEN** the response is 429 `rate_limited`
