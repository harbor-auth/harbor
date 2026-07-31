# Spec: Admin Endpoint Authentication

## ADDED Requirements

### REQ-001: Bearer token authentication on all /admin/* routes

`WithAdminAuth` SHALL intercept every request whose path has the prefix `/admin/`
and require a valid `Authorization: Bearer <token>` header.

Given a request to `/admin/keys/rotate` with no `Authorization` header,
When the request reaches the router,
Then the response SHALL be HTTP 401 with body `{"code": "unauthorized", "message": ...}`
and header `WWW-Authenticate: Bearer error="invalid_token"`.

### REQ-002: Constant-time comparison prevents timing attacks

The middleware SHALL compare tokens by SHA-256 hashing both the presented and
configured token, then comparing with `crypto/subtle.ConstantTimeCompare`.
The middleware MUST NEVER use `==` or `bytes.Equal` on raw token bytes.

Given a wrong token,
When the middleware evaluates it,
Then the comparison SHALL take constant time regardless of where the token differs.

### REQ-003: Fail-closed on unconfigured token

When `ADMIN_API_TOKEN` is empty, the middleware SHALL return 401 for every
request to `/admin/*`. It MUST NEVER pass through.

Given `ADMIN_API_TOKEN` is unset,
When any request arrives at `/admin/keys/rotate`,
Then the response SHALL be HTTP 401.

### REQ-004: Boot guard when DATABASE_URL is set

When `DATABASE_URL` is set but `ADMIN_API_TOKEN` is unset or shorter than 32
bytes, harbor-hot SHALL refuse to start and return a non-zero exit code.

Given `DATABASE_URL` is set and `ADMIN_API_TOKEN` is empty,
When harbor-hot starts,
Then it SHALL exit with an error message referencing `ADMIN_API_TOKEN`.

### REQ-005: Non-admin paths unaffected

`WithAdminAuth` SHALL only intercept paths with the `/admin/` prefix.
Paths `/token`, `/jwks.json`, `/healthz`, `/.well-known/openid-configuration`,
and `/authorize` MUST NOT require the admin bearer token.

### REQ-006: OpenAPI security block

Both `POST /admin/keys/rotate` and `POST /admin/revoke-jwt` SHALL declare
`security: [{bearerAuth: []}]` in `api/openapi/harbor.yaml`.

### REQ-007: Rate limiting on admin endpoints

Both admin endpoints SHALL be added to `hotPathLimits` with tight budgets
(e.g., 10 requests per minute) to prevent a leaked token from enabling
unbounded rotation.

### REQ-008: Network-layer block at ingress

The public Ingress SHALL deny all requests to paths matching `/admin/*` with
a 403 response, providing defence in depth behind the application-layer auth.

### REQ-009: Secret delivery via Kubernetes Secret

`ADMIN_API_TOKEN` SHALL be delivered via a Kubernetes Secret referenced by
`secretKeyRef` in both the raw k8s manifests and the Helm chart. The secret
value SHALL NOT be committed to the repository.
