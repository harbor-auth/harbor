## Context

harbor-mgmt already scaffolds a private channel for Harbor Cloud —
`mgmt.cloudIntegration.{enabled,nodePort,allowedCIDR}` in
`deploy/helm/values.yaml` and a matching ingress rule in
`deploy/helm/templates/networkpolicy-mgmt.yaml` that admits only the
WireGuard tunnel CIDR — but zero HTTP routes exist behind it. Separately,
harbor-hot already ships one working admin surface: `POST /admin/keys/rotate`
guarded by `AdminAuthMiddleware` (`internal/oidcapi/admin_auth.go`), a single
static Bearer secret (`ADMIN_API_TOKEN`) compared in constant time, fail-closed
on empty config, with an ingress-level `server-snippet` 403 on `^/admin` for
defense in depth. `internal/mgmtapi/register.go` has an unrelated pattern — an
optional RFC 7591 "initial access token" gating `/register` — that must not be
reused here; it authorizes client self-registration, not a machine service
identity. There is currently no "namespace"/"tenant" concept anywhere in the
codebase; harbor-core is single-tenant per region today.

## Goals / Non-Goals

**Goals:**

- One authenticated, versioned contract (`/admin/v1/...`) harbor-cloud calls
  over the private path only, distinct from the operator's `ADMIN_API_TOKEN`
  and from `/register`'s initial-access token.
- Reuse harbor-hot's existing, tested key-rotation logic rather than
  duplicating it.
- Idempotent namespace create/delete and session minting, safe to retry over
  an unreliable private tunnel.
- Contract shared with harbor-cloud as OpenAPI + fixtures only — never a
  shared Go module, never an import in either direction (Apache-2.0 harbor
  core / proprietary harbor-cloud boundary, `docs/ARCHITECTURE.md`).

**Non-Goals:**

- Changing `/admin/keys/rotate` on harbor-hot's operator-facing contract.
- A general multi-tenant data model inside harbor-core (namespaces here are a
  provisioning-lifecycle record only, not a routing/PII boundary).
- Customer/tenant self-service key rotation.

## Decisions

### 1. New package, mgmt-only

`internal/cloudapi` is wired **only** into `cmd/harbor-mgmt/main.go`, mounted
on the existing health mux behind `cloudIntegration.enabled`. harbor-hot's
public listener never imports or exposes it. This is the only place the
private NodePort/NetworkPolicy scaffold already terminates, and keeps the
harbor-cloud-facing surface off the internet-facing binary entirely.

### 2. Service-JWT auth (not a shared secret)

Harbor-cloud authenticates with a short-lived, self-issued asymmetric JWT
(ES256/EdDSA, matching `internal/oidc`'s signer family) — not a static token.
Claims: `iss` (harbor-cloud's service identity), `aud` = `"harbor-mgmt-cloudapi"`,
`sub` (caller service id), `scope` (space-delimited:
`sessions:mint namespaces:read namespaces:write keys:rotate`), `exp` (60–120s),
`iat`, `jti`. harbor-mgmt verifies against a configured trust-anchor public key
(`CLOUD_SERVICE_AUTH_PUBLIC_KEY`) — it never holds a private key for this
identity. Replay resistance: `SETNX jti` into Redis (already wired for BFF
sessions) with TTL = token `exp`; a reused `jti` is rejected as
`token_replayed`. Audience/scope literal comparisons stay constant-time
(`INV-CONSTANT-TIME-COMPARE`). Empty/unset trust anchor fails closed (every
request 401), mirroring `AdminAuthMiddleware`.

```go
// internal/cloudapi/serviceauth.go
type ServiceClaims struct {
    Audience string
    Subject  string
    Scopes   []string
    ExpiresAt time.Time
    JTI       string
}

type ServiceAuthVerifier interface {
    // Verify parses and validates a bearer JWT, checks aud/exp, and consults
    // the replay guard for jti. Returns ErrInvalidToken, ErrExpired, or
    // ErrReplayed on failure.
    Verify(ctx context.Context, bearer string) (ServiceClaims, error)
}
```

### 3. Namespace lifecycle + idempotency

New tables (migration `0019_cloud_namespaces.up.sql`):

- `cloud_namespaces(id text primary key, status text, created_at, updated_at, deleted_at)`
- `cloud_operations(idempotency_key text, operation text, request_hash bytea, response_body jsonb, created_at, primary key (idempotency_key, operation))`

Every create/delete/session-mint call requires an `Idempotency-Key` header.
The handler hashes the normalized request body; a replayed key with a matching
hash returns the stored response verbatim (same status code); a replayed key
with a **different** hash returns `409 idempotency_key_reused`. Namespace
create on an existing, non-deleted id (different idempotency key) returns
`409 namespace_already_exists`. Delete is naturally idempotent: deleting an
absent or already-deleted namespace returns `204` every time — never `404`.

### 4. Session minting — namespace-scoped, not an OIDC session

A "session" here is a short-lived, namespace-scoped credential harbor-cloud
mints to perform bounded provisioning operations against one namespace — it
has no relationship to end-user OIDC/BFF sessions. `POST /admin/v1/sessions`
stores `cloud_sessions(session_id, namespace_id, expires_at, consumed_at)` and
returns an opaque bearer token (hash stored, plaintext returned once, mirroring
`register.go`'s credential-minting pattern). Any subsequent call presenting a
session token is checked against the namespace it was minted for; a mismatch
is `403 cross_tenant_forbidden` — this is the cross-tenant isolation the
integration tests exercise. Expired sessions return `410 session_expired`.

### 5. Key rotation — proxy, not a second implementation

`POST /admin/v1/keys/rotate` on mgmt requires `keys:rotate` scope, then makes
an internal HTTP call to harbor-hot's existing, unmodified
`/admin/keys/rotate`, authenticated with a **second**, distinct static
credential (`MGMT_HOT_PROXY_TOKEN`) that `AdminAuthMiddleware` is extended to
accept alongside `ADMIN_API_TOKEN` — each independently rotatable, each
logged with which credential matched (`credential=operator|cloud-proxy`), so
leaking one never leaks the other. This reuses the tested rotation state
machine instead of forking it, and keeps key rotation privileged (only
`cloudapi`'s scope-checked handler or a human with `ADMIN_API_TOKEN` can ever
reach it — never a customer-facing surface).

### 6. Contract sharing

`api/openapi/harbor-cloud.yaml` (Apache-2.0, new file, not merged into
`harbor.yaml` since this is an internal contract with different servers/
security schemes) documents all five operations with `security:
[{cloudServiceAuth: []}]`. JSON fixtures live under
`internal/cloudapi/testdata/contract/` (request/response pairs per scenario);
harbor-cloud consumes the YAML + fixtures directly — no Go import either
direction.

## Risks / Trade-offs

- **Proxying key rotation adds a network hop and a second credential to
  manage.** Accepted: duplicating the rotation state machine in mgmt is a
  larger and riskier surface than one more Bearer secret.
- **Redis dependency for replay resistance.** mgmt already requires Redis for
  BFF/enrollment sessions, so this adds no new hard dependency — but a Redis
  outage means `cloudapi` fails closed (no replay guard → reject, not allow).
- **`namespace` is a new domain concept with no existing analog.** Scoped
  deliberately narrow (a provisioning-lifecycle row + idempotency ledger), not
  a general multi-tenancy model, to avoid design creep into region/PII
  boundaries this change does not touch.
