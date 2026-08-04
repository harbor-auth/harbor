# deploy/

Reference deployment artifacts for self-hosters.

> **Status:** placeholder skeleton. Production deployment infrastructure
> (Terraform, production Helm values/overlays, region topology) lives in
> the closed-source `harbor-auth/harbor-cloud` repo.

## BFF Topology — Single Public Host (Required)

The Browser-Facing BFF (passkey login ceremony, `/login`, `/login/complete`,
plus the public signup/sign-in surface — `/signup*`, `/signin`, `/enroll`,
`/webauthn/*`, `/recovery/*` — see
[docs/design/product/signup-cta-contract.md](../docs/design/product/signup-cta-contract.md))
uses cookies with the `__Host-` prefix. This prefix forces `Path=/` and
prohibits a `Domain` attribute, which means **the cookie cannot span two
different public hostnames**.

The only supported topology is therefore **one public hostname fronting both
binaries** via path-routed ingress. `harbor-mgmt` serves every pre-session and
BFF-session path — not just `/login*` — so a path-routing ingress must send
each of these prefixes to `harbor-mgmt`, with everything else falling through
to `harbor-hot`:

```
https://auth.example.com/login*     → harbor-mgmt  (BFF / passkey ceremony)
https://auth.example.com/signup*    → harbor-mgmt  (public signup journey)
https://auth.example.com/signin     → harbor-mgmt  (public sign-in entry point)
https://auth.example.com/enroll     → harbor-mgmt  (enrollment session)
https://auth.example.com/webauthn/* → harbor-mgmt  (WebAuthn ceremonies)
https://auth.example.com/recovery/* → harbor-mgmt  (recovery codes/ack)
https://auth.example.com/*          → harbor-hot   (OIDC hot path)
```

Both services live behind the same TLS terminator and hostname. The
`__Host-harbor-bff` cookie set during `/login` (or `/signin`, or the
post-registration handoff from `/signup/passkey`) is readable by the
subsequent request to `/authorize/complete` (served by harbor-hot) because
they share the same origin.

**Split-host topology is not supported.** If harbor-hot and harbor-mgmt are
exposed under different public hostnames, `__Host-` cookies minted by harbor-mgmt
cannot be read by harbor-hot. Do **not** drop the `__Host-` prefix to work
around this — it would remove a critical security invariant. Instead, use a
path-routing ingress (see `deploy/helm/templates/ingress.yaml` and
`deploy/k8s/ingress.yaml` for a starting point) or place both services behind a
reverse proxy on a shared hostname.

The example manifests referenced above (`deploy/k8s/ingress.yaml`,
`deploy/helm/templates/ingress.yaml`) route the full prefix list above —
`/login`, `/signup`, `/signin`, `/enroll`, `/webauthn`, and `/recovery` — to
`harbor-mgmt`, with everything else falling through to `harbor-hot`.

### AUTHORIZE_COMPLETE_URL

Harbor-mgmt's `LoginHandler` redirects the browser to `/authorize/complete` on
harbor-hot after a successful passkey assertion. Because the two binaries may be
exposed behind a shared hostname (path-routed) or different internal ports, this
URL **must be absolute and explicitly configured** via the `AUTHORIZE_COMPLETE_URL`
environment variable on harbor-mgmt.

- In Helm deployments: set `mgmt.authorizeCompleteURL` in `values.yaml`.
- In raw k8s: edit `AUTHORIZE_COMPLETE_URL` in `deploy/k8s/configmap-mgmt.yaml`.
- Harbor-mgmt **refuses to start** if `DATABASE_URL` is set but
  `AUTHORIZE_COMPLETE_URL` is not — this prevents the M2 redirect bug from
  surfacing silently in production.

## What's here

- `Dockerfile.weft-agent` — the Weft CI agent environment (pinned Go toolchain:
  protoc-gen-go, sqlc, oapi-codegen, golangci-lint, buf). This builds the
  container agents develop Harbor in — it is NOT a runtime image for
  `harbor-hot`/`harbor-mgmt` (those images are published by CI to GHCR).
- `helm/` — a generic, self-hosted Helm chart for `harbor-hot` + `harbor-mgmt`.
  Install with `helm install harbor deploy/helm/ -n harbor --create-namespace`;
  see `helm/README.md` for the values and the production SCAFFOLD checklist.
- `k8s/` — the equivalent minimal example Kubernetes manifests as raw Kustomize
  (namespace, config/secrets, `harbor-hot` + `harbor-mgmt` Deployments/Services,
  Ingress, HPA, PDBs, ServiceAccounts, and NetworkPolicies). Apply with
  `kubectl apply -k deploy/k8s/`. Secrets are placeholders — replace them via
  your secrets manager before deploying.

## PostgreSQL connection budget

Each Harbor replica uses an explicitly bounded pgx pool. The defaults are
`DB_MAX_CONNS=10`, `DB_MIN_CONNS=2`, and
`DB_MAX_CONN_LIFETIME=30m`. Overrides must be positive, must fit their Go
integer/duration types, and `DB_MIN_CONNS` must not exceed
`DB_MAX_CONNS`; invalid settings stop startup.

Size PostgreSQL for every replica that shares the database:

```
application connections = replica ceiling × DB_MAX_CONNS
required max_connections >= application connections + operational headroom
```

At harbor-hot's 20-replica HPA ceiling, the default is `20 × 10 = 200`
application connections. Configure PostgreSQL with `max_connections >= 220`
to reserve 20 connections for administration and monitoring. Add the budgets
of harbor-mgmt, harbor-relay, migration jobs, and any other database clients
when they share the same PostgreSQL server; alternatively lower each
deployment's `DB_MAX_CONNS`.

## Admin Endpoint Access

The `/admin/` path prefix (e.g. `/admin/keys/rotate`, `/admin/revoke-jwt`) is
**blocked at the ingress layer** for all public traffic — both the raw k8s
manifest (`k8s/ingress.yaml`) and the Helm chart (`helm/templates/ingress.yaml`)
configure an nginx `server-snippet` that returns `403 Forbidden` for any request
matching `^/admin`.

This is **defence-in-depth** on top of the application-level `AdminAuthMiddleware`
(Bearer token, constant-time comparison). Even a leaked token cannot be exercised
from the internet.

### How operators access the admin endpoints

Admin endpoints are intended to be called from inside the cluster or over a
trusted network (VPN / bastion). Two safe patterns:

1. **kubectl port-forward** (recommended for one-off operations):
   ```sh
   kubectl port-forward -n harbor svc/harbor-hot 8080:80
   curl -X POST http://localhost:8080/admin/keys/rotate \
     -H "Authorization: Bearer $ADMIN_API_TOKEN"
   ```

2. **Internal / VPN-only Ingress**: create a second `Ingress` resource on an
   internal `ingressClassName` (e.g. `nginx-internal`) that routes only
   `/admin/` to `harbor-hot`, restricted to your VPN CIDR via
   `nginx.ingress.kubernetes.io/whitelist-source-range`. The public Ingress
   keeps the blanket `deny all` rule.

> **Never** remove the `server-snippet` from the public Ingress without
> replacing it with an equivalent network control. Emergency key rotation
> (`/admin/keys/rotate?emergency=true`) invalidates every outstanding token
> instantly — unauthenticated access would be a critical outage vector.

## Harbor Cloud management API

`internal/cloudapi` implements the authenticated, versioned `/admin/v1/*`
management API that the proprietary Harbor Cloud control plane calls to
provision namespaces, mint namespace-scoped sessions, and rotate signing
keys. It is registered on `harbor-mgmt` (never `harbor-hot`'s public
listener) and is fully inert unless `mgmt.cloudIntegration.enabled` is set —
the shipped default for self-hosters is `false`.

### Private-path-only reachability

`/admin/v1/*` is **never** exposed on `auth.harborauth.com` or any other
public ingress. Reachability is restricted at two independent layers:

1. **A dedicated NodePort, not the public Service.** When
   `cloudIntegration.enabled` is `true`,
   `deploy/helm/templates/service-mgmt.yaml` opens a second Service on
   `cloudIntegration.nodePort` (default `30081`). Production must place this
   NodePort behind a private, encrypted transport — the reference deployment
   uses a WireGuard tunnel to Harbor Cloud's cluster — never bind it to a
   public-facing load balancer.
2. **NetworkPolicy CIDR allow-list.** `deploy/helm/templates/networkpolicy-mgmt.yaml`
   adds an ingress rule scoped to `cloudIntegration.allowedCIDR` (the
   WireGuard tunnel address) only when `cloudIntegration.enabled` is `true`;
   `allowedCIDR` is `required` at template time, so the chart refuses to
   render an accidentally-unbounded rule. Every other source — including
   same-cluster pods outside this rule and, by construction, the internet —
   is denied.

Both layers are defense in depth on top of the application-level
`cloudServiceAuth` verification (`internal/cloudapi.ServiceAuthVerifier`):
even a leaked service JWT cannot be presented from outside the tunnel CIDR,
and a request that reaches the pod without a valid JWT is still rejected
fail-closed (see `INV-CLOUDAPI-SERVICE-AUTH` / `INV-CLOUDAPI-REPLAY-RESISTANT`
in `invariants/registry.yaml`).

### Two distinct internal credentials

`/admin/v1/*` and harbor-hot's operator `/admin/*` surface are guarded by
**two independently rotatable credentials** — leaking one must never leak
the other:

| Credential | Env var | Consumed by | Purpose |
|---|---|---|---|
| Operator admin token | `ADMIN_API_TOKEN` | `harbor-hot` (`AdminAuthMiddleware`) | Direct human/operator calls to `/admin/keys/rotate`, `/admin/revoke-jwt`, etc. (see [Admin Endpoint Access](#admin-endpoint-access) above). |
| Management-to-hot proxy token | `MGMT_HOT_PROXY_TOKEN` | `harbor-mgmt` (`internal/cloudapi.KeysHandler`) presents it; `harbor-hot` (`AdminAuthMiddleware`) accepts it | The internal service hop `harbor-mgmt` makes to `harbor-hot` when proxying `POST /admin/v1/keys/rotate` on Harbor Cloud's behalf. |

`AdminAuthMiddleware` accepts either credential on `harbor-hot`'s `/admin/*`
routes and logs which one matched (`credential=operator` vs
`credential=cloud-proxy`), so an operator token leak and a cloud-proxy token
leak are distinguishable in the audit trail and each can be rotated without
touching the other. `MGMT_HOT_PROXY_TOKEN` is **never** the caller-facing
credential for `/admin/v1/*` itself — Harbor Cloud authenticates to
`harbor-mgmt` with a short-lived, scoped `cloudServiceAuth` JWT
(`CLOUD_SERVICE_AUTH_PUBLIC_KEY` trust anchor), and only `harbor-mgmt`'s own
proxy hop to `harbor-hot` uses the static `MGMT_HOT_PROXY_TOKEN`. Key
rotation is deliberately kept out of Harbor Cloud's customer self-service
surface: only the `keys:rotate`-scoped `cloudapi` handler or a human holding
`ADMIN_API_TOKEN` can ever reach harbor-hot's rotation state machine.

Generate both secrets the same way: `openssl rand -hex 32`. See
`deploy/helm/values.yaml`'s `hot.secrets.adminApiToken` and
`mgmt.cloudIntegration.hotProxyToken` (or the raw manifest placeholders in
`deploy/k8s/secret-hot.yaml` / `deploy/k8s/secret-mgmt.yaml`).

## Rate limiting & trusted client IP

Harbor's hot-path rate limiter (`/token`, `/introspect`, `/authorize`,
`/revoke`) keys anonymous buckets on the source IP. Two environment variables
control how that IP is derived:

| Variable | Default | Meaning |
|---|---|---|
| `TRUSTED_PROXY_HOPS` | `0` | Number of trusted reverse-proxy hops between the internet and Harbor. |
| `TRUSTED_FORWARDED_HEADER` | `X-Forwarded-For` (when hops > 0) | Header the outermost proxy sets with the real client IP. |

### Default (TRUSTED_PROXY_HOPS=0)

The forwarded header is **ignored entirely** and `RemoteAddr` is used. This is
the safe default for direct internet exposure or when you cannot trust the
header contents.

### nginx-ingress (TRUSTED_PROXY_HOPS=1)

nginx-ingress uses `$proxy_add_x_forwarded_for` by default, which **appends**
the observed client IP to the **right** of any `X-Forwarded-For` value the
client already sent:

```
# What nginx-ingress produces:
X-Forwarded-For: <client-supplied>, <real-client-IP-seen-by-nginx>
```

⚠️ **The leftmost entry is attacker-controlled.** A client can send
`X-Forwarded-For: <random>` on every request to get a fresh rate-limit bucket,
making every anonymous limit decorative. **Never use leftmost with nginx-ingress.**

With `TRUSTED_PROXY_HOPS=1`, Harbor takes the **1st-from-right** entry — the
IP nginx actually observed, which the client cannot forge:

```
TRUSTED_PROXY_HOPS=1
# TRUSTED_FORWARDED_HEADER defaults to X-Forwarded-For when hops > 0
```

### Additional L7 load balancer (TRUSTED_PROXY_HOPS=2)

If a cloud L7 load balancer sits in front of nginx-ingress and also appends to
`X-Forwarded-For`, set `TRUSTED_PROXY_HOPS=2` to take the 2nd-from-right entry.

### Footgun: getting hops wrong

- **Too high** (more hops than actual proxies): you read into the
  attacker-controlled left region → rate-limit bypass.
- **Too low** (fewer hops than actual proxies): you bucket on a proxy's IP
  instead of the client → entire traffic through that proxy shares one bucket
  (over-limits legitimate users).

**Count only proxies you control that append to the header.** When in doubt,
use `TRUSTED_PROXY_HOPS=0` and configure your proxy to set a non-standard
header (`TRUSTED_FORWARDED_HEADER`) that clients cannot pre-set.

## License

Apache-2.0 (see `LICENSE` in this directory). Self-hosters can derive their
own production infra from these templates without AGPL obligations.
