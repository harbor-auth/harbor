# deploy/

Reference deployment artifacts for self-hosters.

> **Status:** placeholder skeleton. Production deployment infrastructure
> (Terraform, production Helm values/overlays, region topology) lives in
> the closed-source `harbor-auth/harbor-cloud` repo.

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

## License

Apache-2.0 (see `LICENSE` in this directory). Self-hosters can derive their
own production infra from these templates without AGPL obligations.
