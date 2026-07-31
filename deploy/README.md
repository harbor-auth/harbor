# deploy/

Reference deployment artifacts for self-hosters.

> **Status:** placeholder skeleton. Production deployment infrastructure
> (Terraform, production Helm values/overlays, region topology) lives in
> the closed-source `harbor-auth/harbor-cloud` repo.

## BFF Topology — Single Public Host (Required)

The Browser-Facing BFF (passkey login ceremony, `/login`, `/login/complete`) uses
cookies with the `__Host-` prefix. This prefix forces `Path=/` and prohibits a
`Domain` attribute, which means **the cookie cannot span two different public
hostnames**.

The only supported topology is therefore **one public hostname fronting both
binaries** via path-routed ingress:

```
https://auth.example.com/login*   → harbor-mgmt  (BFF / passkey ceremony)
https://auth.example.com/*        → harbor-hot   (OIDC hot path)
```

Both services live behind the same TLS terminator and hostname. The
`__Host-harbor-bff` cookie set during `/login` is readable by the subsequent
request to `/authorize/complete` (served by harbor-hot) because they share the
same origin.

**Split-host topology is not supported.** If harbor-hot and harbor-mgmt are
exposed under different public hostnames, `__Host-` cookies minted by harbor-mgmt
cannot be read by harbor-hot. Do **not** drop the `__Host-` prefix to work
around this — it would remove a critical security invariant. Instead, use a
path-routing ingress (see `deploy/helm/templates/ingress.yaml` and
`deploy/k8s/ingress.yaml` for a starting point) or place both services behind a
reverse proxy on a shared hostname.

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

## License

Apache-2.0 (see `LICENSE` in this directory). Self-hosters can derive their
own production infra from these templates without AGPL obligations.
