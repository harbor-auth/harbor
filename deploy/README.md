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

## License

Apache-2.0 (see `LICENSE` in this directory). Self-hosters can derive their
own production infra from these templates without AGPL obligations.
