# deploy/

Reference deployment artifacts for self-hosters.

> **Status:** placeholder skeleton. Production deployment infrastructure
> (Terraform, production Helm values/overlays, region topology) lives in
> the closed-source `harbor-auth/harbor-cloud` repo.

## What belongs here

- `Dockerfile` — multi-stage builds for `harbor-hot` and `harbor-mgmt`.
- `helm/` — a generic, self-hosted Helm chart.
- `compose/` — Docker Compose for local/small-scale deployment.
- `k8s/` — minimal example Kubernetes manifests.

## License

Apache-2.0 (see `LICENSE` in this directory). Self-hosters can derive their
own production infra from these templates without AGPL obligations.
