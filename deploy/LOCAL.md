# Local Deployment Context

> ⚠️ This file is gitignored — it is local only and never committed.
> **Always use this machine when deploying or operating Harbor via SSH.**

## Deployment Target Machine

| Field    | Value                    |
|----------|--------------------------|
| IP       | `51.89.98.90`            |
| Hostname | `ns31170412`             |
| User     | `ubuntu`                 |
| OS       | Ubuntu 24.04 LTS         |
| SSH      | `ssh ubuntu@51.89.98.90` |

## Secrets

Stored in **`~/.harbor.env`** on your local machine (never committed). Currently contains:

- `CLOUDFLARE_DNS_ZONE_KEY` — used for Cloudflare DNS-01 ACME challenges on the cluster.

Source before running any deployment commands:

```bash
source ~/.harbor.env
```

## Runtime Kubernetes Secrets

These secrets are managed **out-of-band** from ArgoCD/Helm (ArgoCD is configured to never prune Secrets).
Create them once after initial cluster setup; they persist across ArgoCD syncs.

### `harbor-hot-secrets` (namespace: harbor)

```bash
kubectl create secret generic harbor-hot-secrets -n harbor \
  --from-literal=DATABASE_URL="postgres://harbor:<pg-password>@harbor-postgresql.harbor.svc.cluster.local:5432/harbor?sslmode=disable" \
  --from-literal=REDIS_URL="redis://harbor-redis-master.harbor.svc.cluster.local:6379" \
  --from-literal=KEK_SECRET="<32-byte-hex-kek>"
```

### `harbor-mgmt-secrets` (namespace: harbor)

```bash
kubectl create secret generic harbor-mgmt-secrets -n harbor \
  --from-literal=DATABASE_URL="postgres://harbor:<pg-password>@harbor-postgresql.harbor.svc.cluster.local:5432/harbor?sslmode=disable" \
  --from-literal=REDIS_URL="redis://harbor-redis-master.harbor.svc.cluster.local:6379" \
  --from-literal=HARBOR_KMS_SECRET="<32-byte-hex-kms>"
```

**Note:** The PostgreSQL password is stored in `harbor-postgresql` secret:
```bash
kubectl get secret harbor-postgresql -n harbor -o jsonpath="{.data.password}" | base64 -d
```

### Why ArgoCD doesn’t prune these

`argocd-cm` has `resource.exclusions` set to exclude all `Secret` resources from ArgoCD’s pruning logic:

```bash
kubectl get configmap argocd-cm -n argocd -o jsonpath="{.data.resource\.exclusions}"
```
