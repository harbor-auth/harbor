# Harbor GitOps deployment (ArgoCD)

This directory holds the GitOps configuration that drives the running Harbor
deployment on the RKE2 cluster. Git is the source of truth: a push to `main`
deploys itself.

## The flow

```
git push to main (Go / Dockerfile change)
    └─▶ .github/workflows/publish.yml
          ├─ builds harbor-hot + harbor-mgmt images
          ├─ pushes ghcr.io/harbor-auth/harbor/<svc>:<sha> and :latest
          └─ pins global.image.tag → <sha> in values-prod.yaml, commits [skip ci]
              └─▶ ArgoCD (Application `harbor`) sees the git change
                    └─ runs `helm upgrade` (deploy/helm + values-prod.yaml)
                        └─▶ RKE2 rolls out the new images
```

Images are pinned to the **immutable commit SHA** (not `:latest`) in
`values-prod.yaml`, so every deploy is reproducible and rollbacks are just a
revert of the pinning commit.

## Files

| File | Purpose |
|------|---------|
| `application.yaml` | ArgoCD `Application` — points at `deploy/helm` with `values-prod.yaml`, auto-syncs with prune + self-heal. |
| `values-prod.yaml` | Production Helm overrides (domain, single-node replicas, existing secrets). `global.image.tag` is **managed by CI** — do not edit it by hand. |

## One-time bootstrap

```bash
# 1. Install ArgoCD (from the URL, no repo files needed):
kubectl create namespace argocd
kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml

# 2. After this directory is on main, register the Application:
kubectl apply -f deploy/argocd/application.yaml
```

After that, everything is automatic — merges to `main` deploy without any manual
`kubectl`/`helm` step.

## Changing the domain

Edit these values **together** in `values-prod.yaml` (they must all agree, or
OIDC discovery / WebAuthn origin checks will fail closed) and commit:

- `ingress.host`
- `hot.issuer`
- `mgmt.webauthn.rpId`, `mgmt.webauthn.rpName`, `mgmt.webauthn.rpOrigin`

Then make sure the TLS cert named by `ingress.tlsSecretName` exists for the new
host (cert-manager provisions it). ArgoCD applies the change on the next sync.
