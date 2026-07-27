# Tasks: ArgoCD SSO with Dex + GitHub OAuth (T2.2)

## Prerequisites

- [ ] ArgoCD is installed and running in the `argocd` namespace on the cluster.
- [ ] `kubeseal` CLI is available to generate the real SealedSecret from the GitHub OAuth app credentials (manual operator step; the template is committed, the sealed result is committed separately).
- [ ] A GitHub OAuth App is registered (or will be registered following the README steps) with callback URL `https://argocd.internal.harborauth.com/dex/callback`.
- [ ] DNS entry `argocd.internal.harborauth.com` points to the cluster ingress (manual operator step; documented in README).
- [ ] **No DB migration.** This change is config-only (YAML files); no Go code changes, no database schema changes.

## Implementation

- [ ] `docs/plans/argocd-sso.md`: Create the plan file for this feature, following the Harbor plan template. Mark `status: in-progress`.
- [ ] `deploy/argocd/argocd-cm-patch.yaml`: Create the ArgoCD ConfigMap strategic-merge patch that sets `url: https://argocd.internal.harborauth.com` and the `dex.config` block (GitHub connector, harbor-auth org, ops team, `$dex.github.clientSecret` injection).
- [ ] `deploy/argocd/argocd-rbac-cm-patch.yaml`: Create the RBAC ConfigMap patch with `policy.default: role:readonly` and `policy.csv` granting `harbor-auth:ops` the `role:ops` policy (applications write + clusters get).
- [ ] `deploy/argocd/dex-secret-template.yaml`: Create the SealedSecret template (kind: SealedSecret, namespace: argocd, name: argocd-secret or dex-github-secret) with placeholder encrypted blobs for `clientID` and `clientSecret`. Add comment block with `kubeseal` command.
- [ ] `deploy/argocd/kustomization.yaml`: Create the Kustomize overlay listing `patches:` for the two ConfigMap patches and `resources:` for `dex-secret-template.yaml`. Set `namespace: argocd`.
- [ ] `deploy/argocd/README.md`: Update (or replace) with full SSO setup guide: GitHub OAuth app registration steps, DNS prereqs (argocd.internal.harborauth.com), kubeseal sealing steps, apply procedure, verification steps, and rollback procedure (revert the ConfigMap patches and delete the secret).

## Validation

- [ ] `kubectl apply --dry-run=client -k deploy/argocd/` exits 0 with no errors (validates YAML and Kustomize wiring).
- [ ] `go build ./... && go vet ./... && go test ./...` green (no Go code changes; confirms no regressions).
- [ ] `make agent-check` green.
- [ ] `openspec validate argocd-sso-bf39b5ec --strict` passes.
