# Proposal: ArgoCD SSO with Dex + GitHub OAuth (T2.2)

## Problem

ArgoCD is currently secured only by a rotated admin password (T1.3). There is no
SSO, so access control is binary: admin-or-nothing. This violates least-privilege:
any engineer with the password has full cluster-deploy rights, and there is no
audit trail tied to a real identity. The `infra-hardening.md` plan calls this out
explicitly as T2.2 and marks it as the next item after T1.5 (secretbox, completed
2026-07-24).

## Proposed Solution

Configure ArgoCD's built-in Dex to authenticate via GitHub OAuth, scoped to the
`harbor-auth` org and `ops` team:

1. **`argocd-cm` patch** — add `url`, `dex.config` (GitHub connector, org + team
   scope), and `oidc.config` block so ArgoCD delegates all login to Dex.
2. **`argocd-rbac-cm` patch** — set `policy.default=role:readonly`; grant the
   `harbor-auth:ops` GitHub team the `role:ops` policy (applications write +
   clusters get).
3. **`dex-secret-template.yaml`** — a `SealedSecret` template (or ExternalSecret
   stub) that holds the GitHub OAuth app client ID and secret, injected as
   `$dex.github.clientSecret` in the Dex config.
4. **`kustomization.yaml`** — wires all patches and the secret into a Kustomize
   overlay so `kubectl apply -k deploy/argocd/` applies the full SSO stack.
5. **`README.md` update** — step-by-step GitHub OAuth app registration, DNS
   prereqs (argocd.internal.harborauth.com), and a rollback procedure.

## Non-Goals

- Disabling the admin account (a separate manual step documented in the README
  but NOT automated — requires SSO to be confirmed working first).
- Installing or upgrading ArgoCD itself (assumed to be running; this change is
  config only).
- mTLS or Linkerd integration (T2.3, separate plan).
- Multi-team or fine-grained RBAC beyond readonly/ops (future iteration).

## Success Criteria

- [ ] `kubectl apply --dry-run=client -k deploy/argocd/` succeeds with no errors.
- [ ] `make agent-check` is green (go build + vet + test pass; no Go code changes).
- [ ] ArgoCD is reachable at `argocd.internal.harborauth.com` after the DNS step.
- [ ] GitHub org members in `harbor-auth:ops` can log in and deploy.
- [ ] Non-ops GitHub org members get read-only access.
- [ ] Non-org GitHub users are denied entirely.
