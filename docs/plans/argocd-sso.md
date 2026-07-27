---
status: in-progress
design_refs: docs/infra-hardening.md T2.2
targets:
  - deploy/argocd/argocd-cm-patch.yaml
  - deploy/argocd/argocd-rbac-cm-patch.yaml
  - deploy/argocd/dex-secret-template.yaml
  - deploy/argocd/kustomization.yaml
  - deploy/argocd/README.md
created: 2026-07-27
openspec: openspec/changes/argocd-sso-bf39b5ec/
---

# ArgoCD SSO — Dex + GitHub OAuth (T2.2)

## Problem

ArgoCD is currently protected only by a rotated admin password (T1.3). There
is no SSO, so access control is binary: admin-or-nothing. Any engineer with the
password has full cluster-deploy rights, and there is no audit trail tied to a
real identity. This violates least-privilege and is flagged in
`docs/plans/infra-hardening.md` as T2.2 — the next hardening item after T1.5
(secretbox cipher, completed 2026-07-24).

## Proposed Approach

Configure ArgoCD's built-in Dex to authenticate via GitHub OAuth, scoped to
the `harbor-auth` org and `ops` team. All deliverables are GitOps YAML — no
Go code changes.

### Deliverables

| File | Purpose |
|---|---|
| `deploy/argocd/argocd-cm-patch.yaml` | Strategic-merge patch: sets ArgoCD `url` + Dex GitHub connector |
| `deploy/argocd/argocd-rbac-cm-patch.yaml` | RBAC patch: `policy.default=role:readonly`, ops team gets deploy rights |
| `deploy/argocd/dex-secret-template.yaml` | SealedSecret template for GitHub OAuth client ID + secret |
| `deploy/argocd/kustomization.yaml` | Kustomize overlay wiring all the above |
| `deploy/argocd/README.md` | Setup guide: OAuth app registration, DNS, kubeseal, rollback |

### Key Decisions

- **Built-in Dex** — use ArgoCD's bundled Dex, not an external OIDC provider.
  Harbor's OIDC is not appropriate here (PPID/PKCE overhead for an ops tool).
- **GitHub connector** — `type: github`, `orgs: [{name: harbor-auth, teams: [ops]}]`.
- **RBAC** — `policy.default: role:readonly`; `harbor-auth:ops` → `role:ops`
  (applications write + clusters get).
- **SealedSecrets** — OAuth client secret committed as SealedSecret template;
  operator seals with `kubeseal` and commits the result.
- **Admin account** — disabling it is a separate manual step (documented in
  README); NOT automated here. Must confirm SSO works first.

## DESIGN Alignment

This is an infrastructure hardening task (see `docs/plans/infra-hardening.md`,
T2.2). It does not touch the application OIDC protocol (§3.1), user identity
(§3.2), or any Harbor security invariants. It operates entirely in the `argocd`
namespace using ArgoCD's own config layer.

## Target Code Paths

- `deploy/argocd/` — new files only; no existing files removed.
- `docs/plans/argocd-sso.md` — this plan.

## Implementation Checklist

- [ ] Create `docs/plans/argocd-sso.md` (this file)
- [ ] Create `deploy/argocd/argocd-cm-patch.yaml` — Dex connector + ArgoCD URL
- [ ] Create `deploy/argocd/argocd-rbac-cm-patch.yaml` — RBAC policy
- [ ] Create `deploy/argocd/dex-secret-template.yaml` — SealedSecret template
- [ ] Create `deploy/argocd/kustomization.yaml` — Kustomize overlay
- [ ] Update `deploy/argocd/README.md` — full SSO setup guide
- [ ] Validate: `kubectl apply --dry-run=client -k deploy/argocd/`
- [ ] Validate: `make agent-check` green
- [ ] OpenSpec verify: `openspec validate argocd-sso-bf39b5ec --strict`
- [ ] Create PR
- [ ] CI green + squash-merge

## Risks

- **Lock-out risk:** if SSO is misconfigured and the admin account is disabled,
  access to ArgoCD is lost. Mitigation: keep admin enabled until SSO is
  confirmed working (documented as a manual step, not automated).
- **GitHub OAuth rate limits:** Dex calls `api.github.com` on every login;
  mitigated by caching in Dex's connector.
- **DNS dependency:** `argocd.internal.harborauth.com` must resolve before SSO
  can be tested; documented as a prerequisite in the README.

## Definition of Done

- `kubectl apply --dry-run=client -k deploy/argocd/` exits 0
- `make agent-check` green
- `openspec validate argocd-sso-bf39b5ec --strict` passes
- PR merged to `main` with CI green
- `harbor-auth:ops` team members can log in to ArgoCD via GitHub SSO
