# Spec: ArgoCD SSO — Requirements

## ADDED Requirements

### REQ-001: ArgoCD URL configured for SSO redirect

The `argocd-cm` ConfigMap patch SHALL set `url` to the ArgoCD ingress hostname
(`https://argocd.internal.harborauth.com`) so Dex can construct correct OAuth
callback URIs.

#### Scenario: Dex callback URL matches ArgoCD hostname

**Given** the `argocd-cm` ConfigMap contains `url: https://argocd.internal.harborauth.com`  
**When** a user initiates GitHub OAuth login  
**Then** Dex redirects the browser to `https://argocd.internal.harborauth.com/auth/callback`

---

### REQ-002: Dex GitHub connector scoped to harbor-auth org and ops team

The `dex.config` block in `argocd-cm` SHALL include a GitHub connector of
`type: github`, scoped to `orgs: [{name: harbor-auth, teams: [ops]}]`.
The connector MUST reference the OAuth client secret via
`$dex.github.clientSecret` (environment-variable injection from the
`argocd-secret` Secret) rather than inlining it in plaintext.

#### Scenario: Only harbor-auth org members can authenticate

**Given** a GitHub user who is NOT a member of the `harbor-auth` org  
**When** they attempt to log in to ArgoCD  
**Then** Dex returns an authentication error and ArgoCD denies access

#### Scenario: harbor-auth org member authenticates successfully

**Given** a GitHub user who IS a member of the `harbor-auth` org  
**When** they complete the GitHub OAuth flow  
**Then** Dex returns a valid ID token and ArgoCD creates a session

---

### REQ-003: RBAC default is role:readonly

The `argocd-rbac-cm` ConfigMap patch SHALL set `policy.default: role:readonly`
so that any authenticated user who is not explicitly granted a higher role
gets read-only access to ArgoCD application state.

#### Scenario: Org member without ops team gets read-only access

**Given** a GitHub user in `harbor-auth` org but NOT in the `ops` team  
**When** they authenticate and navigate to ArgoCD  
**Then** they can view application status and logs but CANNOT trigger syncs or rollbacks

---

### REQ-004: harbor-auth:ops team gets deploy rights

The `policy.csv` in `argocd-rbac-cm` SHALL include a group mapping:
`g, harbor-auth:ops, role:ops` and policy rows granting `role:ops`
the ability to perform all application actions (`applications, *, */*, allow`)
and to read cluster state (`clusters, get, *, allow`).

#### Scenario: ops team member can sync an application

**Given** a GitHub user who is a member of `harbor-auth:ops`  
**When** they trigger an application sync in ArgoCD  
**Then** the sync succeeds (they have `applications, sync, *, allow`)

#### Scenario: non-ops user cannot sync

**Given** a GitHub user in `harbor-auth` org but NOT in `ops`  
**When** they attempt to trigger an application sync  
**Then** ArgoCD returns a permission denied error

---

### REQ-005: GitHub OAuth client secret is never committed in plaintext

The `dex-secret-template.yaml` SHALL be a SealedSecret template with placeholder
encrypted blobs, never plaintext values. The README SHALL document the
`kubeseal` command to produce the real sealed secret from the GitHub OAuth app
client ID and secret.

#### Scenario: Secret file contains no plaintext credentials

**Given** the `dex-secret-template.yaml` file in the repository  
**When** a reviewer inspects it  
**Then** all sensitive fields contain only placeholder encrypted ciphertext or
clearly labeled placeholder strings (not real secrets)

---

### REQ-006: Kustomize overlay applies the full SSO stack

A `kustomization.yaml` in `deploy/argocd/` SHALL list the patches and resources
such that `kubectl apply -k deploy/argocd/` (or `kubectl apply --dry-run=client -k deploy/argocd/`)
applies `argocd-cm-patch.yaml`, `argocd-rbac-cm-patch.yaml`, and
`dex-secret-template.yaml` without error.

#### Scenario: Dry-run apply succeeds

**Given** a cluster with ArgoCD installed in the `argocd` namespace  
**When** `kubectl apply --dry-run=client -k deploy/argocd/` is run  
**Then** the command exits 0 and reports no errors
