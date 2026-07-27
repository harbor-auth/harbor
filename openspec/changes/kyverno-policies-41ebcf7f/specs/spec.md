# Spec: Kyverno policy-as-code (T2.4 infra hardening)

Adds four Kyverno ClusterPolicies and a Helm values file for the Kyverno
controller, delivering admission-time enforcement of image-tag, resource-limit,
privilege-escalation, and labelling conventions on the Harbor RKE2 cluster.

## ADDED Requirements

### Requirement: REQ-001 Kyverno Helm values — single-node tuning

The repository SHALL provide `deploy/kyverno/values-kyverno.yaml` containing
Helm values for the Kyverno admission controller tuned for the single-node
cluster: `replicaCount: 1`, resource requests and limits, and an admission
webhook timeout of ≤ 10 seconds.

The values file MUST NOT set `replicaCount` higher than 1 (no multi-node HA
topology on a single-node cluster).

#### Scenario: Values file exists with replicaCount=1

**Given** the file `deploy/kyverno/values-kyverno.yaml` is present
**When** it is parsed as YAML
**Then** the `replicaCount` field equals `1`

#### Scenario: Values file sets resource limits

**Given** the file `deploy/kyverno/values-kyverno.yaml`
**When** it is parsed as YAML
**Then** it contains resource requests and limits for the Kyverno controller

---

### Requirement: REQ-002 disallow-latest-tag ClusterPolicy (Enforce)

The repository SHALL provide `deploy/kyverno/policies/disallow-latest-tag.yaml`
as a Kyverno ClusterPolicy with `validationFailureAction: Enforce` that MUST
block admission of any Pod whose init containers or containers reference an
image tagged `:latest` or with no tag (bare digest or no tag token).

#### Scenario: Policy is a valid ClusterPolicy in Enforce mode

**Given** the file `deploy/kyverno/policies/disallow-latest-tag.yaml`
**When** it is parsed as YAML
**Then** `kind` is `ClusterPolicy` and `spec.validationFailureAction` is `Enforce`

#### Scenario: Policy pattern matches :latest images

**Given** the ClusterPolicy `disallow-latest-tag`
**When** its rules are inspected
**Then** the deny/validate rule targets images ending in `:latest` or having no tag

---

### Requirement: REQ-003 require-resource-limits ClusterPolicy (Enforce)

The repository SHALL provide
`deploy/kyverno/policies/require-resource-limits.yaml` as a Kyverno
ClusterPolicy with `validationFailureAction: Enforce` that MUST block admission
of any Pod where one or more containers (or init containers) omit
`.resources.limits.cpu` or `.resources.limits.memory`.

#### Scenario: Policy is a valid ClusterPolicy in Enforce mode

**Given** the file `deploy/kyverno/policies/require-resource-limits.yaml`
**When** it is parsed as YAML
**Then** `kind` is `ClusterPolicy` and `spec.validationFailureAction` is `Enforce`

#### Scenario: Policy checks both CPU and memory limits

**Given** the ClusterPolicy `require-resource-limits`
**When** its rules are inspected
**Then** the rule references both `resources.limits.cpu` and `resources.limits.memory`

---

### Requirement: REQ-004 disallow-privilege-escalation ClusterPolicy (Enforce, falco excluded)

The repository SHALL provide
`deploy/kyverno/policies/disallow-privilege-escalation.yaml` as a Kyverno
ClusterPolicy with `validationFailureAction: Enforce` that MUST block admission
of any Pod where any container sets `allowPrivilegeEscalation: true` or
`securityContext.privileged: true`. The policy MUST exclude the `falco`
namespace unconditionally.

#### Scenario: Policy is in Enforce mode

**Given** the file `deploy/kyverno/policies/disallow-privilege-escalation.yaml`
**When** it is parsed as YAML
**Then** `spec.validationFailureAction` is `Enforce`

#### Scenario: falco namespace is excluded

**Given** the ClusterPolicy `disallow-privilege-escalation`
**When** its `exclude` (or `exceptions`) block is inspected
**Then** the `falco` namespace appears in the exclusion list

---

### Requirement: REQ-005 require-harbor-labels ClusterPolicy (Audit, harbor namespace only)

The repository SHALL provide
`deploy/kyverno/policies/require-harbor-labels.yaml` as a Kyverno ClusterPolicy
with `validationFailureAction: Audit` scoped to the `harbor` namespace via a
`namespaceSelector` that MUST require Pods to carry both
`app.kubernetes.io/name` and `app.kubernetes.io/version` labels.

The policy MUST NOT use `validationFailureAction: Enforce`.

#### Scenario: Policy is in Audit mode

**Given** the file `deploy/kyverno/policies/require-harbor-labels.yaml`
**When** it is parsed as YAML
**Then** `spec.validationFailureAction` is `Audit`

#### Scenario: Policy is scoped to the harbor namespace

**Given** the ClusterPolicy `require-harbor-labels`
**When** its `match` block is inspected
**Then** a `namespaceSelector` or namespace filter limits the policy to the `harbor` namespace

#### Scenario: Policy checks both required labels

**Given** the ClusterPolicy `require-harbor-labels`
**When** its rules are inspected
**Then** both `app.kubernetes.io/name` and `app.kubernetes.io/version` are required

---

### Requirement: REQ-006 kustomization.yaml references all four policies

The repository SHALL provide `deploy/kyverno/kustomization.yaml` listing all
four ClusterPolicy YAML files as kustomize resources.

#### Scenario: kustomization.yaml is valid and lists four policies

**Given** the file `deploy/kyverno/kustomization.yaml`
**When** it is parsed as YAML
**Then** the `resources` list includes all four policy file paths

---

### Requirement: REQ-007 README documents operational procedures

The repository SHALL provide `deploy/kyverno/README.md` that covers:
- Install order (Kyverno Helm chart first, then `kubectl apply -k`)
- Policy mode rationale (Audit vs Enforce per policy)
- How to add per-workload exceptions via Kyverno `exclude` blocks
- Rollback procedure

#### Scenario: README exists and is non-empty

**Given** the file `deploy/kyverno/README.md`
**When** it is read
**Then** it contains sections on install order, policy modes, exceptions, and rollback
