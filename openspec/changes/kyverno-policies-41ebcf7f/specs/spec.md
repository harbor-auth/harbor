# Spec: Kyverno policy-as-code (T2.4 infra hardening)

Adds four Kyverno ClusterPolicies enforced at Kubernetes admission time, plus a
single-replica fail-open Kyverno install profile for the RKE2 single-node cluster.
All policies start in `Audit` mode; three are promoted to `Enforce` once PolicyReports
confirm Harbor-owned workloads are compliant. Cross-links to
[`docs/plans/kyverno-policies.md`](../../../../docs/plans/kyverno-policies.md).

## ADDED Requirements

### Requirement: REQ-001 Kyverno admission controller SHALL be single-replica with fail-open webhook

On a single-node cluster the system SHALL install Kyverno with exactly one replica
per controller (`admissionController`, `backgroundController`, `cleanupController`,
`reportsController`) and MUST set `failurePolicy: Ignore` on all admission webhooks.
The control plane MUST NOT be blocked if Kyverno is unavailable.

#### Scenario: Kyverno pod restart does not block pod admission

**Given** the Kyverno admission controller pod is terminating (e.g. during an upgrade)
**When** the Kubernetes API server receives a new pod admission request
**Then** the request is admitted (fail-open) and does not block indefinitely

#### Scenario: Single replica is sufficient for single-node

**Given** a single-node RKE2 cluster
**When** Kyverno is installed with `admissionController.replicas: 1`
**Then** Kyverno functions correctly and enforces policies without requiring multiple replicas

---

### Requirement: REQ-002 disallow-latest-tag SHALL block containers using `:latest` or no tag

The system SHALL enforce, at admission time, that every container and initContainer
in the `harbor` and `argocd` namespaces uses a concrete, pinned image tag. It MUST
reject any Pod (or controller autogen equivalent) whose container image is untagged
or tagged `:latest`. It MUST apply this rule via Kyverno autogen to Deployments,
StatefulSets, DaemonSets, Jobs, and CronJobs in the same namespaces.

#### Scenario: Pod with :latest tag is rejected in the harbor namespace

**Given** a Pod manifest whose container image is `harbor-hot:latest` targeting namespace `harbor`
**When** the manifest is submitted to the Kubernetes API server
**Then** the admission webhook rejects it with a policy violation message referencing `disallow-latest-tag`

#### Scenario: Pod with no tag is rejected in the argocd namespace

**Given** a Pod manifest whose container image is `bitnami/redis` (no tag) targeting namespace `argocd`
**When** the manifest is submitted to the Kubernetes API server
**Then** the admission webhook rejects it with a policy violation message referencing `disallow-latest-tag`

#### Scenario: Pod with a pinned tag is admitted

**Given** a Pod manifest whose container image is `harbor-hot:v1.2.3` targeting namespace `harbor`
**When** the manifest is submitted to the Kubernetes API server
**Then** the admission webhook admits the request

#### Scenario: Pod in kube-system is unaffected

**Given** a Pod manifest whose container image is `rancher/kube-apiserver:latest` targeting namespace `kube-system`
**When** the manifest is submitted to the Kubernetes API server
**Then** the admission webhook admits the request (out of scope for this policy)

---

### Requirement: REQ-003 require-resource-limits SHALL enforce CPU and memory limits on harbor containers

The system SHALL enforce, at admission time, that every container in the `harbor`
namespace declares both `resources.limits.cpu` and `resources.limits.memory`. It MUST
reject any Pod (or controller autogen equivalent) missing either limit. It SHALL NOT
enforce this requirement on namespaces outside `harbor`.

#### Scenario: Pod missing memory limit is rejected in harbor namespace

**Given** a Pod manifest with `resources.limits.cpu: 500m` but no `resources.limits.memory` targeting namespace `harbor`
**When** the manifest is submitted to the Kubernetes API server
**Then** the admission webhook rejects it with a policy violation message referencing `require-resource-limits`

#### Scenario: Pod missing both limits is rejected

**Given** a Pod manifest with no `resources.limits` block targeting namespace `harbor`
**When** the manifest is submitted to the Kubernetes API server
**Then** the admission webhook rejects it with a policy violation message referencing `require-resource-limits`

#### Scenario: Pod with both limits set is admitted

**Given** a Pod manifest with `resources.limits.cpu: 500m` and `resources.limits.memory: 256Mi` targeting namespace `harbor`
**When** the manifest is submitted to the Kubernetes API server
**Then** the admission webhook admits the request

#### Scenario: Pod in argocd without limits is unaffected by this policy

**Given** a Pod manifest with no `resources.limits` block targeting namespace `argocd`
**When** the manifest is submitted to the Kubernetes API server
**Then** `require-resource-limits` does not reject the request (scoped to `harbor` only)

---

### Requirement: REQ-004 disallow-privilege-escalation SHALL block allowPrivilegeEscalation cluster-wide, excluding exempt namespaces

The system SHALL enforce, at admission time, that every container cluster-wide
sets `allowPrivilegeEscalation: false`. It MUST reject any Pod (or controller autogen
equivalent) where `allowPrivilegeEscalation` is `true` or is absent (Kubernetes
default is `true` when unset). It MUST exclude the namespaces `kube-system`,
`kyverno`, `cert-manager`, and `falco` from this requirement.

#### Scenario: Pod with allowPrivilegeEscalation: true is rejected

**Given** a Pod manifest with `securityContext.allowPrivilegeEscalation: true` targeting namespace `harbor`
**When** the manifest is submitted to the Kubernetes API server
**Then** the admission webhook rejects it with a policy violation message referencing `disallow-privilege-escalation`

#### Scenario: Pod with allowPrivilegeEscalation absent is rejected

**Given** a Pod manifest with no `securityContext.allowPrivilegeEscalation` field targeting namespace `default`
**When** the manifest is submitted to the Kubernetes API server
**Then** the admission webhook rejects it (field absent defaults to `true`, which is disallowed)

#### Scenario: Pod with allowPrivilegeEscalation: false is admitted

**Given** a Pod manifest with `securityContext.allowPrivilegeEscalation: false` targeting namespace `harbor`
**When** the manifest is submitted to the Kubernetes API server
**Then** the admission webhook admits the request

#### Scenario: Privileged pod in falco namespace is admitted (exempt)

**Given** a Pod manifest with `securityContext.allowPrivilegeEscalation: true` targeting namespace `falco`
**When** the manifest is submitted to the Kubernetes API server
**Then** the admission webhook admits the request (falco is an exempt namespace)

#### Scenario: Privileged pod in kube-system is admitted (exempt)

**Given** a Pod manifest with `securityContext.allowPrivilegeEscalation: true` targeting namespace `kube-system`
**When** the manifest is submitted to the Kubernetes API server
**Then** the admission webhook admits the request (kube-system is an exempt namespace)

---

### Requirement: REQ-005 require-harbor-labels SHALL audit harbor-namespace Pods for missing standard labels

The system SHALL, in `Audit` mode, surface any Pod in the `harbor` namespace that
is missing the labels `app.kubernetes.io/name` or `app.kubernetes.io/version`.
It MUST NOT reject such Pods — it MUST emit a `PolicyReport` entry with the violation.
It SHALL apply via Kyverno autogen to Deployments, StatefulSets, and other controllers.

#### Scenario: Pod missing app.kubernetes.io/name label produces an Audit result

**Given** a Pod manifest without the label `app.kubernetes.io/name` targeting namespace `harbor`
**When** the manifest is submitted to the Kubernetes API server
**Then** the pod is admitted AND a PolicyReport entry is created recording the `require-harbor-labels` violation

#### Scenario: Pod with both required labels produces no violation

**Given** a Pod manifest with labels `app.kubernetes.io/name: harbor-hot` and `app.kubernetes.io/version: v1.2.3` targeting namespace `harbor`
**When** the manifest is submitted to the Kubernetes API server
**Then** the pod is admitted and no `require-harbor-labels` PolicyReport entry is created

#### Scenario: Pod in a different namespace is unaffected

**Given** a Pod manifest without `app.kubernetes.io/name` targeting namespace `argocd`
**When** the manifest is submitted to the Kubernetes API server
**Then** the pod is admitted and no `require-harbor-labels` PolicyReport entry is created (policy is scoped to `harbor` only)

---

### Requirement: REQ-006 All Enforce policies SHALL use background scanning

The system SHALL configure `background: true` on all Enforce ClusterPolicies so
that existing non-compliant resources (deployed before Kyverno was installed or before
the policy was applied) are surfaced in PolicyReports without requiring a re-admission
event.

#### Scenario: Background scan surfaces an existing non-compliant resource

**Given** a running Pod in `harbor` that was deployed before `require-resource-limits` was applied
**When** the Kyverno background controller performs its scan cycle
**Then** a PolicyReport entry is created for that Pod recording the `require-resource-limits` violation, without evicting or restarting the Pod
