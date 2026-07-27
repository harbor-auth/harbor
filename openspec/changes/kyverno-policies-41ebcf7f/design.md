# Design: Kyverno policy-as-code (T2.4 infra hardening)

## Key Decisions

### Decision 1: replicaCount=1 for the single-node cluster
**Chosen:** Deploy Kyverno with a single replica.
**Rationale:** The Harbor cluster is a single-node RKE2 setup. Kyverno's HA
topology (3 replicas) is only needed for multi-node clusters where a pod
restart would leave the admission webhook unreachable. On a single node,
replicaCount=1 avoids the overhead of a leader-election quorum and keeps
resource consumption low.
**Alternatives considered:** replicaCount=3 (rejected — no other nodes to
schedule the replicas on, forced anti-affinity would leave pods Pending).

### Decision 2: Enforce for PSA-companion policies, Audit for labelling
**Chosen:** `disallow-latest-tag`, `require-resource-limits`, and
`disallow-privilege-escalation` use `validationFailureAction: Enforce`.
`require-harbor-labels` uses `validationFailureAction: Audit`.
**Rationale:** The first three policies are safety rails that mirror or
strengthen the PSA `restricted` profile already enforced on the `harbor`
namespace — they should block bad admissions immediately. The labelling policy
is a hygiene check where existing Pods may not yet carry the labels; starting
in Audit allows the team to see the violation count before flip to Enforce.
**Alternatives considered:** Start everything in Audit (rejected — the
PSA-companion policies provide no protection until Enforced); Enforce all four
immediately (rejected — a label-enforcement failure would block a legitimate
rollout and the labelling convention is not yet fully rolled out).

### Decision 3: Never combine Audit + Enforce in the same ClusterPolicy
**Chosen:** Each ClusterPolicy is in exactly one mode. A rollout from Audit to
Enforce is performed by editing the single field `validationFailureAction` in
the existing resource (or by deleting and re-applying), never by having two
separate rules in the same policy with different modes.
**Rationale:** A single policy with mixed modes is confusing, hard to reason
about, and error-prone in GitOps (a conflict between the two modes may produce
unexpected behaviour depending on the Kyverno version). The accepted pattern is
one resource, one mode.
**Alternatives considered:** Two ClusterPolicy resources per rule — one Audit
and one Enforce — deleted when the Enforce variant is promoted (rejected —
doubles resource count and risks a window where both are active simultaneously).

### Decision 4: Exclude falco namespace from privilege-escalation policy
**Chosen:** The `disallow-privilege-escalation` ClusterPolicy excludes the
`falco` namespace unconditionally.
**Rationale:** Falco requires privileged containers and host-PID access to
read kernel-level eBPF maps; blocking those at admission would break Falco
without any security benefit (Falco is intentionally privileged). The `falco`
namespace does not run Harbor workloads, so the exclusion does not weaken the
protection over Harbor Pods.
**Alternatives considered:** Use a Kyverno `PolicyException` resource (rejected
— PolicyException requires an additional CRD and is a heavier mechanism than
a namespace-level exclude for a stable, long-lived exception); rely solely on
PSA mode `privileged` on the falco namespace (rejected — the two controls are
independent and we should not assume PSA namespace labels are always correct).

### Decision 5: kustomization.yaml for policy apply, separate from Helm
**Chosen:** Policies live in `deploy/kyverno/policies/` referenced by a
`deploy/kyverno/kustomization.yaml`. Kyverno itself is installed via Helm
(using `deploy/kyverno/values-kyverno.yaml`); policies are applied separately
with `kubectl apply -k deploy/kyverno/`.
**Rationale:** Kyverno CRDs must exist before ClusterPolicy resources can be
applied; keeping Helm (for Kyverno itself) and kustomize (for policies) as
separate steps makes the ordering explicit and avoids a CRD-not-ready race in
a single `helm install`.
**Alternatives considered:** Package policies inside the Helm chart (rejected —
the Kyverno chart does not have a first-class mechanism for shipping
ClusterPolicy resources alongside the controller, and bundling them risks
ordering issues); ArgoCD Application syncing Helm + kustomize together (allowed
but the explicit two-step is safer for initial rollout).

## Security & Infrastructure Invariants

- Kyverno webhook `failurePolicy: Fail` (default) — if Kyverno is unreachable,
  admission is blocked rather than silently allowed.
- No `exclude` blocks other than the deliberate `falco` namespace carve-out on
  the privilege-escalation policy.
- Policy mode (`validationFailureAction`) is the ONLY dimension of Audit vs
  Enforce; no mixed-mode resources.
- The labelling policy (`require-harbor-labels`) is scoped to the `harbor`
  namespace via a `namespaceSelector` so it does not fire on system namespaces.
