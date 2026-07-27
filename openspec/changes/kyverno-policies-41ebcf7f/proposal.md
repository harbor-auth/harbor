# Proposal: Kyverno policy-as-code (T2.4 infra hardening)

## Problem

Harbor's cluster has no policy-as-code layer: there is nothing that
admission-time enforces that Pods use pinned image tags, declare resource
limits, or do not request privilege escalation beyond the PSA `restricted`
profile. Without this layer a misconfigured rollout can silently violate
cluster standards and the protections afforded by PSA `restricted` can be
circumvented without any enforcement signal.

In addition, Harbor-namespace Pods lack a lightweight labelling convention
(`app.kubernetes.io/name` + `app.kubernetes.io/version`) that enables Kyverno
policies, dashboards, and automation to reason about workloads.

## Proposed Solution

Install **Kyverno** (admission webhook) via Helm with a single-replica values
file tuned for the single-node RKE2 cluster, then ship four ClusterPolicies:

1. **`disallow-latest-tag`** (Enforce) — reject any Pod whose containers use
   the `:latest` tag or an untagged image reference.
2. **`require-resource-limits`** (Enforce) — reject Pods where any container
   omits CPU or memory limits.
3. **`disallow-privilege-escalation`** (Enforce) — belt-and-suspenders over PSA
   `restricted`: deny `allowPrivilegeEscalation: true` or `privileged: true`;
   exclude the `falco` namespace (Falco is a legitimate privileged workload).
4. **`require-harbor-labels`** (Audit) — report Pods in the `harbor` namespace
   that lack `app.kubernetes.io/name` and/or `app.kubernetes.io/version`.

A kustomization.yaml stitches the policy manifests together for `kubectl
apply -k`. A README documents install order, mode rationale, adding exceptions
via Kyverno's `exclude` block, and rollback.

## Non-Goals

- No image-signing / Cosign `verifyImages` policy (tracked as T3.2).
- No Falco or OPA Gatekeeper (different tools).
- No multi-node Kyverno HA tuning (single-node only; scale-out is future work).
- No cluster-level RBAC changes or new Kubernetes API resources beyond the
  Kyverno CRDs installed by the Helm chart.
- No application (Go) code changes — this is purely cluster infrastructure.

## Success Criteria

- [ ] Kyverno Helm values tuned for single-node (replicaCount=1, resource caps,
  webhook timeout).
- [ ] Four ClusterPolicies authored and YAML-valid.
- [ ] `disallow-latest-tag` and `require-resource-limits` and
  `disallow-privilege-escalation` all use `validationFailureAction: Enforce`.
- [ ] `require-harbor-labels` uses `validationFailureAction: Audit`.
- [ ] `disallow-privilege-escalation` excludes the `falco` namespace.
- [ ] kustomization.yaml references all four policy manifests.
- [ ] README covers install, mode rationale, exceptions, rollback.
- [ ] `go build ./... && go vet ./... && go test ./... && make agent-check` green
  (no Go changes, just verifying no regressions).
