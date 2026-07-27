# Proposal: Kyverno policy-as-code (T2.4 infra hardening)

## Problem

The cluster enforces Pod Security Admission `restricted` on the `harbor` namespace,
but PSA is a fixed, coarse profile — it cannot express Harbor-specific standards.
Today there is no admission-time enforcement of:

- Image tag discipline (`:latest` makes rollbacks non-reproducible and diffs meaningless).
- CPU/memory limits — a single runaway pod on the **single-node** cluster starves etcd,
  the API server, and every Harbor workload simultaneously.
- Labeling conventions (`app.kubernetes.io/name`, `…/version`) that observability and
  audit tooling depend on.
- Privilege escalation in namespaces PSA does not label (ArgoCD, future Falco/Linkerd).

Every guardrail today is convention enforced by humans at review time. A bad
`kubectl apply` or a subtly wrong ArgoCD sync lands silently.

## Proposed Solution

Install **Kyverno** (YAML-native admission controller, no Rego) and ship four
ClusterPolicies versioned in git and deployed by ArgoCD:

1. `disallow-latest-tag` (Enforce) — block any container using `:latest` or no tag, scoped to `harbor` + `argocd`.
2. `require-resource-limits` (Enforce) — all containers in `harbor` must declare CPU + memory limits.
3. `disallow-privilege-escalation` (Enforce, cluster-wide minus `kube-system`, `kyverno`, `cert-manager`, `falco`) — belt-and-suspenders over PSA `restricted`.
4. `require-harbor-labels` (Audit) — harbor-namespace Pods must carry `app.kubernetes.io/name` and `app.kubernetes.io/version`.

Single-replica install with `failurePolicy: Ignore` on the admission webhook — mandatory
for a single-node cluster to avoid a Kyverno-crash → webhook-blocks-pods → Kyverno-can't-restart self-deadlock.

## Non-Goals

- No Rego / OPA Gatekeeper policies — Kyverno YAML only.
- No image-signing (`verifyImages`) in this change — that is T3.2 (depends on this).
- No multi-replica HA — single-node; scale to 3 replicas only when a second node is added.
- No changes to Go application code.
- No changes to existing network policies or PSA labels.
- No cluster-level runtime enforcement beyond admission (Falco handles runtime — T3.3).

## Success Criteria

- [ ] Kyverno installs cleanly, single-replica, on the RKE2 single-node cluster.
- [ ] `disallow-latest-tag` rejects any Pod with `:latest` or no tag in `harbor`/`argocd`.
- [ ] `require-resource-limits` rejects any Pod missing CPU or memory limits in `harbor`.
- [ ] `disallow-privilege-escalation` rejects `allowPrivilegeEscalation: true` cluster-wide (except excluded namespaces).
- [ ] `require-harbor-labels` surfaces missing-label Pods in PolicyReports without blocking them.
- [ ] `kube-system`, `kyverno`, `falco`, and RKE2 static pods are unaffected.
- [ ] `go build ./... && go vet ./... && go test ./... && make agent-check` green (no Go changes).
