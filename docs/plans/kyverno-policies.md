---
title: Kyverno policy-as-code (T2.4 infra hardening)
status: draft
design_refs: [§4.4, §1.5, §A.8]
targets: [deploy/kyverno/]
promoted_to: null
openspec: changes/kyverno-policies
created: 2026-07-27
---

# Plan — Kyverno Policy-as-Code (`kyverno-policies`)

> **Status:** draft · **Tier:** T2.4 (infra-hardening) · **Target:** cluster-wide on
> `51.89.98.90` (RKE2, single-node, ArgoCD GitOps) · **Parent doc:** [`infra-hardening.md`](infra-hardening.md#t24--kyverno-policy-as-code)

## Problem

The cluster enforces Pod Security Admission `restricted` on the `harbor` namespace, but
PSA is a **fixed, coarse profile** — it cannot express Harbor-specific standards:

- Nothing stops a `:latest` image tag from being deployed (non-reproducible rollbacks,
  silent drift between "what's running" and "what git says").
- Nothing requires CPU/memory limits — one runaway pod on a **single-node** cluster
  starves etcd, the API server, and every Harbor workload simultaneously.
- No enforcement of labeling conventions (`app.kubernetes.io/name`, `…/version`), which
  the observability and audit tooling assume.
- PSA covers only the `harbor` namespace; `argocd`, future `linkerd`/`falco`/`kyverno`
  namespaces have no guardrails at all.
- Every guardrail today is *convention*, checked by humans at review time — nothing is
  enforced at admission, so a bad `kubectl apply` or a subtly wrong ArgoCD sync lands.

Kyverno gives declarative, YAML-native admission policies (no Rego), versioned in git and
deployed by ArgoCD like everything else. It is also the prerequisite for T3.2
(Cosign `verifyImages`).

## Proposed approach

### Deliverables (in-repo)

```
deploy/kyverno/
  values-kyverno.yaml                      # Helm values: single-replica, resource caps, webhook timeout
  policies/
    disallow-latest-tag.yaml               # Enforce
    require-resource-limits.yaml           # Enforce
    disallow-privilege-escalation.yaml     # Enforce (falco namespace excluded)
    require-harbor-labels.yaml             # Audit
  kustomization.yaml
  README.md                                # install, exception process, rollback
```

### Installation profile (single-node aware)

Helm chart `kyverno/kyverno`, pinned version, with:

- `admissionController.replicas: 1` (and single replicas for background/cleanup/reports
  controllers) — HA is meaningless on one node; 3 replicas would just triple memory.
- **Failure policy `Ignore` on the admission webhook initially** (chart default is
  fail-open for the resource webhook): on a single-node cluster a crashed Kyverno with
  `Fail` would block *all* pod admission, including Kyverno's own restart — a
  self-deadlock. Revisit `Fail` only with multi-replica on multi-node. This is the key
  availability-vs-enforcement decision; documented explicitly in README.
- Resource requests/limits set modestly (e.g. 128Mi/256Mi admission controller) —
  practicing what `require-resource-limits` preaches.
- Webhook timeout set to 10s (chart default 10s is fine; documented explicitly so it's
  a conscious choice, not an accidental default).
- `config.resourceFilters`: keep defaults excluding `kube-system`, and add exclusions
  for `kube-node-lease`, Kyverno's own namespace — never let policy block the
  control plane or RKE2 static pods.

### The four priority policies

| Policy | Mode | Scope | Rule |
|---|---|---|---|
| `disallow-latest-tag` | **Enforce** | `harbor`, `argocd` (namespace selector) | Deny Pods (via controller autogen for Deployments/Jobs/CronJobs) whose containers/initContainers use no tag or `:latest`. |
| `require-resource-limits` | **Enforce** | `harbor` | Every container must set `resources.limits.cpu` and `resources.limits.memory` and requests. |
| `disallow-privilege-escalation` | **Enforce** | cluster-wide minus `kube-system`, `kyverno`, `cert-manager`, **`falco`** | `allowPrivilegeEscalation` must be `false`; belt-and-suspenders over PSA `restricted`, extended to namespaces PSA doesn't label. `falco` excluded: it is a legitimate privileged workload. |
| `require-harbor-labels` | **Audit** | `harbor` | Pods must carry `app.kubernetes.io/name` + `app.kubernetes.io/version`. Audit-only: third-party charts (postgres, redis) may not comply; visibility without outage risk. |

Policy authoring conventions:
- `spec.validationFailureAction: Enforce` / `Audit` per table; **every Enforce policy
  ships with `background: true`** so existing non-compliant resources surface in
  PolicyReports before they block anything.
- Use Kyverno **autogen** (default) so rules written against Pods automatically cover
  Deployments/StatefulSets/DaemonSets/Jobs/CronJobs.
- Namespace scoping via `match.any[].resources.namespaces`, and explicit `exclude` for
  `kube-system`, `kyverno`, `cert-manager` where appropriate — the ingress controller
  and RKE2 components are not ours to break.
- Each policy carries `annotations: policies.kyverno.io/description` + severity for
  report tooling.

### Rollout order (no-surprises)

1. Install Kyverno; wait ready.
2. Apply **all four policies in `Audit`** first (one commit).
3. Review `kubectl get policyreport -A` — fix any Harbor-chart violations found.
4. Flip the three Enforce policies to `Enforce` (second commit) once reports are clean
   for Harbor-owned workloads.
5. ArgoCD app for `deploy/kyverno/` with sync-wave ordering: Kyverno install wave
   before policies wave (policies are CRs of Kyverno's CRDs).

## DESIGN alignment

This plan realises the **defence-in-depth** and **spec-first** principles of §1.5
and the cluster security boundary described in §4.4. It does not change any application
code or DESIGN.md — it adds admission-time enforcement of conventions that the design
already calls for (resource governance, image pinning, label contracts for observability
§6.5). It is also the prerequisite for T3.2 (Cosign `verifyImages`), which adds
cryptographic image provenance (§A.8 agentic guardrails analogue: same "verify before
execute" property, applied to the cluster layer).

This plan does **not** contradict DESIGN.md. It is purely additive infra hardening and
confirms the existing design rather than revising it.

## Target code paths

```
deploy/kyverno/
  values-kyverno.yaml
  policies/disallow-latest-tag.yaml
  policies/require-resource-limits.yaml
  policies/disallow-privilege-escalation.yaml
  policies/require-harbor-labels.yaml
  kustomization.yaml
  README.md
docs/plans/kyverno-policies.md              # this file
docs/README.md                              # Plans table row added
```

No Go code changes expected. Harbor chart manifests may need minor compliance fixes
(e.g. verify containers declare limits, images pin tags) discovered by the policies.

## Implementation checklist

- [ ] `deploy/kyverno/values-kyverno.yaml`: single-replica, fail-open webhook, 10s
  timeout, resource caps, resource filters excluding `kube-system` + `kyverno` +
  `kube-node-lease`.
- [ ] `deploy/kyverno/policies/disallow-latest-tag.yaml`: ClusterPolicy Enforce,
  namespace selector for `harbor` + `argocd`, autogen enabled, background true.
- [ ] `deploy/kyverno/policies/require-resource-limits.yaml`: ClusterPolicy Enforce,
  `harbor` namespace only, both CPU + memory limits required, background true.
- [ ] `deploy/kyverno/policies/disallow-privilege-escalation.yaml`: ClusterPolicy
  Enforce, cluster-wide with explicit `exclude` for `kube-system`, `kyverno`,
  `cert-manager`, `falco`; background true.
- [ ] `deploy/kyverno/policies/require-harbor-labels.yaml`: ClusterPolicy Audit,
  `harbor` namespace, `app.kubernetes.io/name` + `app.kubernetes.io/version` required.
- [ ] `deploy/kyverno/kustomization.yaml`: reference all policy files and values.
- [ ] `deploy/kyverno/README.md`: install order (Helm install kyverno → apply policies),
  policy mode rationale (Audit-first → Enforce), how to add exceptions
  (`PolicyException` CR, PR-reviewed only), rollback procedure (`validationFailureAction:
  Audit` flip, or emergency: `kubectl delete mutatingwebhookconfiguration kyverno-resource-mutating-webhook-cfg`).
- [ ] Verify Harbor chart manifests comply with the Enforce policies (image tags pinned,
  limits declared); fix violations in the same PR.
- [ ] `helm lint deploy/kyverno/` — clean.
- [ ] `kubectl apply --dry-run=client -f deploy/kyverno/policies/` — clean.
- [ ] Kyverno CLI offline tests: `kyverno apply deploy/kyverno/policies/ --resource
  <fixture>` — good/bad fixtures committed under `deploy/kyverno/tests/`; a `:latest`
  pod denied, a limit-less pod denied, `allowPrivilegeEscalation: true` denied, unlabeled
  pod produces Audit result. (If kyverno CLI not available in CI, document as manual
  gate.)
- [ ] Repo health: `go build ./... && go vet ./... && go test ./... && make agent-check`
  green (no Go changes expected; must stay green).
- [ ] Reconcile & promote: `@plan promote kyverno-policies` once all artifacts are merged.

## Risks & open questions

- **Single-node webhook deadlock:** if Kyverno crashes with `failurePolicy: Fail`, the
  webhook call from the API server blocks, no new pods can be scheduled including Kyverno
  itself — permanent self-deadlock until the webhook is manually deleted. **Mitigation:**
  `failurePolicy: Ignore` on all webhooks for single-node; revisit only if the cluster
  ever gains a second node and a second Kyverno replica. This is an explicit, documented
  decision — not a missing safeguard.
- **falco namespace privilege escalation carve-out:** Falco requires privileged
  containers; `disallow-privilege-escalation` must exclude the `falco` namespace from
  day one. If the Falco plan lands after this one, the exclusion must be added
  retroactively. The two plans must coordinate (tracked as a cross-plan dependency).
- **Third-party chart compliance (`require-harbor-labels`, `require-resource-limits`):**
  Helm charts for Bitnami PostgreSQL and Redis may not carry the required labels or
  declare limits within Harbor's thresholds. The Audit-first rollout surfaces these
  before any Enforce flip; fixing upstream chart values is the expected remediation.
- **Webhook timeout under load:** the default 10s webhook timeout means that if Kyverno
  is slow (e.g. high CPU from background scanning), admission calls may time out.
  With `Ignore` policy, they degrade silently — no enforcement for that window.
  Monitor Kyverno pod CPU; set reasonable resource limits (not caps so tight that
  background scans starve the admission path).
- **ArgoCD sync-wave ordering:** the kyverno policies are CRs against CRDs that the
  Kyverno Helm chart installs. If ArgoCD applies them before CRDs are Ready, the sync
  fails. The kustomization must use ArgoCD sync-wave annotations or a hook to ensure
  CRD readiness before policy application.
- **PSA + Kyverno admission on the same object:** PSA runs before admission webhooks.
  A `disallow-privilege-escalation` policy is belt-and-suspenders over PSA `restricted`
  — fine. But if a namespace has PSA `baseline`, Kyverno provides stronger enforcement.
  The scoping must be deliberate about which namespaces each policy targets.

## Definition of done

All five deliverable files exist under `deploy/kyverno/`; `helm lint` is clean; all
four ClusterPolicy YAMLs pass `kubectl apply --dry-run=client`; Harbor chart manifests
comply with the Enforce policies (no `:latest` tags, all containers have CPU + memory
limits); offline Kyverno CLI tests (or documented manual verification) confirm each
policy correctly admits compliant resources and rejects non-compliant ones; the README
documents install order, policy mode rationale, exception process, and rollback;
`go build ./... && go vet ./... && go test ./... && make agent-check` green; a row in
`docs/README.md` Plans table points to this file. Ready to `@plan promote`.
