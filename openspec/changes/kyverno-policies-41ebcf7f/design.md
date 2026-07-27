# Design: Kyverno policy-as-code (T2.4 infra hardening)

## Key Decisions

### Decision 1: Single-replica, fail-open webhook on single-node
**Chosen:** `admissionController.replicas: 1`; `failurePolicy: Ignore` on all Kyverno admission webhooks.
**Rationale:** On a single-node cluster, if Kyverno crashes and the webhook has
`failurePolicy: Fail`, the Kubernetes API server blocks every pod admission call (including
Kyverno's own restart pod) — permanent self-deadlock until the webhook is manually deleted
via SSH. `failurePolicy: Ignore` means enforcement degrades gracefully: during a Kyverno
outage, unchecked pods can be admitted, but the cluster keeps running. This is the correct
trade-off for a single-node cluster where control-plane availability matters more than
momentary enforcement gaps. Revisit `Fail` + 3 replicas when a second node is added.
**Alternatives considered:** `failurePolicy: Fail` (rejected — self-deadlock on single-node); 
3 replicas (rejected — wastes memory, meaningless HA on one node).

### Decision 2: Audit-first rollout, then Enforce
**Chosen:** All four policies ship as `validationFailureAction: Audit` initially;
`background: true` so existing non-compliant resources surface in PolicyReports. The three
Enforce policies are flipped to `Enforce` in a second commit once PolicyReports are clean for
Harbor-owned workloads.
**Rationale:** Third-party charts (Bitnami PostgreSQL, Redis) may not carry Harbor's required
labels or fit within the initial resource-limit thresholds. Switching directly to `Enforce`
would block them without warning. Audit-first gives a zero-disruption window to discover and
fix violations; `background: true` extends scanning to already-running pods.
**Alternatives considered:** Ship directly in Enforce (rejected — risk of blocking third-party
chart pods on first sync); Audit-only forever (rejected — the point of Kyverno is enforcement).

### Decision 3: falco namespace excluded from disallow-privilege-escalation
**Chosen:** The `falco` namespace is listed in the explicit `exclude` block of
`disallow-privilege-escalation`, alongside `kube-system`, `kyverno`, and `cert-manager`.
**Rationale:** Falco (T3.3) legitimately requires privileged containers to access kernel
syscall data via eBPF. Adding it to `harbor` PSA restricted would break it. The exclusion
is shipped from day one — even if Falco is not yet installed — so the policy never needs
retroactive patching when Falco lands.
**Alternatives considered:** Add `falco` exclusion later (rejected — would require patching a
live Enforce policy, risking an admission gap or outage window during the patch).

### Decision 4: Autogen enabled for all four policies
**Chosen:** Kyverno's default `autogen` is left enabled so rules authored against `Pod`
resources are automatically extended to cover `Deployment`, `StatefulSet`, `DaemonSet`,
`Job`, and `CronJob` controller specs.
**Rationale:** Harbor workloads are Deployments, not bare Pods. Without autogen, the policy
would pass on the Deployment admission call and only fail (confusingly) when the Deployment
controller creates the Pod. Autogen ensures rejection happens at the correct resource boundary.
**Alternatives considered:** Write separate rules per controller kind (rejected — verbose,
drift-prone, exactly what autogen exists to prevent).

### Decision 5: require-harbor-labels stays Audit permanently (for now)
**Chosen:** `require-harbor-labels` is `Audit` in the delivered artifacts and carries no
planned Enforce flip.
**Rationale:** Third-party charts in the `harbor` namespace (PostgreSQL, Redis) do not carry
`app.kubernetes.io/name`/`…/version` labels by default. An Enforce flip would block those
charts from upgrading. The value is visibility (for observability and policy-report tooling),
not admission rejection. A future Enforce flip requires either custom chart overrides for each
third-party workload or a `PolicyException` CR, and is deliberately deferred.
**Alternatives considered:** Enforce immediately (rejected — blocks third-party chart upgrades);
skip the policy entirely (rejected — the label contract is relied upon by observability tooling).

## Policy matrix summary

| Policy | Mode | Namespaces | Autogen | Background |
|---|---|---|---|---|
| `disallow-latest-tag` | Enforce | `harbor`, `argocd` | ✅ | ✅ |
| `require-resource-limits` | Enforce | `harbor` | ✅ | ✅ |
| `disallow-privilege-escalation` | Enforce | cluster-wide (excl. `kube-system`, `kyverno`, `cert-manager`, `falco`) | ✅ | ✅ |
| `require-harbor-labels` | Audit | `harbor` | ✅ | ✅ |

## No Go interface changes

This feature adds no Go code. It adds Kubernetes YAML under `deploy/kyverno/`. The only
repository-wide change is that Harbor chart manifests (Deployments, etc.) must comply with
the Enforce policies — any manifest that would be rejected needs to be fixed in the same PR.
