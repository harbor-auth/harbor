# kyverno-policies

Ship **Kyverno policy-as-code** (T2.4 infra hardening): four ClusterPolicies
enforced at Kubernetes admission time, versioned in git and deployed by ArgoCD.
Gives the cluster admission-time enforcement of Harbor-specific standards that
Pod Security Admission cannot express — image tag discipline, CPU/memory limits,
privilege escalation prevention, and label conventions.

**Four policies:**
- **`disallow-latest-tag`** (Enforce, `harbor`+`argocd`) — rejects any container
  using `:latest` or no tag; non-reproducible rollbacks and silent drift become
  impossible to deploy.
- **`require-resource-limits`** (Enforce, `harbor`) — rejects any container
  missing `resources.limits.cpu` or `resources.limits.memory`; a single runaway
  pod on the **single-node** cluster cannot starve etcd or the API server.
- **`disallow-privilege-escalation`** (Enforce, cluster-wide minus `kube-system`,
  `kyverno`, `cert-manager`, `falco`) — belt-and-suspenders over PSA `restricted`,
  extended to namespaces PSA does not label. `falco` excluded: it is a legitimate
  privileged workload.
- **`require-harbor-labels`** (Audit, `harbor`) — surfaces Pods missing
  `app.kubernetes.io/name` or `app.kubernetes.io/version` in PolicyReports without
  blocking them; third-party charts (PostgreSQL, Redis) may not comply yet.

**Install profile:** single-replica per controller, `failurePolicy: Ignore` on all
admission webhooks — mandatory for single-node to prevent Kyverno-crash →
webhook-blocks-all-pods self-deadlock. All policies ship in `Audit` first;
Enforce promotion happens once PolicyReports confirm Harbor-owned workloads comply.
This feature is the prerequisite for T3.2 (Cosign `verifyImages`).
