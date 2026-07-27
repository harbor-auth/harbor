# Kyverno Policy-as-Code (T2.4)

Kyverno enforces cluster-level admission policies for Harbor — image tag discipline,
resource limits, privilege escalation prevention, and label conventions — without
requiring Rego knowledge. Policies are YAML, versioned in git, and deployed by ArgoCD.

**Plan file:** [`docs/plans/kyverno-policies.md`](../../docs/plans/kyverno-policies.md)  
**OpenSpec:** [`openspec/changes/kyverno-policies-41ebcf7f/`](../../openspec/changes/kyverno-policies-41ebcf7f/)

---

## Install order

> ⚠️ **Wave ordering is mandatory.** The ClusterPolicy CRDs are installed by the Kyverno
> Helm chart; policies cannot be applied until those CRDs are established.

### Step 1 — Install Kyverno (wave 0)

```bash
helm repo add kyverno https://kyverno.github.io/kyverno/
helm repo update
helm install kyverno kyverno/kyverno \
  -n kyverno --create-namespace \
  -f deploy/kyverno/values-kyverno.yaml
```

Wait for all Kyverno pods to be Ready:

```bash
kubectl rollout status deployment -n kyverno --timeout=120s
```

### Step 2 — Apply ClusterPolicies (wave 1)

```bash
kubectl apply -k deploy/kyverno/
```

Verify all four policies are established:

```bash
kubectl get clusterpolicy
# NAME                          ADMISSION   BACKGROUND   VALIDATE ACTION   READY   AGE
# disallow-latest-tag           true        true         Enforce           True    Xs
# disallow-privilege-escalation true        true         Enforce           True    Xs
# require-harbor-labels         true        true         Audit             True    Xs
# require-resource-limits       true        true         Enforce           True    Xs
```

### Step 3 — Check PolicyReports (Audit-first review)

All policies ship in `Audit` mode first. After applying:

```bash
kubectl get policyreport -A
```

Review violations for Harbor-owned workloads. Third-party chart violations (PostgreSQL,
Redis) on `require-harbor-labels` are expected — do not block on them.

### Step 4 — Flip Enforce policies to Enforce

Once PolicyReports are clean for Harbor-owned workloads, the three Enforce policies
are already in `Enforce` mode per the delivered manifests. If you changed them to
`Audit` for an initial review pass, flip them back:

```bash
kubectl patch clusterpolicy disallow-latest-tag \
  --type merge -p '{"spec":{"validationFailureAction":"Enforce"}}'
kubectl patch clusterpolicy require-resource-limits \
  --type merge -p '{"spec":{"validationFailureAction":"Enforce"}}'
kubectl patch clusterpolicy disallow-privilege-escalation \
  --type merge -p '{"spec":{"validationFailureAction":"Enforce"}}'
```

---

## Policy mode rationale

| Policy | Mode | Reason |
|---|---|---|
| `disallow-latest-tag` | **Enforce** | `:latest` is a non-reproducible footgun; there is no legitimate use for it on this cluster. |
| `require-resource-limits` | **Enforce** | Single-node: an unlimited pod can starve etcd and every Harbor workload. Mandatory. |
| `disallow-privilege-escalation` | **Enforce** | Belt-and-suspenders over PSA `restricted`; extends to namespaces PSA does not cover. |
| `require-harbor-labels` | **Audit** | Third-party charts (PostgreSQL, Redis) don't carry Harbor labels; blocking them would break upgrades. Visibility only. |

### Fail-open webhook (single-node safety)

All Kyverno webhooks use `failurePolicy: Ignore`. On a single-node cluster, if Kyverno
crashes with `Fail`, the API server blocks **all** pod admission — including Kyverno's own
restart pod — creating a permanent self-deadlock that requires manual webhook deletion via
SSH. Ignore means enforcement degrades gracefully during a Kyverno outage but the cluster
keeps running.

**Do not change `failurePolicy` to `Fail` on a single-node cluster.** Revisit if/when a
second node is added and `admissionController.replicas` is increased to 3.

---

## How to add exceptions (`PolicyException`)

Policy exceptions are PR-reviewed changes committed to this repository. Ad-hoc exceptions
via `kubectl apply` are not permitted — ArgoCD will overwrite them on the next sync.

**Process:**

1. Author a `PolicyException` resource and open a PR:

```yaml
apiVersion: kyverno.io/v2
kind: PolicyException
metadata:
  name: allow-redis-no-limits
  namespace: harbor
spec:
  exceptions:
    - policyName: require-resource-limits
      ruleNames:
        - require-limits
  match:
    any:
      - resources:
          kinds:
            - Pod
          namespaces:
            - harbor
          names:
            - harbor-redis-*
```

2. Get the PR reviewed and merged. ArgoCD picks up the exception on the next sync.
3. Add a comment in the exception YAML explaining why it is needed and when it can be removed.

**Never create exceptions directly on the cluster** — they will be reconciled away.

---

## Rollback

### Soft rollback (Audit mode)

Flip any Enforce policy to Audit to stop blocking admissions without uninstalling:

```bash
kubectl patch clusterpolicy disallow-latest-tag \
  --type merge -p '{"spec":{"validationFailureAction":"Audit"}}'
kubectl patch clusterpolicy require-resource-limits \
  --type merge -p '{"spec":{"validationFailureAction":"Audit"}}'
kubectl patch clusterpolicy disallow-privilege-escalation \
  --type merge -p '{"spec":{"validationFailureAction":"Audit"}}'
```

This stops all blocking. PolicyReports continue to accumulate. Reverse the flip when ready.

### Hard rollback (emergency webhook deletion)

If Kyverno itself is broken and its webhook is blocking admissions despite `Ignore` policy
(e.g. the webhook object was manually patched to `Fail`), delete the webhook:

```bash
kubectl delete mutatingwebhookconfiguration kyverno-resource-mutating-webhook-cfg
kubectl delete validatingwebhookconfiguration kyverno-resource-validating-webhook-cfg
```

This removes enforcement entirely. Kyverno will re-register its webhooks when it restarts.

### Full uninstall

```bash
kubectl delete -k deploy/kyverno/          # remove ClusterPolicies
helm uninstall kyverno -n kyverno          # remove Kyverno itself
kubectl delete namespace kyverno           # clean up namespace
```

Falco, ArgoCD, and all Harbor workloads are unaffected — Kyverno is never in any traffic
or data path, only in the admission path.

---

## Reading PolicyReports

```bash
# Summary across all namespaces
kubectl get policyreport -A

# Detailed violations in the harbor namespace
kubectl describe policyreport -n harbor

# All Enforce-severity violations cluster-wide (should be zero for Harbor workloads)
kubectl get clusterpolicyreport -o json | \
  jq '.items[].results[] | select(.result=="fail" and .policy!="require-harbor-labels")'
```

## Verifying dry-run (offline)

```bash
# Validate the policy YAMLs are schema-valid (requires kubeconform or kubectl with kyverno CRDs installed)
kubectl apply --dry-run=client -f deploy/kyverno/policies/

# Helm lint the values file (chart must be available locally)
helm lint kyverno/kyverno -f deploy/kyverno/values-kyverno.yaml
```
