# Falco Runtime Threat Detection — Harbor T3.3

eBPF-based runtime security for the Harbor OIDC service, using Falco with the
modern eBPF (CO-RE) driver and five custom Harbor detection rules.

**Status:** Phase 1 (stdout-only shadow mode). Wire Falcosidekick after triage.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Install Runbook](#install-runbook)
3. [Verification Smoke Tests](#verification-smoke-tests)
4. [Shadow-Then-Alert Tuning Loop](#shadow-then-alert-tuning-loop)
5. [Per-Rule Triage Notes](#per-rule-triage-notes)
6. [Adding Rule Exceptions](#adding-rule-exceptions)
7. [Upgrading](#upgrading)
8. [Rollback Instructions](#rollback-instructions)
9. [Reference](#reference)

---

## Prerequisites

- Kubernetes cluster with Linux 5.8+ nodes (required for modern eBPF / CO-RE)
- RKE2 (containerd socket at `/run/k3s/containerd/containerd.sock`)
- Helm 3.x (`helm version`)
- Kyverno: `disallow-privilege-escalation` ClusterPolicy must **exclude** the
  `falco` namespace (Falco DaemonSet pods are privileged — see below)
- Harbor namespace must exist: `kubectl get ns harbor`

### Kyverno Coordination

Before installing Falco, patch the `disallow-privilege-escalation` ClusterPolicy
to exclude the `falco` namespace:

```yaml
spec:
  rules:
    - name: disallow-privilege-escalation
      exclude:
        resources:
          namespaces: [falco]
```

Without this exclusion, the Falco DaemonSet pods will fail admission.

---

## Install Runbook

### Step 1 — Create the falco namespace with PSA labels

```bash
kubectl apply -k deploy/falco/
# Verify:
kubectl get ns falco --show-labels
# Expected: pod-security.kubernetes.io/enforce=privileged
```

### Step 2 — Add the Falcosecurity Helm repository

```bash
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update
```

### Step 3 — Validate before deploying

```bash
# Lint the chart with our values:
helm lint /path/to/falco-chart -f deploy/falco/values-falco.yaml

# Dry-run template render:
helm template falco falcosecurity/falco -n falco \
  -f deploy/falco/values-falco.yaml \
  | kubectl apply --dry-run=client -f -
```

### Step 4 — Install Falco

```bash
helm install falco falcosecurity/falco \
  -n falco \
  -f deploy/falco/values-falco.yaml
```

Key configuration choices made in `values-falco.yaml`:

| Setting | Value | Rationale |
|---|---|---|
| `driver.kind` | `modern_ebpf` | CO-RE: no DKMS, survives kernel upgrades |
| containerd socket | `/run/k3s/containerd/containerd.sock` | RKE2 path |
| CPU request / limit | 100m / 500m | Low baseline, capped for noisy-neighbour safety |
| Memory request / limit | 128Mi / 512Mi | Typical eBPF overhead |
| `collectors.kubernetes` | `true` | Enables `k8s.ns.name` / `k8s.pod.name` fields |
| `falco.json_output` | `true` | Structured logs, required for Falcosidekick |
| `falco.priority` | `notice` | Suppresses debug/info noise; all Harbor rules active |
| `falcosidekick.enabled` | `false` | Phase 1 stdout-only; enable in phase 2 |

### Step 5 — Verify the DaemonSet is running

```bash
kubectl -n falco get daemonset falco
kubectl -n falco get pods -l app.kubernetes.io/name=falco
# All pods should be Running (one per node).
```

---

## Verification Smoke Tests

### Check Falco is loading rules

```bash
kubectl -n falco logs -l app.kubernetes.io/name=falco --tail=50 \
  | grep -E '(harbor|rule|load)'
# Expected: lines like "Loading rules from..." with no parse errors.
```

### Confirm Harbor rules are active

```bash
kubectl -n falco logs -l app.kubernetes.io/name=falco --tail=200 \
  | grep -i harbor
# Expected: Falco startup message listing Harbor rules (if a rule fires) or
# no output (rules loaded silently until an event matches).
```

### Confirm JSON output

```bash
kubectl -n falco logs -l app.kubernetes.io/name=falco --tail=10 \
  | grep '^{' | head -3 | python3 -m json.tool
# Expected: valid JSON events (if any have fired).
```

### Capability check — confirm modern_ebpf driver loaded

```bash
kubectl -n falco logs -l app.kubernetes.io/name=falco --tail=100 \
  | grep -iE '(modern_ebpf|eBPF|driver)'
# Expected: "using modern BPF probe" or similar driver initialization message.
```

### Trigger a test event (non-production clusters only)

```bash
# Spawn a shell in any Harbor pod — this should fire "Harbor Shell Spawned".
# WARNING: do this in staging/dev only.
kubectl -n harbor exec -it deploy/harbor-hot -- /bin/sh 2>/dev/null || true

# Then watch for the alert:
kubectl -n falco logs -l app.kubernetes.io/name=falco -f \
  | grep "Shell spawned in Harbor"
```

### Confirm k8s metadata enrichment

```bash
kubectl -n falco logs -l app.kubernetes.io/name=falco --tail=50 \
  | grep -i metacollector
# Expected: k8s-metacollector started and connected.
kubectl -n falco get pods -l app.kubernetes.io/name=k8s-metacollector
# Expected: Running.
```

---

## Shadow-Then-Alert Tuning Loop

The rollout follows a **shadow-then-alert** procedure to avoid alert fatigue and
false-positive noise before rules are production-validated.

### Phase 1 — Shadow mode (stdout only)

Duration: ≥ 1 week of normal production traffic.

1. **Collect events** continuously:
   ```bash
   kubectl -n falco logs -l app.kubernetes.io/name=falco -f \
     | grep -v '^$' | tee /tmp/falco-events-$(date +%Y%m%d).jsonl
   ```

2. **Triage each unique rule/process combination** that fires:
   ```bash
   # Count events by rule:
   cat /tmp/falco-events-*.jsonl | python3 -c "
   import sys, json, collections
   rules = collections.Counter()
   for line in sys.stdin:
       try:
           e = json.loads(line)
           rules[e.get('rule', 'unknown')] += 1
       except: pass
   [print(f'{c:>6}  {r}') for r, c in rules.most_common()]
   "
   ```

3. **For each false positive**, add a scoped exception macro in
   `deploy/falco/rules/harbor_rules.yaml` (see [Adding Rule Exceptions](#adding-rule-exceptions)).
   Commit and review every exception — no ad-hoc silent suppression.

4. **Validate rules after each exception**:
   ```bash
   falco --validate deploy/falco/rules/harbor_rules.yaml
   ```

5. **Update the inline copy** in `values-falco.yaml` `customRules.harbor_rules.yaml`
   to match the standalone file (or use `--set-file` at install time; see
   comment in `values-falco.yaml`).

6. **Apply** the updated rules:
   ```bash
   helm upgrade falco falcosecurity/falco -n falco \
     -f deploy/falco/values-falco.yaml
   ```

### Phase 2 — Enable Falcosidekick alert routing

When false-positive rate is acceptable (target: < 1 actionable alert / day):

1. Fill in `deploy/falco/falcosidekick-values.yaml` (Slack webhook,
   Alertmanager host, PagerDuty key, etc.).
2. Set `falcosidekick.enabled: true` in `values-falco.yaml`.
3. Upgrade:
   ```bash
   helm upgrade falco falcosecurity/falco -n falco \
     -f deploy/falco/values-falco.yaml \
     -f deploy/falco/falcosidekick-values.yaml
   ```
4. Confirm alerts route to configured destinations with a test event.

---

## Per-Rule Triage Notes

### Rule 1 — Harbor Shell Spawned (CRITICAL)

**What it detects:** Any shell binary (`bash`, `sh`, `zsh`, etc.) executed
inside a Harbor namespace container.

**Why CRITICAL:** Harbor images run distroless Go binaries. Any shell execution
is strongly anomalous — RCE, supply-chain compromise, or hands-on intrusion.

**Expected false positives:**
- Init containers that run shell-based setup scripts (e.g., database migration
  init containers, secret injection sidecars).
- Debug containers attached with `kubectl debug`.

**Triage steps:**
1. Check `proc.pname` and `k8s.pod.name` in the event output.
2. If from an init container: add a scoped exception limited to that container
   image + process name combination.
3. If from `kubectl debug`: acceptable for break-glass; confirm the session was
   pre-approved. Consider a time-scoped exception.
4. If unexplained: treat as active incident — isolate the pod, capture logs.

**First response:** `kubectl describe pod <pod> -n harbor` + `kubectl logs`,
then cordon the node if compromise is suspected.

---

### Rule 2 — Harbor Privileged Exec (CRITICAL)

**What it detects:** Any process with a non-zero TTY (interactive session) in a
Harbor namespace container — i.e., `kubectl exec -it` or `kubectl attach`.

**Why CRITICAL:** Direct interactive access to a production pod is either a
break-glass event (pre-approved, time-boxed) or active intrusion.

**Expected false positives:**
- Legitimate operator break-glass sessions (pre-approved in change management).
- CI/CD pipelines that run health-check commands via `exec` (should use
  `livenessProbe`/`readinessProbe` instead — file a follow-on task to fix).

**Triage steps:**
1. Cross-reference with the Kubernetes API audit log to identify the actor
   (`kubectl get events -n harbor` or audit backend).
2. If legitimate break-glass: no exception needed — the event is the intended
   audit trail. Confirm the session was pre-approved.
3. If a CI/CD pipeline fires this: replace the exec with a proper probe and add
   a scoped exception for that CI service account while the fix is in flight.

---

### Rule 3 — Harbor Unexpected Outbound (WARNING)

**What it detects:** Outbound connections to any port not in
`{53, 443, 465, 587, 5432, 6379}` from a Harbor namespace container.

**Why WARNING:** Possible data exfiltration or C2 channel. Also catches
misconfigured dependencies trying to reach unexpected backends.

**Expected false positives:**
- A new dependency (database replica, caching layer, external API) added to
  Harbor without a corresponding NetworkPolicy + allowlist update.
- Ephemeral DNS resolver trying a non-standard port.

**Triage steps:**
1. Identify `fd.rip` (remote IP) and `fd.dport` in the event.
2. If a legitimate new egress target: add the port to `harbor_allowed_outbound_ports`
   in `harbor_rules.yaml` AND to the egress NetworkPolicy (both layers move
   together to maintain defence-in-depth).
3. Unexpected 443 connections: in phase 2, tighten to an IP/CIDR allowlist
   covering only known KMS and JWKS endpoints.

---

### Rule 4 — Harbor Sensitive File Read (WARNING)

**What it detects:** Reads of `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`,
`/etc/hosts`, `/etc/hostname`, `/proc/self/environ`, or SSH key files from
inside a Harbor namespace container.

**Why WARNING:** Classic post-exploit recon. These files serve no purpose to a
Go OIDC binary.

**Expected false positives:**
- libc/musl resolving UIDs via `/etc/passwd` on container startup (rare in
  distroless but possible in scratch-based images with static Go binaries).
- Container runtime reading `/etc/hostname` for the pod hostname.

**Triage steps:**
1. Check `proc.name` in the event — if it's `harbor-hot` or `harbor-mgmt`
   reading `/etc/hostname` at startup, add a narrow exception by `proc.name`
   + `fd.name`.
2. If `proc.name` is an unexpected binary: treat as active incident.

---

### Rule 5 — Harbor Secret Mount Access by Foreign Process (CRITICAL)

**What it detects:** Any process other than `harbor-hot` or `harbor-mgmt`
reading from `/var/run/secrets/...` (Kubernetes service account tokens) or
`/etc/harbor-secrets/...` (application secret mounts).

**Why CRITICAL:** Credential harvesting by an injected or compromised process
targeting signing material, database credentials, or service account tokens.

**Expected false positives:**
- A new legitimate Harbor binary added to the image (e.g., `harbor-watcher`)
  that is not yet in `harbor_allowed_binaries`.
- A sidecar injected by the service mesh (Linkerd) reading its own token.

**Triage steps:**
1. `proc.name` and `fd.name` reveal exactly what process read which secret.
2. If a new Harbor binary: add it to the `harbor_allowed_binaries` list in
   `harbor_rules.yaml` (with a PR review).
3. If a Linkerd/sidecar proxy: add the proxy binary as a scoped exception with
   a comment explaining the allowance.
4. If unexplained: **immediate response** — cordon the node, capture a forensic
   pod snapshot (`kubectl debug`), rotate the potentially compromised secret.

---

## Adding Rule Exceptions

Never edit the upstream Falco default rules. All exceptions are layered
additively in `deploy/falco/rules/harbor_rules.yaml` via macro overrides.

### Pattern — Narrow proc.name exception

```yaml
# Exception: harbor-init init container runs a shell to migrate the DB schema.
# Approved by: @security-team on 2026-07-27 (PR #84)
- macro: harbor_shell_exception_init
  condition: (proc.name = "sh" and proc.pname = "harbor-init")

- rule: Harbor Shell Spawned
  condition: and not harbor_shell_exception_init
  override:
    condition: append
```

### Pattern — New allowed binary

```yaml
- list: harbor_allowed_binaries
  items:
    - harbor-hot
    - harbor-mgmt
    - harbor-watcher    # added 2026-08-01 — new monitoring sidecar (PR #91)
```

### Validate after every change

```bash
falco --validate deploy/falco/rules/harbor_rules.yaml
```

Then update the inline copy in `values-falco.yaml` and upgrade Falco:

```bash
helm upgrade falco falcosecurity/falco -n falco \
  -f deploy/falco/values-falco.yaml
```

---

## Upgrading

```bash
helm repo update
helm upgrade falco falcosecurity/falco \
  -n falco \
  -f deploy/falco/values-falco.yaml

# Phase 2 (after Falcosidekick is wired):
helm upgrade falco falcosecurity/falco \
  -n falco \
  -f deploy/falco/values-falco.yaml \
  -f deploy/falco/falcosidekick-values.yaml
```

Always validate before upgrading:

```bash
helm lint /path/to/falco-chart -f deploy/falco/values-falco.yaml
helm template falco falcosecurity/falco -n falco \
  -f deploy/falco/values-falco.yaml | kubectl apply --dry-run=client -f -
```

---

## Rollback Instructions

### Quick rollback — revert to previous Helm release

```bash
# List release history:
helm history falco -n falco

# Roll back to the previous revision:
helm rollback falco -n falco

# Or to a specific revision:
helm rollback falco <REVISION> -n falco
```

### Full uninstall

```bash
helm uninstall falco -n falco

# Optionally remove the namespace (deletes all Falco resources):
kubectl delete ns falco
```

> **Note:** Uninstalling Falco stops all runtime detection immediately. Ensure
> an alternative detection mechanism is in place or that the uninstall is
> time-bounded.

### Rollback custom rules only

If a bad rule causes excessive CPU or false positives, revert the rules without
touching the Helm release:

```bash
git revert <commit-that-changed-harbor_rules.yaml>
git push
# Then apply the reverted rules via helm upgrade.
helm upgrade falco falcosecurity/falco -n falco \
  -f deploy/falco/values-falco.yaml
```

---

## Reference

- Feature plan: `docs/plans/falco-runtime-detection.md`
- Custom rules: `deploy/falco/rules/harbor_rules.yaml`
- Helm values: `deploy/falco/values-falco.yaml`
- Falcosidekick stub: `deploy/falco/falcosidekick-values.yaml`
- Kustomization: `deploy/falco/kustomization.yaml`
- Falco docs: <https://falco.org/docs/>
- Falcosecurity Helm chart: <https://github.com/falcosecurity/charts>
- MITRE ATT&CK techniques covered: T1059 (shell), T1609 (exec), T1048
  (exfiltration), T1083 (file discovery), T1552 (credential access)
