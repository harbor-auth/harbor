# Spec: Falco eBPF Runtime Threat Detection (T3.3)

Adds eBPF-based runtime syscall detection for the Harbor OIDC service via Falco
with the modern eBPF (CO-RE) driver. Defines the driver configuration, Harbor-scoped
custom rules, alert routing phases, and namespace isolation requirements.

## ADDED Requirements

### Requirement: REQ-001 Modern eBPF driver (CO-RE) with RKE2 containerd socket

The system SHALL deploy Falco with `driver.kind: modern_ebpf` (CO-RE). The kernel
module driver MUST NOT be used on this single-node cluster. The containerd socket
path SHALL be `/run/k3s/containerd/containerd.sock` (RKE2 path). Resource limits
SHALL be cpu: 500m, memory: 512Mi; requests SHALL be cpu: 100m, memory: 128Mi.

#### Scenario: Falco values select modern_ebpf driver

**Given** the Helm values file `deploy/falco/values-falco.yaml`
**When** `helm lint` and `helm template` are run against it
**Then** both commands exit 0 with `driver.kind: modern_ebpf` in the rendered config

#### Scenario: RKE2 containerd socket is configured

**Given** the Helm values file
**When** the containerd collector section is inspected
**Then** the socket path is `/run/k3s/containerd/containerd.sock` and docker/podman sockets are disabled

### Requirement: REQ-002 Kubernetes metadata collector enabled

The system SHALL enable `collectors.kubernetes: true` so that `k8s.ns.name` and
`k8s.pod.name` fields are available in all Falco alert output fields.

#### Scenario: k8s-metacollector is deployed

**Given** the Helm values with `collectors.kubernetes: true`
**When** `helm template` renders the chart
**Then** a k8s-metacollector ServiceAccount and deployment artifact are present in the output

### Requirement: REQ-003 JSON stdout output at notice+ priority

The system SHALL configure `falco.json_output: true`, `falco.priority: notice`, and
`falco.stdout_output.enabled: true`. The Falcosidekick integration SHALL be disabled
(phase 1 shadow mode).

#### Scenario: JSON output is enabled in the rendered config

**Given** the Helm values file
**When** `helm template` renders the falco ConfigMap
**Then** `json_output: true` and `priority: notice` appear in the rendered falco.yaml

#### Scenario: Falcosidekick is disabled in phase 1

**Given** the Helm values file
**When** the falcosidekick section is inspected
**Then** `falcosidekick.enabled` is `false`

### Requirement: REQ-004 Harbor Shell Spawned rule (CRITICAL)

The system SHALL define a Falco rule `Harbor Shell Spawned` scoped to
`k8s.ns.name = "harbor"` containers that fires when any shell binary
(`bash`, `sh`, `zsh`, etc.) is executed. Priority SHALL be CRITICAL. Tags SHALL
include `[harbor, T3.3]`.

#### Scenario: Shell execution in Harbor namespace triggers CRITICAL alert

**Given** a process exec event with `proc.name = "sh"` in a Harbor namespace container
**When** the Falco rule engine evaluates the event
**Then** the `Harbor Shell Spawned` rule fires at CRITICAL priority

### Requirement: REQ-005 Harbor Privileged Exec rule (CRITICAL)

The system SHALL define a Falco rule `Harbor Privileged Exec` that fires when an
interactive TTY (`proc.tty != 0`) is opened in a Harbor namespace container by
a non-Harbor process. Priority SHALL be CRITICAL.

#### Scenario: Interactive TTY in Harbor container triggers CRITICAL alert

**Given** a spawned process with a non-zero TTY in a Harbor namespace container
**When** the Falco rule engine evaluates the event
**Then** the `Harbor Privileged Exec` rule fires at CRITICAL priority

### Requirement: REQ-006 Harbor Unexpected Outbound rule (WARNING)

The system SHALL define a Falco rule `Harbor Unexpected Outbound` that fires when a
Harbor namespace container opens an outbound TCP/UDP connection to a port not in the
approved allowlist `{53, 443, 465, 587, 5432, 6379}`. Priority SHALL be WARNING.

#### Scenario: Outbound to unapproved port triggers WARNING

**Given** an outbound TCP connection from a Harbor namespace container to port 8080
**When** the Falco rule engine evaluates the event
**Then** the `Harbor Unexpected Outbound` rule fires at WARNING priority

#### Scenario: Outbound to Postgres port is not flagged

**Given** an outbound TCP connection from a Harbor namespace container to port 5432
**When** the Falco rule engine evaluates the event
**Then** the `Harbor Unexpected Outbound` rule does NOT fire

### Requirement: REQ-007 Harbor Sensitive File Read rule (WARNING)

The system SHALL define a Falco rule `Harbor Sensitive File Read` that fires when a
Harbor namespace container reads from the sensitive file list (`/etc/passwd`,
`/etc/shadow`, `/etc/sudoers`, `/etc/hosts`, `/etc/hostname`, `/proc/self/environ`,
SSH key files). Priority SHALL be WARNING.

#### Scenario: Read of /etc/shadow in Harbor container triggers WARNING

**Given** a file-open-for-read event with `fd.name = "/etc/shadow"` in a Harbor namespace container
**When** the Falco rule engine evaluates the event
**Then** the `Harbor Sensitive File Read` rule fires at WARNING priority

### Requirement: REQ-008 Harbor Secret Mount Access by Foreign Process rule (CRITICAL)

The system SHALL define a Falco rule `Harbor Secret Mount Access by Foreign Process`
that fires when any process other than `harbor-hot` or `harbor-mgmt` reads from
`/var/run/secrets/...` or `/etc/harbor-secrets/...` in a Harbor namespace container.
Priority SHALL be CRITICAL.

#### Scenario: Foreign process reads Kubernetes secret mount triggers CRITICAL

**Given** a file-open-for-read with `fd.name` prefixed `/var/run/secrets/` by `proc.name = "curl"` in Harbor namespace
**When** the Falco rule engine evaluates the event
**Then** the `Harbor Secret Mount Access by Foreign Process` rule fires at CRITICAL priority

#### Scenario: Harbor binary reading its secret mount is not flagged

**Given** a file-open-for-read with `fd.name` prefixed `/var/run/secrets/` by `proc.name = "harbor-hot"` in Harbor namespace
**When** the Falco rule engine evaluates the event
**Then** the `Harbor Secret Mount Access by Foreign Process` rule does NOT fire

### Requirement: REQ-009 Dedicated privileged falco namespace

The system SHALL create a dedicated `falco` Kubernetes Namespace with PSA labels
`pod-security.kubernetes.io/enforce: privileged`. The Falco DaemonSet MUST NOT
run in the `harbor` namespace.

#### Scenario: falco namespace has PSA privileged labels

**Given** the `deploy/falco/namespace.yaml` manifest
**When** `kubectl kustomize deploy/falco/` renders it
**Then** the Namespace has `pod-security.kubernetes.io/enforce: privileged` label

### Requirement: REQ-010 Rules are additive over default ruleset

The system SHALL load Harbor custom rules via the Helm chart's `customRules`
mechanism. The default Falco ruleset MUST NOT be forked or removed. Exceptions
SHALL be added as macro overrides in `harbor_rules.yaml` (committed + reviewed),
never by editing default rules in place.

#### Scenario: customRules section is present in Helm values

**Given** the Helm values file
**When** the `customRules` key is inspected
**Then** `customRules.harbor_rules.yaml` is populated with the Harbor rules content
