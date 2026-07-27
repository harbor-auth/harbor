# Spec: KMS credentials rotation via External Secrets Operator

Eliminates static AWS KMS credentials by deploying ESO to pull them from AWS SSM
Parameter Store into the `harbor-kms-credentials` Secret consumed by `harbor-hot`.
Defines the ClusterSecretStore configuration, ExternalSecret mapping, IAM privilege
boundaries, and the harbor-hot envFrom wiring.

## ADDED Requirements

### Requirement: REQ-001 ESO ClusterSecretStore backed by AWS SSM Parameter Store

The system SHALL deploy a `ClusterSecretStore` resource that authenticates with
AWS SSM Parameter Store using credentials from a Kubernetes Secret
(`eso-ssm-credentials`) provisioned via a Sealed Secret.

The `ClusterSecretStore` MUST reference an IAM user whose AWS credentials are
stored in the `eso-ssm-credentials` Secret. The IAM user MUST have
`ssm:GetParameter` on `/harbor/*` only and MUST NOT have any KMS rights.

#### Scenario: ClusterSecretStore references bootstrap Secret

**Given** an `eso-ssm-credentials` Secret exists in the `external-secrets` namespace
**When** the ESO controller initialises the ClusterSecretStore
**Then** it authenticates against AWS SSM using those credentials and reports `Ready: True`

#### Scenario: Bootstrap IAM user has no KMS rights

**Given** the ESO bootstrap IAM user policy
**When** that user attempts to call `kms:Sign` or `kms:GetPublicKey`
**Then** AWS IAM denies the request with `AccessDenied`

### Requirement: REQ-002 ExternalSecret maps SSM paths to harbor-kms-credentials

The system SHALL deploy an `ExternalSecret` that maps SSM Parameter Store paths
`/harbor/kms/aws-access-key-id` and `/harbor/kms/aws-secret-access-key` to keys
`AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` respectively in the
`harbor-kms-credentials` Secret in the `harbor` namespace.

The `ExternalSecret` MUST set `refreshInterval: 1h` so credential rotation in SSM
propagates in-cluster within one hour without a pod restart. The target Secret
MUST be named `harbor-kms-credentials` and MUST be in the `harbor` namespace.

#### Scenario: ExternalSecret syncs SSM values into harbor-kms-credentials

**Given** SSM parameters `/harbor/kms/aws-access-key-id` and `/harbor/kms/aws-secret-access-key` exist
**When** ESO reconciles the ExternalSecret
**Then** a Secret named `harbor-kms-credentials` in the `harbor` namespace contains
  the keys `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` with the SSM values

#### Scenario: Credential rotation propagates without pod restart

**Given** ops updates `/harbor/kms/aws-access-key-id` in SSM to a new value
**When** one hour elapses
**Then** the `harbor-kms-credentials` Secret in the `harbor` namespace contains
  the new value without any manual intervention or pod restart

### Requirement: REQ-003 harbor-hot Deployment consumes harbor-kms-credentials

The system SHALL configure the `harbor-hot` Deployment to receive
`AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` from the ESO-managed
`harbor-kms-credentials` Secret via a second `envFrom.secretRef`.

The Helm chart MUST gate the second `envFrom` on a `hot.kmsSecret.existingSecret`
value so the reference is opt-in and backward-compatible with deployments that do
not use ESO. The raw `deploy/k8s/deployment-hot.yaml` manifest MUST mirror this.

#### Scenario: harbor-hot pod receives KMS credentials from ESO-managed Secret

**Given** `harbor-kms-credentials` exists in the `harbor` namespace (ESO-synced)
**When** a `harbor-hot` Pod starts with `hot.kmsSecret.existingSecret: harbor-kms-credentials`
**Then** the process environment contains `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`
  sourced from `harbor-kms-credentials` and `/jwks.json` returns keys

#### Scenario: Deployment is backward-compatible when kmsSecret is unset

**Given** `hot.kmsSecret.existingSecret` is empty string
**When** the Helm chart renders the Deployment
**Then** no second `envFrom.secretRef` is emitted for KMS credentials

### Requirement: REQ-004 ESO operator sized for single-node cluster

The system SHALL configure the ESO Helm values with a single replica and resource
requests/limits appropriate for a single-node RKE2 cluster.

The `values-eso.yaml` MUST set `replicaCount: 1` (or equivalent) and MUST declare
CPU and memory `requests` and `limits` on the ESO controller container.

#### Scenario: ESO runs as a single replica

**Given** ESO is installed with `deploy/eso/values-eso.yaml`
**When** the ESO controller Deployment is reconciled
**Then** exactly one ESO controller Pod is running
