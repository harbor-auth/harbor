# Design: KMS credentials rotation via External Secrets Operator

## Key Decisions

### Decision 1: ESO over IRSA
**Chosen:** Deploy the External Secrets Operator (ESO) with an IAM-user bootstrap
Secret rather than IRSA (IAM Roles for Service Accounts).
**Rationale:** The cluster is OVH/RKE2 — there is no EKS pod-identity webhook, no
OIDC issuer endpoint registered with AWS, and no mechanism to vend STS tokens from
a service account. IRSA is EKS-specific. ESO with a static bootstrap IAM user is
the correct, portable mechanism for non-EKS clusters.
**Alternatives considered:** IRSA (unavailable — rejected); mounting credentials
directly into `harbor-hot-secrets` statically (status quo; no rotation — rejected);
HashiCorp Vault (additional infrastructure dependency not yet in this cluster —
deferred to T3.4).

### Decision 2: Sealed Secret for ESO bootstrap IAM credentials
**Chosen:** The bootstrap IAM user credentials are provisioned out-of-band via a
Sealed Secret (`eso-ssm-credentials`). The manifest is committed (ciphertext is
safe to commit); ops creates the Sealed Secret with kubeseal.
**Rationale:** Keeps the IAM credential lifecycle outside of Helm and GitOps
plaintext. The Sealed Secret is cluster-specific (sealed to the cluster's cert),
so it cannot be decrypted outside the target cluster.
**Alternatives considered:** Storing plaintext credentials in Helm values (leaks
to anyone who reads the repo — rejected); generating the Secret in CI (CI has
no access to the cluster cert required for sealing — deferred).

### Decision 3: Least-privilege IAM split
**Chosen:** Two IAM principals: (a) the ESO bootstrap IAM user with
`ssm:GetParameter` on `/harbor/*` only (no KMS rights); (b) the existing KMS
IAM role used by `harbor-hot` for actual signing operations.
**Rationale:** ESO's only job is to read SSM parameters. Granting it KMS rights
would let a compromised ESO controller sign arbitrary tokens — a privilege far
beyond its scope. The least-privilege split means a compromise of the ESO
bootstrap credential cannot directly affect signing.
**Alternatives considered:** Single IAM user with both SSM and KMS rights (excess
privilege — rejected).

### Decision 4: 1-hour refresh interval
**Chosen:** `refreshInterval: 1h` on the ExternalSecret.
**Rationale:** Ops rotates the SSM parameters, and the new credential lands
in-cluster within one hour with no manual restart. The tradeoff (1 h window where
the old credential is still live after rotation) is acceptable for a signing-key
credential — it is not a session secret. Polling more frequently would add ESO CPU
load with negligible security benefit for a daily/weekly rotation cadence.
**Alternatives considered:** 5m (excessive API calls for low-frequency ops
rotation — rejected); 24h (too long a stale window — rejected).

### Decision 5: harbor-kms-credentials as a separate Secret
**Chosen:** The ExternalSecret writes `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`
into a dedicated `harbor-kms-credentials` Secret, consumed by `harbor-hot` via a
second `envFrom.secretRef` rather than merging into `harbor-hot-secrets`.
**Rationale:** Keeps the ESO-managed lifecycle (KMS creds) cleanly separated from
the operator-managed lifecycle (DATABASE_URL, REDIS_URL, KEK_SECRET). RBAC can
scope each secret independently; ops can rotate the KMS credential without
touching the DB/Redis creds.
**Alternatives considered:** Merging all fields into `harbor-hot-secrets` via ESO
(couples two orthogonal secret lifecycles, complicates RBAC — rejected).
