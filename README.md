# Harbor

> [!WARNING]
> **The live deployment is not production ready.** It works end to end, but it
> is carrying deliberate shortcuts — including an over-scoped registry
> credential, an OpenBao instance whose five unseal shares all sit on one
> machine, and no offsite backups. See
> [docs/NOT-PRODUCTION-READY.md](docs/NOT-PRODUCTION-READY.md) before pointing
> anything at it that you would be sorry to lose.

**Privacy-first, ethical Single Sign-On.** A tracking-free replacement for "Sign in with Google/Facebook".

Harbor is an OpenID Provider (OP) that authenticates people to the apps they've explicitly connected — and **nothing more**. No tracking, no profiling, no data selling. We're a neutral identity + auth broker that manages your passkeys, MFA, and logins.

## Principles

- **Verifiable privacy.** We technically constrain *ourselves* from tracking users. Pairwise pseudonymous identifiers (PPID) mean relying parties can't correlate you across apps — and neither can we.
- **Data sovereignty.** Each user lives in exactly one jurisdiction. Their data never leaves that region. Region is encoded in identifiers so requests route at the edge with no global lookup.
- **Extreme performance, low cost.** The sign-in / token-verification hot path is stateless and edge-cacheable (asymmetric JWTs verified via JWKS, no DB hit), so we can serve millions of verifications per second cheaply.
- **Standards-first, contract-first, codegen-everywhere.** We never invent what an open standard already solves, every interface (external *and* internal) is defined by a versioned machine-readable contract, and anything derivable from a spec is generated — not hand-maintained.

## Tech at a glance

| Layer | Choice |
|---|---|
| Core backend | **Go** (modular monolith; `zitadel/oidc`, `go-webauthn`, `pgx` + `sqlc`) |
| Auth factors | **Passkeys (WebAuthn)** primary; TOTP + recovery codes secondary |
| Protocols | **OIDC / OAuth 2.1 + PKCE**; SAML deferred |
| Data | **Postgres + Redis** per region; envelope encryption via regional KMS/HSM |
| Frontend | **Next.js (React) + TypeScript** dashboard & auth UI (typed API client generated from OpenAPI) |
| Contracts | **OpenAPI 3.1** (REST) · **Protobuf/gRPC** (internal) · **SQL + `sqlc`** (data) — spec-first, codegen-verified in CI |
| Deploy | **Kubernetes**, multi-jurisdiction, anycast/GeoDNS edge |

## Status

🚧 **Foundation / scaffolding.** The design is set and the codegen-first foundation is landing: spec-first API contracts (`api/openapi`, `api/proto`), the Go modular-monolith skeleton (`harbor-hot` / `harbor-mgmt` serving spec-generated OIDC discovery + health), the Postgres schema + migrations, PPID derivation (with a golden regression vector), and the `make generate` / `validate` / `test` toolchain wiring the `.agents/` skills. No production auth flows (`/authorize`, `/token`, passkeys) yet.

## Getting started

### Prerequisites

Harbor pins its entire toolchain (Go 1.26, `sqlc`, `oapi-codegen`, `buf`,
`golangci-lint`, `go-migrate`, `k6`, Node/`pnpm`) with Nix so
local and CI runs are byte-identical. Enter the hermetic dev shell:

```bash
nix develop            # drops you into the pinned toolchain shell
```

Without Nix you need Go 1.26+ and Docker (for the e2e / conformance gates); the
`make` targets **fail closed** with an install hint when a required tool is
missing. Run `make help` to list every target.

### Build

```bash
make build             # compile ./... and build harbor-hot + harbor-mgmt into ./bin
make build-static      # static CGO-off linux/amd64 binaries for tiny images
```

### Test

```bash
make test              # unit tests
make test-race         # unit tests with the race detector
make test-cover        # unit tests with coverage
make test-integration  # integration tests (real Postgres/Redis; -tags=integration)
```

### Run

Harbor is a modular monolith split into two binaries (see
[docs/DESIGN.md](docs/DESIGN.md) §4.1).

Both binaries deliberately use the production object graph in local
development. Start PostgreSQL, Redis, the migration/RP seed jobs, local KMS,
and both services with:

```bash
docker compose -f e2e/docker-compose.yml up -d --wait
```

The compose stack applies every migration and idempotently registers the
`harbor-e2e` public RP with `http://localhost:3000/callback`. It does not enable
a development mode or install an auto-approved demo user. `harbor-hot` is at
`http://localhost:8080`; `harbor-mgmt` and the passkey login UI are at
`http://localhost:8081`.

Run the live end-to-end suite against that graph:

```bash
HARBOR_E2E_BASE_URL=http://localhost:8080 \
HARBOR_MGMT_E2E_BASE_URL=http://localhost:8081 \
HARBOR_E2E_DATABASE_URL='postgres://harbor:harbor@localhost:5432/harbor?sslmode=disable' \
  go test -tags e2e ./e2e/...
```

Stop the stack and remove its local database/Redis state with:

```bash
docker compose -f e2e/docker-compose.yml down -v
```

To run either binary outside compose, provide the same required configuration:
`DATABASE_URL`, `REDIS_URL`, `REGION`, the shared `HARBOR_KMS_SECRET`, and the
component-specific URLs, WebAuthn, registration, admin, and signing-KMS values
shown in [`e2e/docker-compose.yml`](e2e/docker-compose.yml). Missing durable or
security-critical dependencies are startup errors; there is no dev/noop boot
path.

### Codegen & validation

Everything derivable from the `api/` contracts is generated, never
hand-maintained (spec-first, zero drift):

```bash
make generate          # regenerate Go/TS from api/openapi + api/proto + sqlc
make validate          # fmt, vet, lint, spec-lint, codegen-drift (fast inner loop)
make agent-check       # ALL checks -> check-results.json (the one trusted verdict, F6)
```

### Database migrations

```bash
make migrate        DATABASE_URL=postgres://…   # apply all pending migrations
make migrate-status DATABASE_URL=postgres://…   # show the current version
make migrate-down   DATABASE_URL=postgres://…   # roll back the last migration
```

### Conformance (release gate)

`make conformance` first runs the fast in-repo e2e OIDC smoke harness
(`e2e/docker-compose.yml` + `go test -tags=e2e ./e2e/...`), then the full OpenID
Foundation OP certification suite and the WebAuthn gate (requires Docker):

```bash
make conformance       # e2e smoke -> OIDF OP plan -> assert -> WebAuthn gate
```

The OIDF OP suite is intentionally **honest red** until harbor-hot reaches real
OIDC compliance (asymmetric-signed tokens, pairwise subjects) — details in
[conformance/README.md](conformance/README.md).

## KMS Credentials — Bootstrap, Rotation, and Rollback

Harbor's AWS KMS signing key credentials are managed by the [External Secrets Operator](https://external-secrets.io/) (ESO). The IAM access key used by `harbor-hot` to call AWS KMS is stored in AWS SSM Parameter Store and synced into the cluster automatically, eliminating static long-lived credentials.

See [`docs/plans/kms-credentials-rotation.md`](docs/plans/kms-credentials-rotation.md) for the full architecture and rationale.

### IAM setup (one-time, performed by ops)

Two IAM users are required:

**1. ESO bootstrap user** (`harbor-eso-bootstrap`) — reads SSM only:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["ssm:GetParameter"],
    "Resource": "arn:aws:ssm:us-east-1:*:parameter/harbor/*"
  }]
}
```

**2. KMS workload user** (`harbor-kms`) — calls KMS only:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:GenerateDataKey",
      "kms:DescribeKey"
    ],
    "Resource": "arn:aws:kms:us-east-1:<ACCOUNT_ID>:key/<HARBOR_KEK_ARN>"
  }]
}
```

### Bootstrap procedure (one-time)

**Step 1:** Create access keys for both IAM users. Store the KMS workload key in SSM:

```bash
# Store the KMS workload credentials in SSM (rotated here going forward).
aws ssm put-parameter --name /harbor/kms/aws-access-key-id \
  --value "<HARBOR_KMS_ACCESS_KEY_ID>" --type SecureString --overwrite
aws ssm put-parameter --name /harbor/kms/aws-secret-access-key \
  --value "<HARBOR_KMS_SECRET_ACCESS_KEY>" --type SecureString --overwrite
```

**Step 2:** Provision the ESO bootstrap credential as a Sealed Secret (never commit plaintext):

```bash
# Install kubeseal if not already present.
# Create the bootstrap Secret in the external-secrets namespace.
kubectl create secret generic eso-ssm-credentials \
  -n external-secrets \
  --from-literal=access-key-id="<ESO_BOOTSTRAP_ACCESS_KEY_ID>" \
  --from-literal=secret-access-key="<ESO_BOOTSTRAP_SECRET_ACCESS_KEY>" \
  --dry-run=client -o yaml \
  | kubeseal --controller-namespace kube-system -o yaml \
  > deploy/eso/sealed-eso-ssm-credentials.yaml

# Apply the Sealed Secret to the cluster.
kubectl apply -f deploy/eso/sealed-eso-ssm-credentials.yaml
```

**Step 3:** Install ESO via Helm:

```bash
helm repo add external-secrets https://charts.external-secrets.io
helm repo update
helm install external-secrets external-secrets/external-secrets \
  -n external-secrets --create-namespace \
  --version 0.10.7 \
  -f deploy/eso/values-eso.yaml
```

**Step 4:** Apply the ESO CRs (ClusterSecretStore + ExternalSecret):

```bash
kubectl apply -k deploy/eso/
```

**Step 5:** Verify sync (may take up to 60 seconds):

```bash
kubectl get clustersecretstore harbor-ssm
kubectl get externalsecret -n harbor harbor-kms-credentials
# STATUS column should show: SecretSynced
kubectl get secret -n harbor harbor-kms-credentials
# Should exist with keys AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY.
```

**Step 6:** Restart harbor-hot to pick up the new credentials:

```bash
kubectl rollout restart deployment/harbor-hot -n harbor
kubectl rollout status deployment/harbor-hot -n harbor
```

### Rotation procedure

When the ops team rotates the KMS IAM user access key:

1. **Create key 2** in AWS IAM for `harbor-kms` (leave key 1 active — two concurrent keys allowed).

2. **Update SSM** with the new credentials:
   ```bash
   aws ssm put-parameter --name /harbor/kms/aws-access-key-id \
     --value "<NEW_ACCESS_KEY_ID>" --type SecureString --overwrite
   aws ssm put-parameter --name /harbor/kms/aws-secret-access-key \
     --value "<NEW_SECRET_ACCESS_KEY>" --type SecureString --overwrite
   ```

3. **Wait ≤ 1 hour** for ESO to re-fetch from SSM (or trigger immediately: `kubectl annotate externalsecret harbor-kms-credentials -n harbor force-sync="$(date +%s)" --overwrite`).

4. **Verify** the Secret was updated: check `kubectl get secret harbor-kms-credentials -n harbor -o jsonpath='{.metadata.annotations.reconcile\.external-secrets\.io/data-hash}'` changed.

5. **Restart harbor-hot** to load the new env vars:
   ```bash
   kubectl rollout restart deployment/harbor-hot -n harbor
   kubectl rollout status deployment/harbor-hot -n harbor
   ```

6. **Verify KMS calls succeed** via CloudTrail — confirm calls are attributed to key 2.

7. **Deactivate key 1** in AWS IAM. Zero-downtime by construction (key 1 was active until step 6 completed).

> **Tip:** Install [Stakater Reloader](https://github.com/stakater/Reloader) and add `reloader.stakater.com/auto: "true"` to the `harbor-hot` Deployment to automate step 5 — pods restart automatically when the Secret changes.

### Rollback / break-glass

If ESO is unavailable or `harbor-kms-credentials` is missing:

- **`deletionPolicy: Retain`** means the last-synced Secret persists even if the ExternalSecret is deleted or ESO crashes. `harbor-hot` keeps running as long as the Secret exists.

- **Manual break-glass** (create the Secret by hand if needed):
  ```bash
  kubectl create secret generic harbor-kms-credentials -n harbor \
    --from-literal=AWS_ACCESS_KEY_ID="<ACCESS_KEY_ID>" \
    --from-literal=AWS_SECRET_ACCESS_KEY="<SECRET_ACCESS_KEY>"
  kubectl rollout restart deployment/harbor-hot -n harbor
  ```

- **Disable ESO integration** temporarily: set `hot.secrets.kmsCredentialsSecret: ""` in `deploy/argocd/values-prod.yaml` and sync — the `secretRef` block is omitted entirely and harbor-hot falls back to other credential sources (IAM instance profile, etc.).

## Documentation

- **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** — a one-page, high-level map (hot/cold path, regions, KMS) — start here.
- **[docs/DESIGN.md](docs/DESIGN.md)** — full system design: trust model, protocols, multi-jurisdiction routing, performance engineering, security, data model, user flows, compliance, roadmap, and key trade-offs.
- **[docs/README.md](docs/README.md)** — the feature/plan index (as-built capabilities and future work).

## Roadmap (summary)

0. **MVP** — single region OIDC OP, passkey login, PPID, dashboard, GDPR self-serve.
1. **Performance** — split hot/cold paths, edge JWKS caching, load-test to millions/sec.
2. **Multi-jurisdiction** — second region, PII-free global control plane, edge routing.
3. **Trust & enterprise** — DPoP, social recovery, transparency log, third-party audit.
4. **Add-ons** — privacy-preserving age proof (verifiable credentials).

See [docs/DESIGN.md §14](docs/DESIGN.md) for details, and [§1](docs/DESIGN.md) for the engineering principles (standards/contract/codegen-first).

## License

Harbor is a **multi-license monorepo** managed under the
[REUSE specification](https://reuse.software): the full text of every license
lives in [`LICENSES/`](LICENSES/), and the authoritative, machine-readable map is
[`REUSE.toml`](REUSE.toml) (verify with `reuse lint`).

Unless a file or subtree declares otherwise, everything is **AGPL-3.0-only**.
Per-subtree overrides:

| Path | License | Why |
|---|---|---|
| *(default)* | **AGPL-3.0-only** | Core server & identity code — network copyleft. |
| `api/` | **Apache-2.0** | Public OpenAPI / Protobuf contracts — permissive for broad client/SDK generation. |
| `docs/` | **CC-BY-4.0** | Documentation & prose — reusable with attribution. |
| `.agents/` | **MIT** | Agent skills & workflow tooling — maximally reusable. |
| `tools/` | **MIT** | Developer tooling. |

Copyright © 2026 The Harbor Authors.

> **Proprietary components** (e.g. deployment & billing) are kept as separate,
> independently-licensed works — their own subtree with its own `LICENSE` + SPDX
> headers, or a separate private repo — so the AGPL boundary stays explicit and
> auditable.
