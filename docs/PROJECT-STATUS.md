# Harbor project status

Reviewed 2026-10-21; production inspected and branches reconciled 2026-10-22. This review distinguishes
implemented code from release evidence. The production follow-up below was inspected read-only on 2026-10-22.

## Implementation evidence

| Area | Evidence in the current tree |
| --- | --- |
| OIDC, PKCE, signed tokens, refresh, introspection, revocation, logout | `internal/oidc/`, `internal/oidcapi/`, `cmd/harbor-hot/main.go` |
| Verified-email signup | [Email-first signup](features/email-first-signup.md), `internal/signup/` |
| Durable passkeys and discoverable login | `webauthn.NewDBStore` and `bff.DiscoverableUserResolver` in `cmd/harbor-mgmt/main.go` |
| MFA, recovery, audit, export/delete, consent and relay management | Services and dependencies wired in `cmd/harbor-mgmt/main.go`; handlers in `internal/mgmtapi/` |
| Browser dashboard | `internal/bff/dashboard.go`, `web/templates/` (Go templates; the Next.js design is not the current UI) |
| Cloud provisioning and enterprise SSO | `internal/cloudapi/`, `cmd/harbor-mgmt/cloudapi.go`, `cmd/harbor-mgmt/sso.go` |
| Persistent encrypted signing keys and external KMS | `buildSigningStackWithProvider` in `cmd/harbor-hot/main.go`; signing occurs locally after key loading, not inside a non-exportable HSM |

These are implementation findings, not claims that each complete production
journey has been exercised. Older July plan rows describe earlier states and
must not be used as the current backlog without checking the code.

## Verification and gaps

- `go test ./...` passed on 2026-10-21 using Go 1.26.0 on macOS arm64.
  Tagged integration/e2e tests and the full aggregate checks were not run.
- `check-results.json` records a July 31 run, not the current verdict.
- The available `conformance/out/results.json` records July 23, runner exit 1,
  and zero modules. No current passing certification result was established.
- Some e2e tests skip when prerequisites or flows are unavailable. Critical
  journeys need explicit pass evidence and a review of skipped cases.
- `internal/oidcapi/userinfo.go` returns the pairwise subject but leaves
  grant-backed relay email lookup unfinished.
- Introspection supports confidential-client Basic authentication; its admin
  Bearer path is explicitly unsupported in `internal/oidcapi/introspect.go`.
- PPIDs constrain correlation by relying parties. They do not alone establish
  that Harbor cannot correlate accounts across clients: durable grant records
  associate user IDs with client IDs. Provider-blindness claims need review.

## Operational evidence

[NOT-PRODUCTION-READY.md](NOT-PRODUCTION-READY.md) is an August deployment
snapshot. Its credential, unseal, backup, GitOps and availability findings need
fresh verification; this repository review did not establish their current state.

The September [OpenBao recovery investigation](plans/openbao-offline-recovery-investigation.md)
records successful offline decryption of real OVH ciphertext. It explicitly
leaves native OpenBao snapshot restore, recovery-endpoint compatibility, rotation,
and historical backup recovery unproven. Production configuration was not changed
by that investigation.

## Next milestone: verified single-region private beta

1. Exercise signup, email verification, passkey registration, recovery-code
   acknowledgement, consent and RP login as one complete journey. Verify
   recovery, logout, revocation and account deletion; unavailable critical
   flows must fail the release gate rather than skip.
2. Audit live routing/configuration, deployed image revisions and credentials.
   Demonstrate OpenBao restart and full offsite-backup restoration.
3. Produce fresh aggregate checks and OIDC certification artifacts for the
   intended release revision, retaining results and skipped-test details.
4. Reconcile historical plans and privacy/product claims with that evidence.

The immediate priority is proving the assembled deployment and its recovery
procedures. Do not infer release readiness from healthy endpoints or unit tests.

## Production follow-up — 2026-10-22

At the start of this review, the local checkout and production were different
lines of development. After
fetching `origin/main`, Argo reports revision
`1f600d41031d8841ec4881dad069c645e57fbdd5` (September 9), while this checkout's
HEAD is `b01fd37` (September 10). Neither contains the other's complete changes.
Production values declare application image source revision
`381f666ff0830a735f22e8d2f0a0365babe6c2a3`; later main commits update infrastructure.
Do not deploy this local branch over production without integrating the
production security changes first.

### Confirmed configuration gaps

- **Verified-email signup is not deployed.** The live `/signup` form contains
  no email field and posts only `{region}` to `/enroll`. The local verified-email
  change is absent from `origin/main`. Neither management ConfigMap nor its
  referenced Secret contains signup SMTP settings (key names inspected only).
- **The region picker advertises unsupported choices.** Live signup offers EU,
  US and APAC, while deployment region and external user-DEK/signing key maps
  configure EU only. The main-branch enrollment handler validates recognized
  region codes but does not enforce equality with this deployment's region.
  Non-EU enrollment was not submitted; its exact failure response remains
  unverified. The page's promise to store data in the selected region is not
  backed by a multi-region deployment inspected here.
- **Management API routes fall through to the hot service.** Live ingress routes
  `/login`, `/signup`, `/signin`, `/enroll`, `/webauthn`, `/recovery` and
  `/dashboard` to management; everything else goes to hot. Public GETs to
  `/mfa/factors`, `/audit-events`, `/consent-grants`, and `/relay-addresses`
  returned 404. The same GETs directly to the management Service with the public
  Host header returned 403 (`step-up MFA verification required`), confirming
  that management handles them while public ingress does not. `/compliance`, `/register`
  and `/byo-domains` are also absent from the ingress route list; intended
  public exposure and authentication must be reviewed before adding routes.

### Confirmed healthy or improved

- Discovery, `/signin`, `/signup` and `/healthz` responded successfully using
  curl with normal certificate verification. Python urllib received Cloudflare
  1010 responses, so those responses were not treated as application failures.
- Issuer, login URL, authorization-completion URL and WebAuthn RP origin all
  use `https://auth.harborauth.com`; the RP ID matches that hostname.
- Harbor hot/management, PostgreSQL, Redis and OpenBao pods are Ready. Argo's
  harbor, backup, platform and OpenBao applications report Synced/Healthy;
  Harbor auto-sync, pruning and self-healing are enabled.
- OpenBao 2.6.2 reports `sealed=false`, Raft storage and `ovhcloudkms` seal.
  Its live configuration uses the OVH US endpoint for auto-unseal. The older
  manual-unseal warning is superseded for this deployment. Regional custody
  requirements for that seal dependency still need explicit review.
- The local PostgreSQL backup CronJob is enabled, with last success
  `2026-10-22T02:00:05Z`. It was the only CronJob returned in namespace `harbor`.
  Offsite backup and restore were not demonstrated.

### Follow-up order

1. Reconcile local verified-email signup with production main's security work;
   configure its mail delivery and EU-only signup before releasing it.
2. Review intended management API exposure and correct ingress routing with
   tests against the rendered production configuration.
3. Exercise actual RP login, recovery, MFA and compliance journeys, then prove
   offsite recovery. Ready pods and Argo sync are insufficient release evidence.

No production resources were changed. No signup or account deletion was
submitted. A diagnostic invocation of the management binary with `--version`
was not a supported version query: it attempted startup, connected to existing
PostgreSQL/Redis, and exited because port 8081 was already occupied. No rollout
or restart was performed.

## Repository reconciliation — 2026-10-22

Branch `reconcile/signup-production-20261022` combines production main at
`1f600d4` with local branch `security/pre-oss-audit-fixes` at `b01fd37` and
preserves the local documentation and agent-tool edits in a separate worktree.
The original checkout remains untouched. The earlier divergence findings above
are historical context; this combined branch has both lines of code.

Resolved integration points:

- Renumbered account identifiers to migration `0023`, retaining main's signing
  rotation migration `0022` and regenerating SQL artifacts from both schemas.
- Kept OpenBao user-DEK provider selection and all production security,
  dependency, key-rotation, monitoring and signed-image release changes.
- Combined SMTP configuration/egress with OpenBao configuration/egress, keeping
  the legacy environment KEK conditional instead of restoring it in production.
- Preserved explicit consent in the BFF e2e flow while using delivered-email
  verification for new test accounts; added signup configuration to management
  startup integration tests and Helm CI fixtures.
- Routed authenticated user APIs (`/mfa`, `/audit-events`, `/consent-grants`,
  `/relay-addresses`, `/compliance`, `/byo-domains`) to management in Helm and raw
  ingress. Privileged admin and RP registration routes were not added.
- Kept the signup region picker and enrollment API bound to the deployed region.

This is a repository integration, not a production rollout. Existing production
image pins are retained. SMTP sender/egress and the stable identifier lookup key
must be provisioned before deploying the combined management binary. Production
remains on the previously inspected images until a reviewed release is applied.

### Reconciliation validation

- `nix develop -c make agent-check` passes after selecting SDK 12 on Darwin;
  the previous SDK 11 could not link Go's `SecTrustCopyCertificateChain` call.
  Native Go 1.26 aggregate checks also passed.
- Pinned `make generate` completed with no generated-code drift. Signup OpenAPI
  lint passed. Helm lint/default security contracts passed; a production-values
  render retained both OpenBao access and provider-scoped SMTP egress.
- Real PostgreSQL/Redis signup integration passed under the race detector,
  using external user-DEK envelopes with a fake KMS client. It exercises
  identifier persistence/labels, export, erasure, duplicate races and rollback.
- Management startup integration passed against the local SQL/Redis stack.
- Delivered Mailpit verification → passkey → explicit consent → signed token
  passed for independent accounts; nonce cleanup and refresh-session logout
  revocation passed. Required BFF tests now fail if their ceremony cannot finish.
- The broader single-replica e2e command completed successfully but skipped
  DB-backed cases because its host invocation had no e2e database URL, plus
  existing recovery/MFA and legacy-flow cases. These are not counted as proof
  of the skipped journeys. Cross-replica and full OIDF certification were not run.

The BFF harness now addresses management's login routes through
`HARBOR_MGMT_E2E_BASE_URL` and carries Secure cookies over local HTTP using the
existing test-only jar. This fixes the split-port compose 404/skip while leaving
production cookie behavior unchanged. The local compose resources are disposable.
