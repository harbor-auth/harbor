# Email-first signup

Agreed 2026-09-10. Scope: document, implement, verify, and update design/feature docs.

## Decisions

- Require a verified email for new public passkey signup. Flow: email + home region → email code → passkey → recovery codes → return destination.
- Keep the account UUID stable and independent of identifiers and credentials. Store typed, verified account identifiers; initially only email is accepted. Phone-number identifiers can be added later. Signing in on a phone does not itself require a phone-number identifier.
- Email is an account label and a destination available for email relay. It is never automatically disclosed to relying parties. Existing consent and relay semantics remain intact.
- Email verification authorizes new enrollment only, never sign-in, account linking, adding credentials to an existing account, or recovery. Duplicate email ownership is disclosed only after verification, then directs the person to sign in.
- Multiple passkeys may belong to an account. Use verified email for WebAuthn name/displayName, keeping an opaque user handle. There are no existing users: replace email-free public enrollment outright. Federated authentication remains separate.
- Identifiers are envelope encrypted under the account DEK. A purpose- and region-separated HMAC lookup supports uniqueness without storing plaintext email. Uniqueness is regional, consistent with Harbor's no-global-user-lookup architecture; no global email index is introduced.
- Email comparison trims surrounding whitespace and treats ASCII addresses case-insensitively; do not strip plus tags or dots. Unsupported/ambiguous mailbox syntax is rejected.
- Codes are browser-bound, single-use, expire after ten minutes, and allow at most five attempts. Redis coordinates attempts and consumption across replicas. Rate-limit requests by source and keyed destination; no addresses or codes in logs, API responses, or URLs.
- Persist the account and identifier atomically after verification. Allow expired, credential-free pending enrollments to be replaced, but never replace an account that acquired a credential.
- Verification mail uses a configured regional SMTP submission service. Missing configuration fails closed. No production verification bypass.
- Export includes identifiers. Erasure removes lookup material and crypto-shreds encrypted values with the account DEK.

## Tasks

- [x] Add typed identifier schema, atomic persistence, lookup, export/erasure support, and readable passkey labels.
- [x] Add distributed verification and mail delivery; require verified enrollment at the public API and wire production dependencies.
- [x] Update signup UI and API contract; preserve return destination and mandatory recovery.
- [x] Add abuse, replay, expiry, duplicate/concurrency, encryption, integration, and UI contract checks; run relevant checks and independent review.
- [x] Update design, feature, deployment, and test documentation with actual behavior and rollout requirements.

## Rollout

Apply additive migration before application rollout. Provision a stable random identifier lookup key and regional SMTP settings on every management replica. No backward compatibility or backfill is required (confirmed by user). Authenticated identifier enrollment/change and email-based recovery are separate future work.


## Completion and validation — 2026-09-10

Implemented the clean-cutover public flow, typed encrypted identifiers, verified
passkey labels, export/erasure, distributed verification, SMTP submission,
production wiring, API contract/codegen, UI, and deployment/test configuration.
No email-free public signup or compatibility backfill remains.

Validation:

- `go test ./...` passed.
- Race tests passed for signup, management API, identity, clients, and WebAuthn.
- Real PostgreSQL + Redis integration passed with the race detector, including
  concurrent duplicate enrollment, expired pending accounts with credentials,
  activation racing cleanup, export/erasure, and migration rollback.
- SMTP tests passed for actual TLS delivery, rejection of untrusted/plaintext
  servers, and a stalled-server deadline.
- OpenAPI lint, generated artifacts, Helm rendering/security contracts, and doc
  references/links passed.
- The complete `tools/agentcheck` suite passed on a clean snapshot of the change.
  The original working checkout has a preexisting ignored
  `.local/security-signoff/rotation_probe.go` formatting issue; it was preserved.
- Browser preview confirmed email entry and transition to code entry. The
  browser disconnected before the invalid-code screen could be inspected.
  The full Docker-compose e2e stack was not run; its helpers compile and now
  verify using delivered Mailpit codes, with retries only for explicit 429s.
- Independent review found no remaining high/medium issues. Deployment SMTP
  egress, Linkerd handling, delivery deadlines, and cleanup race coverage were
  addressed during review. GraphQL/Rails-specific pattern rules do not apply
  to this Go/template implementation.

Deployment remains an operational step: provision the regional SMTP sender and
credentials, stable identifier lookup key, and SMTP egress CIDRs, then apply the
migration and roll out the application. No production deployment was performed.
