---
title: Email-first signup and account identifiers
status: implemented
design_refs: [§11.1, §10, §7.5, §9]
code: [internal/signup/, internal/identity/identifier.go, internal/clients/identifiers.go, internal/mgmtapi/enroll.go, web/templates/signup.html]
spec: [api/openapi/harbor-signup.yaml]
tests: [internal/signup/service_test.go, internal/signup/smtp_test.go, internal/mgmtapi/enroll_test.go, internal/mgmtapi/signup_integration_test.go]
plan: docs/plans/email-first-signup.md
last_reconciled: 2026-09-10
---

# Email-first signup

New public accounts require a verified email before registering a passkey. This is a clean cutover: there are no existing users and no legacy signup compatibility path. Corporate SSO remains separate.

## Flow

1. Open `/signup` on the home region's public origin. The production picker offers that deployment's region; the API rejects another region rather than storing its email in the wrong jurisdiction.
2. Enter email and submit `POST /enroll` with `{email, region}`. It sends an eight-digit code and returns `202 verification_required`. It does not create an account or authorize passkey registration.
3. Enter the code in the same browser. `POST /enroll/verify` requires `{code}` and the HttpOnly `harbor_signup_verification` cookie. Successful verification atomically creates the pending account and its identifier, then issues the enrollment cookie and returns `201`.
4. Create a passkey. Its user handle is the account UUID's bytes; its name and display name are the verified email. Credentials are attached to the account, not to an email-derived ID.
5. Save and acknowledge recovery codes. The existing recovery gate remains mandatory, then the validated return destination is honored.

The email verification request and code are never login or recovery credentials for an existing account. After proving email ownership, a duplicate signup receives `409 account_exists` with guidance to sign in using the existing passkey. It receives no enrollment session. Unverified requests receive the same response whether or not an account exists.

A pending account with no credential can be replaced after 20 minutes, beyond the initial enrollment and WebAuthn ceremony windows. Active accounts and accounts with credentials are never replaced by this cleanup. Verification is consumed before account creation; a dependency failure afterward requires restarting signup. If an account was committed but the enrollment handoff failed, it becomes eligible for the same pending-account cleanup.

## Account identity and privacy

`users.id` remains the account's stable identity. `account_identifiers` stores typed identifiers independently of passkeys. Only `email` is currently accepted; verified phone numbers can be introduced later without changing account IDs or credential ownership. Identifier changes/linking need their own authenticated workflow and are not implemented here.

Addresses are trimmed and ASCII case-folded. Display names, quoted local parts, non-ASCII addresses, and ambiguous mailbox syntax are rejected. Plus tags and dots are preserved; Harbor does not guess provider-specific aliases. Email ownership does not establish one unique human.

The normalized value is encrypted under the account DEK with account-and-kind-bound authenticated data. A separate HMAC lookup, domain-separated by purpose, region and kind, enforces regional uniqueness. There is no global email directory or cross-region deduplication. The lookup key must remain stable; rotation requires reindexing while addresses are decryptable.

Identifiers are included in account export. The normal `EraseUserDEK` status transition deletes identifier rows through a database trigger, removing the lookup and releasing the email while the account DEK is destroyed.

The verified address is available as the account's email-relay destination. This change does not provision relay addresses or add real email to OIDC claims; consent/relay provisioning remains a separate surface. Apps are not automatically given the signup email.

## Verification controls

- Random 256-bit browser secret; eight-digit random code, ten-minute expiry, five attempts.
- Redis Lua atomically counts failures and consumes successes across management replicas.
- Verification payload (email, region, return destination) is purpose-wrapped using the regional key provider. Redis stores a keyed proof of the code, not its plaintext.
- Five send requests per keyed destination per hour, plus the existing distributed source limit on both endpoints. Dependency failures fail closed.
- Strict JSON, bounded bodies, same-origin browser protections, `Cache-Control: no-store`, Secure/HttpOnly/SameSite=Strict cookies. Neither email nor codes appear in URLs or response bodies.
- Mandatory STARTTLS with certificate verification. Optional SMTP AUTH credentials must be configured together. The entire mail operation has an eight-second deadline, below the HTTP write timeout.

## Verification and operation

Unit tests cover code replay, expiry, attempt exhaustion, browser binding, concurrent consumption, encryption, normalization, source/destination limits, and failed handoffs. The tagged PostgreSQL/Redis integration test applies the real migrations and covers HTTP enrollment, label loading, export, erasure, duplicate races, rollback, and expired pending cleanup.

```sh
go test ./...
go test -race ./internal/signup ./internal/mgmtapi ./internal/identity ./internal/clients ./internal/webauthn
# Isolated PostgreSQL and Redis instances required:
DATABASE_URL=... REDIS_URL=... go test -tags integration ./internal/mgmtapi -run TestEmailSignupIntegration -v
```

See [deployment instructions](../../deploy/README.md#email-signup) for required SMTP and lookup-key settings. The e2e compose stack supplies a local TLS-enabled Mailpit inbox; e2e helpers retrieve actual delivered codes rather than bypassing verification.
