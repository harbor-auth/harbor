# Design

## Principles

1. Treat `HARBOR_ENV=production` (or the repository's canonical equivalent selected during implementation) as an explicit mode. Production constructors return errors for every missing durable dependency; dev/test fallbacks require explicit opt-in.
2. Assemble each binary from one PostgreSQL pool and one Redis client. Reuse existing sqlc-backed stores and Redis implementations; do not create parallel persistence abstractions.
3. Use the configured regional KMS provider for signing and user-DEK wrapping. No local KEK or invented credential may satisfy production readiness.
4. Centralize client authentication and JWT verification so userinfo, introspection, revocation, logout, and token issuance cannot drift.
5. Use `grants` as the canonical authorization record and migrate/remove `consent_grants`; session revocation and grant revocation share a transaction.
6. Make browser continuations and authenticator counter changes compare-and-swap operations. Redis mutation scripts must reject missing/expired keys and non-positive TTL.
7. Apply distributed limits to sensitive endpoints, with bounded-local or fail-closed outage behavior; never silently disable them in production.

## Workstreams

### A. Production object graphs

Refactor hot and management startup into testable constructors. Wire DB client registry, auth codes, grants, sessions, revoked JTIs, outbox worker/subscriber, JWT/logout verification, session revocation, enrollment Redis, WebAuthn DB/Redis stores, and registration authorization. Live-graph tests instantiate production configuration and assert concrete durable behavior.

### B. OIDC lifecycle

Create a single client authenticator supporting registered public and confidential methods with hashed, constant-time secret checks. Create a shared access/id-token verifier with issuer, audience, type, time, JTI, scope, algorithm, kid/rotation, and revocation policy, and inject it into every token-consuming handler. Persist revocation and rotation/theft signals before publication.

### C. Consent, recovery, and MFA

Model pending consent in the BFF session and only write a canonical grant after approval. Propagate recovery scope through the BFF session and gate all sensitive management routes. Bind MFA verification and step-up state to that same session and enforce distributed user/session/IP limits and lockout.

### D. BFF and WebAuthn races

Consume authorization completion state atomically before redirect. Require nonce-bound sessions and prevent Redis Lua updates from recreating expired keys. Return affected-row information for sign-count updates and reject concurrent no-op or regressing writes.

### E. Abuse and deployment

Validate production HTTPS origins/hosts and prohibit disabled rate limits. Make relay authentication required outside explicit development. Keep Helm/raw manifests aligned on immutable images, secrets, Redis/KMS variables, runtime settings, and narrowly scoped egress.

## Validation

Each bug fix begins with a focused failing regression test. Workstreams finish with assembled cross-replica tests. Final validation runs gofmt, `go build ./...`, `go vet ./...`, `go test ./...`, `make agent-check`, `make generate-check`, OpenSpec strict verification, and relevant Helm/Kubernetes rendering checks.
