# production-wiring-collapse-6af19442

## Why

Harbor's two production binaries still admit alternate development object graphs. Missing PostgreSQL, Redis, crypto, or persistence collaborators can select in-memory, noop, stub, or placeholder implementations and defer a deployment error until a security-critical request fails or silently succeeds. This makes multi-replica authorization codes, refresh issuance, enrollment, registration, and user data durability depend on environment-specific branches rather than construction-time invariants.

## What changes

- Require PostgreSQL and Redis when constructing `harbor-hot` and `harbor-mgmt`, with explicit pgxpool limits and clear startup errors.
- Collapse both binaries onto DB/Redis-backed registries, authorization codes, sessions, grants, consent, registration, enrollment, WebAuthn, dashboard, and BYO-domain stores.
- Remove the development boot mode, demo client, noop/stub/placeholder collaborators, memory rate limiter, and dead hot bootstrap path; keep deliberate revocation caches and documented local crypto providers.
- Move test doubles out of production packages or behind test-only boundaries, and enforce the production graph with architecture tests.
- Correct Kubernetes, Helm, and local-compose environment contracts, including one shared user-DEK KEK consumed by management enrollment and hot-path PPID derivation.
- Add construction and integration coverage for the live graph, cross-replica code exchange, refresh issuance, passkey enrollment, and missing-dependency failure.

## Impact

This changes startup and dependency contracts across `cmd/harbor-hot`, `cmd/harbor-mgmt`, OIDC/BFF/WebAuthn/client stores, architecture tests, generated database access for BYO domains, and deployment manifests. Local development must run the existing PostgreSQL and Redis services. No compatibility migration is required because Harbor is pre-launch; existing migration files may be amended and generated code refreshed.

## Plan

Primary plan: `docs/plans/production-wiring-collapse.md`. Aligns with DESIGN §4.1, §4.4, §10, and §1.7.
