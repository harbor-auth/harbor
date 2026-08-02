# Design: one production object graph

## Construction boundary

Database and Redis connection helpers return errors when their required URLs are absent or invalid. Binary graph builders accept concrete, non-nil dependencies and return errors for incomplete graphs. Service constructors validate every security- and durability-critical collaborator rather than installing noop defaults. Development and e2e use the same graph against compose-provided services.

## Store wiring

`harbor-hot` uses the DB client registry, Redis authorization-code store, DB refresh-session/grant/consent stores, DB revocation outbox and revoked-JTI store, and the DB/crypto-backed PPID resolver. `harbor-mgmt` uses Redis BFF, WebAuthn, enrollment, and abuse state plus DB WebAuthn credentials, users, grants, sessions, dashboard data, registration, relay, audit, compliance, MFA, and BYO domains. Dynamic registration remains protected by the initial access token gate.

## Test support boundary

In-memory stores and deterministic sources remain available only to tests through a test-support boundary that production commands cannot import. Noop stores, the fixed stub resolver, unsigned placeholder issuer, demo client, memory rate limiter, noop command adapters, and dead bootstrap code are removed. `oidc.RevocationFilter` remains an intentional memory/Bloom cache backed by durable revoked JTIs. Local crypto providers and their DEV-ONLY warnings remain until the separate HSM plan supplies replacements.

## Deployment contract

Both workloads receive required database and Redis URLs, region and public URLs, and correctly named WebAuthn variables. A chart-level `global.userDekKekSecret` is rendered as `HARBOR_KMS_SECRET` for management and hot so the same user DEK can be wrapped during enrollment and unwrapped for PPID derivation. Signing-key KEK configuration stays distinct. Helm and raw Kubernetes rendering tests assert this contract.

## Verification

Architecture tests reject production imports or constructor calls for test scaffolds. Live-graph integration tests build through the binary `run`/graph boundary against PostgreSQL and Redis and assert concrete stores. Flow tests prove cross-instance code consumption, `offline_access` refresh issuance, and completion of enrollment ceremonies. Missing required dependencies must fail during startup.
