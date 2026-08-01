# Design

## Object graph

`harbor-hot` opens a required, explicitly sized pgx pool and required Redis client, then constructs the DB client registry, Redis authorization-code store, DB refresh-session/grant/consent stores, real signer/verifier/revocation collaborators, Redis BFF sessions, and Redis rate limiters. `harbor-mgmt` uses the same required infrastructure for DB WebAuthn credentials, Redis ceremony/BFF sessions, enrollment persistence, dynamic client registration with its initial-access-token gate, and its DB-backed dashboard and domain stores.

Required collaborators are validated at construction and return errors rather than selecting noops. `HARBOR_DEV_MODE`, `validateProductionReadiness`, the demo client, placeholder issuer, stub resolver, noop collaborators, memory rate limiter, and dead hot bootstrap are removed. Test doubles remain usable only from tests/test-support code; architecture tests prevent command packages from reaching them. The in-memory and bloom revocation filters remain intentional read-through caches, and `LocalKeyProvider`/`LocalSigner` remain the available crypto backend with their warnings.

## Deployment

The chart exposes an explicit shared user-DEK KEK consumed as `HARBOR_KMS_SECRET` by both binaries, while hot signing keys continue to use `KEK_SECRET`. Both components receive Postgres, Redis, region, and required URLs. Reference Kubernetes manifests use the exact WebAuthn and KEK names read by code. pgx pool maximum connections are explicit so the 20-pod HPA cannot exhaust Postgres unpredictably.

## Verification

Unit tests cover missing dependency/configuration failures and architecture constraints. Container-backed integration tests build the real handler graphs and prove cross-instance auth-code consumption, `offline_access` refresh issuance, registration, and passkey enrollment. Rendering checks cover Helm and Kustomize; repository-wide build, vet, test, agent, generation, and conformance checks remain mandatory.
