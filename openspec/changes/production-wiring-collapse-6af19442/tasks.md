# production-wiring-collapse-6af19442 — Tasks

## Prerequisites

- [x] The admin endpoint authorization parent feature is complete.
- [x] The production wiring plan has been reviewed in full.

## Implementation

- [x] Require PostgreSQL, Redis, URLs, and security-critical collaborators in both composition roots.
- [x] Replace runtime scaffolds with durable PostgreSQL and Redis adapters.
- [x] Remove development mode, no-op/placeholder/stub paths, and dead bootstrap code.
- [x] Add durable BYO-domain persistence and explicit PostgreSQL pool sizing.
- [x] Align raw Kubernetes, Helm, and local-development runtime configuration.
- [x] Preserve only the documented revocation-cache and local-crypto exceptions.

## Tests

- [x] Cover missing collaborators and composition-root startup failures.
- [x] Cover hot and management live production graphs.
- [x] Cover cross-replica authorization-code exchange and refresh-token issuance.
- [x] Cover passkey enrollment and authorized dynamic registration persistence.
- [x] Enforce production graph architecture boundaries.

## Validation

- [x] `openspec validate production-wiring-collapse-6af19442 --strict`.
- [x] `go build ./...`.
- [x] `go vet ./...`.
- [x] `go test ./...`.
- [x] `make agent-check`.
- [x] `make generate-check`.
- [x] Helm and raw Kubernetes rendering contracts.
