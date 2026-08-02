# production-wiring-collapse-6af19442 — Tasks

- [ ] Add failing construction, architecture, and deployment-contract tests for the forbidden fallback graphs and required dependencies.
- [ ] Make PostgreSQL, Redis, and OIDC/BFF/WebAuthn/management collaborators required and error-returning; preserve only documented exceptions.
- [ ] Collapse harbor-hot onto its existing durable graph and delete its dev graph, demo client, readiness bypass, and dead bootstrap.
- [ ] Collapse harbor-mgmt onto DB/Redis-backed enrollment, registration, WebAuthn, dashboard, and service dependencies.
- [ ] Add and wire a DB-backed BYO-domain store using the existing pre-launch migration policy and regenerate sqlc output.
- [ ] Move memory stores and fixed test sources to test support, remove noop/placeholder/stub implementations and the memory rate limiter, and update unit tests.
- [ ] Correct Kubernetes and Helm configuration, including the shared user-DEK KEK, and add rendering assertions.
- [ ] Update compose and local-development documentation to boot the real graph with PostgreSQL and Redis.
- [ ] Add live-graph and end-to-end regressions for concrete implementation identity, cross-replica code exchange, refresh issuance, and passkey enrollment.
- [ ] Run build, vet, tests, agent-check, generate-check, OpenSpec, and Kubernetes/Helm rendering validation.
