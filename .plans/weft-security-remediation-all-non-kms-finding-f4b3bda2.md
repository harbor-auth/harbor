# Add failing harbor-hot production graph tests

1. Capture the production startup contract for PostgreSQL, Redis, external KMS, and every durable OIDC dependency.
2. Add a live-graph source guard proving production assembly cannot instantiate demo, placeholder, local-crypto, in-memory, stub, or no-op implementations.
3. Add a signing bootstrap regression test rejecting a local key provider in production.
4. Run the focused package test and confirm the new tests fail for the intended missing production wiring.
5. Commit, rebase on the shared branch, and push the red-test task for the implementation task to satisfy.
