# Production wiring collapse

Harbor's shipped binaries currently select in-memory, noop, and placeholder implementations whenever Postgres, Redis, or related configuration is absent. That makes startup appear successful while authentication, refresh tokens, client registration, and passkey enrollment are unavailable or unsafe across replicas.

This change makes Postgres and Redis mandatory, assembles one production object graph in each binary, removes the development escape path and dead scaffolds, and aligns Helm/Kubernetes configuration with the environment names read by the binaries. Deliberate hot-path revocation caches and the documented local crypto provider remain.

Success means both binaries fail at startup when a required dependency is missing, the shipped manifests render all required values, and integration tests prove cross-replica authorization-code exchange, refresh-token issuance, dynamic registration, and passkey enrollment use real stores.
