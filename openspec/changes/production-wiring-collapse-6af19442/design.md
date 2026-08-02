# Design: One fail-closed production graph

Both composition roots validate required configuration before opening an HTTP
listener and instantiate PostgreSQL/Redis adapters for every durable runtime
seam. Constructors reject absent security-critical collaborators instead of
installing no-op behavior. Test-only memory stores remain outside production
packages, and architecture tests prevent either binary from importing them.

The hot binary uses PostgreSQL for clients, sessions, grants, consents, and
revocation durability, and Redis for authorization codes, BFF state, rate
limits, and revocation distribution. The management binary uses PostgreSQL for
WebAuthn credentials, enrollment state, client registration, and BYO domains,
and Redis for bounded ceremony and BFF sessions.

Raw manifests and Helm render the same runtime contract, including the shared
user-DEK KEK consumed by both binaries. PostgreSQL pool limits are explicit per
replica so the 20-replica HPA ceiling remains within the deployment budget.

The in-memory revocation filter remains a deliberate database-backed hot-path
cache. The local signer/key provider remains the only available crypto backend
and retains its development warning.
