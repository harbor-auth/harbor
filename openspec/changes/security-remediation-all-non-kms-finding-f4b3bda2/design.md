# Design: Non-KMS security remediation

Production startup is the trust boundary. It validates runtime mode, URLs,
Redis, database, abuse controls, relay authentication, and external KMS
configuration before listening. Development-only local crypto and in-memory
implementations remain reachable solely through an explicit development mode.

The hot service builds a durable dependency graph around one database pool and
Redis client. Client authentication and JWT verification are shared by all
token-consuming endpoints. Revocation is persisted through a claimed outbox,
durable revoked-JTI state, and pub/sub propagation so replicas converge.

The management service uses the canonical grants ledger and Redis-backed BFF,
enrollment, ceremony, MFA, and recovery state. Consent is an explicit,
one-time decision. Recovery restricts the session to enrollment, while step-up
is recorded against the authenticated browser session and protected by shared
multi-dimensional limits.

Redis scripts consume or mutate only existing records with positive TTLs.
Authorization completion consumes its continuation before code issuance.
WebAuthn sign-count updates are conditional and the caller rejects a zero-row
or regressing update, except for authenticators whose counter remains zero.

Raw and Helm deployment variants expose the same required secret and
environment contracts, pin production images by digest, require signature
verification, constrain egress, and fail closed when production prerequisites
are absent. Regional KMS creation and credential wiring remain external.
