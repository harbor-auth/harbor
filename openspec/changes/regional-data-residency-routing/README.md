# regional-data-residency-routing

Make **region** a first-class, request-scoped, fail-closed property so a user's
PII physically cannot leave their home region (§5). Adds a **total** host/issuer
→ region resolver (an unrecognised host is rejected, never silently defaulted),
a request-scoped region context that binds datastore selection to the pinned
region (a handler cannot reach another region's store), a **cross-region PII
guard** that returns a defined error and is metered — never partial data — when
a handler would read a user from a foreign region, and issuer/host coherence so
a token minted on the `eu` issuer is only ever verified or introspected on the
`eu` surface. This is a Wave-5 platform guardrail that every later user-data
feature (`email-relay-service`, `compliance-export`, `consent-management-ui`)
inherits; it introduces no new table and keeps the hot path a cheap,
stateless host-prefix lookup (§4.1).
